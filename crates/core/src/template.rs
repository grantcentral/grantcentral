//! `{{ ... }}` interpolation and assertion/capture expressions, both minijinja.

use anyhow::{Result, anyhow};
use minijinja::value::Serde;
use minijinja::{Environment, Error, ErrorKind, UndefinedBehavior};
use serde_json::Value;

pub struct Templates {
    env: Environment<'static>,
}

impl Default for Templates {
    fn default() -> Self {
        let mut env = Environment::new();
        // Undefined values fail when printed but are falsy in conditions (`when`).
        env.set_undefined_behavior(UndefinedBehavior::SemiStrict);
        env.add_function("now", || crate::now() as i64);
        env.add_function("random", |n: Option<usize>| crate::random_b64(n.unwrap_or(32)));
        env.add_filter("b64url", |s: String| crate::b64(s.as_bytes()));
        env.add_filter("b64url_decode", |s: String| -> Result<String, Error> {
            crate::unb64(&s)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .map_err(|e| Error::new(ErrorKind::InvalidOperation, e.to_string()))
        });
        env.add_filter("sha256", |s: String| crate::b64(&crate::sha256(s.as_bytes())));
        // `{{ token | jwt }}` -> {header, payload} without verifying.
        env.add_filter("jwt", |s: String| -> Result<minijinja::Value, Error> {
            let (header, payload) = crate::jose::decode(&s).map_err(|e| Error::new(ErrorKind::InvalidOperation, e.to_string()))?;
            Ok(minijinja::Value::from(Serde(serde_json::json!({ "header": header, "payload": payload }))))
        });
        Templates { env }
    }
}

impl Templates {
    /// Renders a string. Strings without template syntax are returned unchanged.
    pub fn render(&self, s: &str, ctx: &Value) -> Result<String> {
        if !s.contains("{{") && !s.contains("{%") {
            return Ok(s.to_string());
        }
        self.env.render_str(s, Serde(ctx)).map_err(|e| anyhow!("template `{s}`: {}", describe(&e)))
    }

    /// Evaluates an expression such as `status == 200`.
    pub fn eval(&self, expr: &str, ctx: &Value) -> Result<Value> {
        let compiled = self.env.compile_expression(expr).map_err(|e| anyhow!("expression `{expr}`: {}", describe(&e)))?;
        let v = compiled.eval(Serde(ctx)).map_err(|e| anyhow!("expression `{expr}`: {}", describe(&e)))?;
        Ok(serde_json::to_value(&v)?)
    }

    pub fn truthy(&self, expr: &str, ctx: &Value) -> Result<bool> {
        let compiled = self.env.compile_expression(expr).map_err(|e| anyhow!("expression `{expr}`: {}", describe(&e)))?;
        let v = compiled.eval(Serde(ctx)).map_err(|e| anyhow!("{}", describe(&e)))?;
        Ok(v.is_true())
    }

    /// Renders every string inside a JSON value. A string that is exactly one
    /// `{{ expr }}` whose result is an object or array keeps that structure, so
    /// `authorization_details = "{{ steps.x.body.authorization_details }}"` works.
    /// Keys listed in `skip` (at any depth) are left untouched.
    pub fn render_value(&self, v: &Value, ctx: &Value, skip: &[&str]) -> Result<Value> {
        Ok(match v {
            Value::String(s) => {
                if let Some(expr) = whole_expression(s) {
                    let out = self.eval(expr, ctx)?;
                    if out.is_object() || out.is_array() {
                        return Ok(out);
                    }
                }
                Value::String(self.render(s, ctx)?)
            }
            Value::Array(a) => Value::Array(a.iter().map(|x| self.render_value(x, ctx, skip)).collect::<Result<_>>()?),
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, x)| Ok((k.clone(), if skip.contains(&k.as_str()) { x.clone() } else { self.render_value(x, ctx, skip)? })))
                    .collect::<Result<_>>()?,
            ),
            other => other.clone(),
        })
    }
}

fn whole_expression(s: &str) -> Option<&str> {
    let inner = s.trim().strip_prefix("{{")?.strip_suffix("}}")?;
    (!inner.contains("{{") && !inner.contains("}}")).then_some(inner.trim())
}

fn describe(e: &Error) -> String {
    let mut msg = e.to_string();
    if e.kind() == ErrorKind::UndefinedError {
        msg.push_str(" (an undefined variable, or a missing secret)");
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn render_and_eval() {
        let t = Templates::default();
        let ctx = json!({ "client_id": "abc", "status": 200, "body": { "scope": "openid email", "details": [{"type": "x"}] } });
        assert_eq!(t.render("id={{ client_id }}", &ctx).unwrap(), "id=abc");
        assert!(t.truthy("status == 200", &ctx).unwrap());
        assert!(t.truthy("'email' in body.scope", &ctx).unwrap());
        assert!(!t.truthy("status == 201", &ctx).unwrap());
        assert!(t.render("{{ nope }}", &ctx).is_err(), "strict undefined");
        let v = t.render_value(&json!({ "a": "{{ body.details }}", "b": "{{ status }}", "s": "{{ nope }}" }), &ctx, &["s"]).unwrap();
        assert_eq!(v, json!({ "a": [{"type": "x"}], "b": "200", "s": "{{ nope }}" }));
        assert_eq!(t.render("{{ 'ab' | b64url }}", &ctx).unwrap(), "YWI");
    }
}
