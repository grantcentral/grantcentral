# 05: `serve` bind address and port from the environment

**What to build:** `grantcentral serve` gets a bind-address flag, `--bind <IP>`, that can also be set with the `GRANTCENTRAL_BIND` environment variable. The default stays `127.0.0.1`. The existing `--port` can also be set with `GRANTCENTRAL_PORT`. In a container, `-e GRANTCENTRAL_BIND=0.0.0.0 -e GRANTCENTRAL_PORT=8080 -p 8080:8080 ... serve --no-open` makes the web UI reachable from the host. See the spec (`../spec.md`), "Web UI bind address".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `Command::Serve` has `#[arg(long, env = "GRANTCENTRAL_BIND", default_value = "127.0.0.1")] bind: IpAddr`, passed to `web::serve`, which binds the listener to it.
- [ ] `--port` has `env = "GRANTCENTRAL_PORT"`. Its default stays `0` (a free port).
- [ ] The token check is unchanged and covers every API call at any bind address.
- [ ] `check_host` accepts a `Host` whose host part is `localhost` or an IP literal (bracketed IPv6 included), with any port, and refuses everything else, including a missing header. The logic is a pure function with unit tests for each of those cases.
- [ ] With a non-loopback bind, `serve` warns on stderr that the UI is reachable from the network and that the token travels over plain HTTP.
- [ ] The printed URL uses the bind address, or `127.0.0.1` when it is unspecified (`0.0.0.0`, `::`).
- [ ] The `web.rs` module comment, README "The web UI" and the AGENTS.md "Web UI security" bullet describe `--bind`, both env variables and the new Host rule.
- [ ] Committed as `feat:`. No version bump and no `CHANGELOG.md` edit.
