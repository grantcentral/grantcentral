// Local OpenID Provider for GrantCentral's end-to-end flows, built on
// node-oidc-provider (an OpenID-certified implementation), plus a tiny
// protected resource for RFC 6750 / RFC 9449 / RFC 9470 / RFC 9728 requests.
//
//   npm install && node server.mjs        # http://localhost:3000
//
// Test users log in with any username and the password "pass". An
// authorization request with login_hint=auto logs in as "alice" without a
// form, so flows can run with `login = "http"`.

import { X509Certificate, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createServer as createHttpsServer } from 'node:https';
import Provider, { errors } from 'oidc-provider';

const PORT = Number(process.env.PORT || 3000);
const TLS_PORT = PORT + 443;
const ISSUER = `http://localhost:${PORT}`;
const API = `${ISSUER}/api`;

const signing = (type, opts, alg) => ({ ...generateKeyPairSync(type, opts).privateKey.export({ format: 'jwk' }), use: 'sig', alg, kid: `${alg.toLowerCase()}-sig` });
const encryption = (type, opts, alg) => ({ ...generateKeyPairSync(type, opts).privateKey.export({ format: 'jwk' }), use: 'enc', alg, kid: `${alg.toLowerCase()}-enc` });
const jwks = {
  keys: [
    signing('rsa', { modulusLength: 2048 }, 'RS256'),
    signing('ec', { namedCurve: 'P-256' }, 'ES256'),
    signing('rsa', { modulusLength: 2048 }, 'PS256'),
    encryption('rsa', { modulusLength: 2048 }, 'RSA-OAEP-256'),
    encryption('ec', { namedCurve: 'P-256' }, 'ECDH-ES+A256KW'),
  ],
};

// The test client's public key; the private half lives in project/keys.
const clientKey = JSON.parse(readFileSync(new URL('./project/keys/client.private.jwk.json', import.meta.url)));
const { d, p, q, dp, dq, qi, ...clientPublic } = clientKey;

const clients = [
  {
    client_id: 'gc-confidential',
    client_secret: 'gc-confidential-secret-0123456789',
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange'],
    redirect_uris: ['http://127.0.0.1:8765/callback'],
    authorization_details_types: ['payment_initiation'],
    scope: 'openid offline_access profile email api:read',
  },
  {
    client_id: 'gc-public',
    token_endpoint_auth_method: 'none',
    application_type: 'native',
    grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
    response_types: ['code'],
    // Port-agnostic loopback redirect (RFC 8252 §7.3).
    redirect_uris: ['http://127.0.0.1/callback'],
    scope: 'openid offline_access profile email api:read',
  },
  {
    client_id: 'gc-pkjwt',
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    request_object_signing_alg: 'ES256',
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    redirect_uris: ['http://127.0.0.1:8767/callback'],
    jwks: { keys: [clientPublic] },
    dpop_bound_access_tokens: false,
    scope: 'openid offline_access profile email api:read',
  },
  {
    client_id: 'gc-hybrid',
    client_secret: 'gc-confidential-secret-0123456789',
    application_type: 'native',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['code', 'code id_token'],
    redirect_uris: ['http://127.0.0.1:8769/callback'],
    scope: 'openid',
  },
  {
    client_id: 'gc-jar-encrypted',
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    request_object_signing_alg: 'ES256',
    request_object_encryption_alg: 'RSA-OAEP-256',
    request_object_encryption_enc: 'A256GCM',
    redirect_uris: ['http://127.0.0.1:8768/callback'],
    jwks: { keys: [clientPublic] },
    scope: 'openid profile',
  },
];

// Mutual TLS (RFC 8705) on a second, HTTPS listener when run.sh has generated certificates.
const certs = new URL('./project/keys/generated/', import.meta.url);
const tls = existsSync(new URL('server.crt', certs))
  ? { key: readFileSync(new URL('server.key', certs)), cert: readFileSync(new URL('server.crt', certs)) }
  : undefined;
if (tls) {
  const cert = new X509Certificate(readFileSync(new URL('client.crt', certs)));
  clients.push({
    client_id: 'gc-mtls',
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
    tls_client_certificate_bound_access_tokens: true,
    grant_types: ['client_credentials'],
    response_types: [],
    redirect_uris: [],
    jwks: { keys: [{ ...cert.publicKey.export({ format: 'jwk' }), x5c: [cert.raw.toString('base64')] }] },
  });
}
const MTLS = `https://localhost:${TLS_PORT}`;

const configuration = {
  clients,
  jwks,
  findAccount: async (_ctx, id) => ({
    accountId: id,
    claims: async () => ({ sub: id, name: `Test user ${id}`, email: `${id}@example.test`, email_verified: true }),
  }),
  claims: { openid: ['sub'], profile: ['name'], email: ['email', 'email_verified'] },
  scopes: ['openid', 'offline_access', 'profile', 'email', 'api:read'],
  interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
  issueRefreshToken: async (_ctx, client) => client.grantTypeAllowed('refresh_token'),
  rotateRefreshToken: true,
  // auth_time in JWT access tokens lets the resource server ask for step-up (RFC 9470).
  extraTokenClaims: async (ctx, token) => {
    if (token.kind !== 'AccessToken') return undefined;
    const source = ctx.oidc.entities.AuthorizationCode || ctx.oidc.entities.RefreshToken;
    return source?.authTime ? { auth_time: source.authTime } : undefined;
  },
  conformIdTokenClaims: false,
  pkce: { required: () => true },
  clientAuthMethods: ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt', 'none', 'self_signed_tls_client_auth'],
  discovery: tls ? {
    mtls_endpoint_aliases: {
      token_endpoint: `${MTLS}/token`,
      introspection_endpoint: `${MTLS}/token/introspection`,
      revocation_endpoint: `${MTLS}/token/revocation`,
    },
  } : {},
  features: {
    devInteractions: { enabled: false },
    clientCredentials: { enabled: true },
    introspection: { enabled: true },
    jwtIntrospection: { enabled: true },
    revocation: { enabled: true },
    registration: { enabled: true },
    registrationManagement: { enabled: true, rotateRegistrationAccessToken: false },
    deviceFlow: { enabled: true },
    pushedAuthorizationRequests: { enabled: true },
    requestObjects: { enabled: true },
    encryption: { enabled: true },
    claimsParameter: { enabled: true },
    jwtUserinfo: { enabled: true },
    // gc-pkjwt must use server-provided DPoP nonces (RFC 9449 §8).
    dPoP: { enabled: true, nonceSecret: randomBytes(32), requireNonce: (ctx) => ctx.oidc.client?.clientId === 'gc-pkjwt' },
    mTLS: {
      enabled: Boolean(tls),
      certificateBoundAccessTokens: true,
      selfSignedTlsClientAuth: true,
      getCertificate: (ctx) => {
        const peer = ctx.socket.getPeerCertificate?.();
        return peer?.raw ? new X509Certificate(peer.raw).toString() : undefined;
      },
      certificateAuthorized: () => false,
      certificateSubjectMatches: () => false,
    },
    richAuthorizationRequests: {
      enabled: true,
      types: { payment_initiation: { validate() {} } },
      // Policy: grant exactly what was requested (and consented to).
      authorizationDetailsForGrantSource: (ctx) => ctx.oidc.grant?.rar || JSON.parse(ctx.oidc.params.authorization_details || '[]'),
      authorizationDetailsForAccessToken: (_ctx, _token, source) => source?.rar,
    },
    resourceIndicators: {
      enabled: true,
      defaultResource: () => undefined,
      useGrantedResource: () => true,
      // Access tokens for the API are JWTs (RFC 9068).
      getResourceServerInfo: () => ({ scope: 'api:read', audience: API, accessTokenFormat: 'jwt', jwt: { sign: { alg: 'ES256' } } }),
    },
  },
  ttl: { DeviceCode: 600 },
};

const provider = new Provider(ISSUER, configuration);

// Token exchange (RFC 8693): swaps a valid access token for a new one.
const exchangeParams = new Set(['subject_token', 'subject_token_type', 'actor_token', 'actor_token_type', 'requested_token_type', 'audience', 'resource', 'scope']);
provider.registerGrantType('urn:ietf:params:oauth:grant-type:token-exchange', async (ctx) => {
  const { subject_token: token } = ctx.oidc.params;
  const subject = (await provider.AccessToken.find(token)) || (await provider.ClientCredentials.find(token));
  if (!subject || subject.isExpired) throw new errors.InvalidGrant('subject_token is not an active access token');
  const issued = new provider.ClientCredentials({ client: ctx.oidc.client, scope: subject.scope || 'api:read' });
  ctx.body = {
    access_token: await issued.save(),
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: issued.expiration,
  };
}, exchangeParams);

const page = (title, body) => `<!doctype html><meta charset="utf-8"><title>${title}</title>
<body style="font:16px system-ui;margin:3em;max-width:30em"><h1>${title}</h1>${body}`;

async function readForm(req) {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  return Object.fromEntries(new URLSearchParams(raw));
}

// Login and consent. Consent is granted automatically for everything requested.
provider.use(async (ctx, next) => {
  const m = ctx.path.match(/^\/interaction\/([^/]+)(\/login)?$/);
  if (!m) return next();
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  const { prompt, params, session } = details;
  let result;
  if (prompt.name === 'login') {
    if (ctx.method === 'POST' && m[2]) {
      const form = await readForm(ctx.req);
      if (form.password !== 'pass') {
        ctx.body = page('Sign in', '<p id="error">Wrong password.</p>');
        return undefined;
      }
      result = { login: { accountId: form.username || 'alice', acr: 'urn:gc:pwd', amr: ['pwd'] } };
    } else if (params.login_hint === 'auto') {
      result = { login: { accountId: 'alice', acr: params.acr_values?.split(' ')[0] || 'urn:gc:pwd', amr: ['pwd'] } };
    } else {
      ctx.body = page('Sign in', `<form method="post" action="/interaction/${m[1]}/login">
        <p><label>Username <input id="username" name="username" autofocus></label></p>
        <p><label>Password <input id="password" name="password" type="password"></label></p>
        <p><button id="submit" type="submit">Sign in</button></p></form>`);
      return undefined;
    }
  } else if (prompt.name === 'consent') {
    const d = prompt.details;
    const grant = details.grantId
      ? await provider.Grant.find(details.grantId)
      : new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
    if (d.missingOIDCScope) grant.addOIDCScope(d.missingOIDCScope.join(' '));
    if (d.missingOIDCClaims) grant.addOIDCClaims(d.missingOIDCClaims);
    for (const [indicator, scopes] of Object.entries(d.missingResourceScopes || {})) grant.addResourceScope(indicator, scopes.join(' '));
    for (const detail of d.rar || []) grant.addRar(detail);
    result = { consent: { grantId: await grant.save() } };
  } else {
    throw new Error(`unexpected prompt ${prompt.name}`);
  }
  ctx.status = 303;
  ctx.redirect(await provider.interactionResult(ctx.req, ctx.res, result, { mergeWithLastSubmission: true }));
  return undefined;
});

// Protected resource: RFC 9728 metadata and an endpoint that wants a fresh
// login (max_age=30, RFC 9470) and honors DPoP-bound tokens (RFC 9449).
provider.use(async (ctx, next) => {
  if (ctx.path === '/.well-known/oauth-protected-resource/api') {
    ctx.body = { resource: API, authorization_servers: [ISSUER], bearer_methods_supported: ['header'], dpop_signing_alg_values_supported: ['ES256'] };
    return undefined;
  }
  if (!ctx.path.startsWith('/api/')) return next();
  const challenge = (error, extra = '') => {
    ctx.status = 401;
    ctx.set('WWW-Authenticate', `Bearer realm="gc-api", error="${error}"${extra}, resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/api"`);
    ctx.body = { error };
  };
  const [scheme, value] = (ctx.get('authorization') || '').split(' ');
  if (!value) return challenge('invalid_request');
  const token = (await provider.AccessToken.find(value).catch(() => undefined))
    || (await provider.ClientCredentials.find(value).catch(() => undefined));
  // JWT access tokens are not stored; accept them by decoding (a real RS verifies the signature).
  let claims = token ? { sub: token.accountId, cnf: token.jkt ? { jkt: token.jkt } : undefined } : undefined;
  if (!claims && value.split('.').length === 3) {
    try { claims = JSON.parse(Buffer.from(value.split('.')[1], 'base64url')); } catch { /* not a JWT */ }
  }
  if (!claims) return challenge('invalid_token');
  if (claims.cnf?.jkt && (scheme !== 'DPoP' || !ctx.get('dpop'))) return challenge('invalid_token', ', error_description="DPoP proof required"');
  if (ctx.path === '/api/sensitive') {
    const fresh = claims.auth_time && Date.now() / 1000 - claims.auth_time < 30;
    if (!fresh) return challenge('insufficient_user_authentication', ', error_description="A more recent authentication is required", max_age="30"');
  }
  ctx.body = { ok: true, sub: claims.sub, path: ctx.path };
  return undefined;
});

provider.on('server_error', (_ctx, err) => console.error('server_error', err));
provider.listen(PORT, () => console.log(`oidc-provider listening on ${ISSUER}`));
if (tls) {
  createHttpsServer({ ...tls, requestCert: true, rejectUnauthorized: false }, provider.callback())
    .listen(TLS_PORT, () => console.log(`mTLS endpoints on ${MTLS}`));
}
