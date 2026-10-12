#!/usr/bin/env bash
# Runs the end-to-end flows against a local oidc-provider.
#   e2e/run.sh [grantcentral run args...]
# Flows tagged "chromium" need CHROME (path to Chrome/Chromium) or a browser on PATH;
# without one they are skipped.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
bin="${GRANTCENTRAL:-$here/../target/debug/grantcentral}"
[ -d "$here/node_modules" ] || (cd "$here" && npm install --silent)

# Throwaway certificates for the mutual TLS flow (RFC 8705).
certs="$here/project/keys/generated"
if [ ! -f "$certs/client.crt" ]; then
  mkdir -p "$certs"
  ec=(-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes)
  openssl req -x509 "${ec[@]}" -days 365 -subj "/CN=GrantCentral e2e CA" -keyout "$certs/ca.key" -out "$certs/ca.crt" 2> /dev/null
  openssl req "${ec[@]}" -subj /CN=localhost -keyout "$certs/server.key" -out "$certs/server.csr" 2> /dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' > "$certs/server.ext"
  openssl x509 -req -in "$certs/server.csr" -CA "$certs/ca.crt" -CAkey "$certs/ca.key" -CAcreateserial -days 365 \
    -extfile "$certs/server.ext" -out "$certs/server.crt" 2> /dev/null
  # Self-signed client certificate, registered by value (self_signed_tls_client_auth).
  openssl req -x509 "${ec[@]}" -days 365 -subj /CN=gc-mtls -addext basicConstraints=CA:FALSE \
    -keyout "$certs/client.key" -out "$certs/client.crt" 2> /dev/null
fi

node "$here/server.mjs" > "$here/server.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -fs http://localhost:3000/.well-known/openid-configuration > /dev/null && break; sleep 0.2; done

skip=()
if [ -z "${CHROME:-}" ] && ! command -v chromium chromium-browser google-chrome > /dev/null 2>&1; then
  echo "no Chrome found: skipping flows tagged chromium"
  skip=(--skip-tag chromium)
fi
"$bin" -C "$here/project" run "${skip[@]}" "$@"
