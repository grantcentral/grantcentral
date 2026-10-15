#!/usr/bin/env bash
# Stands in for the grantcentral binary and runs an image instead:
#   GRANTCENTRAL_IMAGE=grantcentral:slim GRANTCENTRAL="$PWD/e2e/docker.sh" e2e/run.sh --skip-tag chromium
# Host networking lets the container reach the local OP, and the OP's redirects reach the
# container's loopback listener. The e2e directory is mounted at the same path, so the
# absolute paths run.sh passes resolve, and running as the caller's UID keeps written files theirs.
# Only the e2e directory is mounted, so give output paths (--junit) as absolute paths inside it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
exec docker run --rm --network host --user "$(id -u):$(id -g)" -v "$here:$here" -w "$PWD" "${GRANTCENTRAL_IMAGE:?}" "$@"
