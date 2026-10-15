# GrantCentral images for pipelines. Nothing compiles here: the build context holds prebuilt
# static musl binaries named after Docker's TARGETARCH (`amd64`, `arm64`).
#   slim: grantcentral, git and CA certificates
#   full: slim plus Chromium, set up for `run --login chromium`
#
# Building locally (x86_64; for arm64 use aarch64-unknown-linux-musl and ctx/arm64):
#   cargo build --release --locked --target x86_64-unknown-linux-musl   # needs musl-tools (musl-gcc)
#   mkdir -p ctx && cp target/x86_64-unknown-linux-musl/release/grantcentral ctx/amd64
#   docker build -f Dockerfile --target full -t grantcentral ctx         # or --target slim
#   docker run --rm -v "$PWD:/work" grantcentral run --login chromium --junit report.xml
FROM alpine:3.24 AS slim
ARG TARGETARCH
RUN apk add --no-cache ca-certificates git && adduser -D -H -h /tmp -u 10001 grantcentral
COPY --chmod=755 $TARGETARCH /usr/local/bin/grantcentral
# World-writable, so git and Chromium also work under `docker run --user <any uid>`.
ENV HOME=/tmp
USER 10001
WORKDIR /work
ENTRYPOINT ["grantcentral"]

FROM slim AS full
USER root
# The package pulls in nss and the rest of what it needs.
RUN apk add --no-cache chromium
USER 10001
ENV CHROME=/usr/bin/chromium-browser GRANTCENTRAL_NO_SANDBOX=true
