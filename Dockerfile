# CLI image for pipelines: grantcentral, git and Chromium for headless logins.
#   docker build -t grantcentral .
#   docker run --rm -v "$PWD:/work" -w /work grantcentral run --login chromium --junit report.xml
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p grantcentral

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates chromium git libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/grantcentral /usr/local/bin/grantcentral
ENV CHROME=/usr/bin/chromium GRANTCENTRAL_NO_SANDBOX=true
ENTRYPOINT ["grantcentral"]
