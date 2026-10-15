# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.4](https://git.jirsh.net/grantcentral/grantcentral/compare/v0.0.3...v0.0.4) - 2026-10-15

### Added

- publish multi-arch container images to GHCR
- serve --bind and GRANTCENTRAL_BIND/GRANTCENTRAL_PORT

### Fixed

- treat an empty CHROME as unset

### Other

- turn the README into an intro and add a getting-started guide

## [0.0.3](https://git.jirsh.net/grantcentral/grantcentral/compare/v0.0.2...v0.0.3) - 2026-10-13

### Other

- [**breaking**] run JOSE on aws-lc-rs and drop OpenSSL

## [0.0.2](https://git.jirsh.net/grantcentral/grantcentral/compare/v0.0.1...v0.0.2) - 2026-10-12

### Performance

- shrink the release binary

### Other

- tag releases as v{{ version }} in release-plz
- use an annotated tag in the release steps

## [0.0.1](https://git.jirsh.net/grantcentral/grantcentral/releases/tag/v0.0.1) - 2026-10-12

### Other

- release binaries and crates from v* tags
- Update the web UI live when project files change on disk
- Drop the iced desktop app in favor of `grantcentral serve`
- Use CodeMirror for the web UI editor
- Cross-compile to Windows and macOS
- Add GrantCentral: OAuth 2.0 / OpenID Connect flow testing tool
