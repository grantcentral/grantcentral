# 01: `SHA256SUMS` on every release

**What to build:** Every tagged release attaches a `SHA256SUMS` file covering all of its assets, so that the CI integrations (tickets 03–05) and anyone downloading by hand can verify what they downloaded. See the spec (`../spec.md`), "Release: `SHA256SUMS`".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The `release` job writes `SHA256SUMS` in standard `sha256sum` format (hash, two spaces, bare file name) over every downloaded asset and attaches it to the GitHub Release next to them. No signing.
- [ ] `sha256sum -c SHA256SUMS` passes in a directory holding the downloaded release assets.
- [ ] `workflow_dispatch` runs are unchanged. They publish nothing, so they don't need the file.
- [ ] If the musl tarballs from `.scratch/ghcr-image/issues/01-musl-release-binaries.md` are already on the release, they are covered without extra work, because the file lists every asset.
- [ ] README "Releases" says the release attaches `SHA256SUMS` and shows how to verify a download.
- [ ] Nothing in the workflow pushes a git ref.
- [ ] Committed as `ci:` (or `feat:` if the README change is the user-facing part). No version bump and no `CHANGELOG.md` edit.
