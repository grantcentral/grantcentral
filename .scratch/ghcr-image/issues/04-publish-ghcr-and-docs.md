# 04: Publish both images to GHCR, plus the container docs

**What to build:** On a `v*` tag push, the release publishes `ghcr.io/<owner>/grantcentral` for `linux/amd64` and `linux/arm64`, in both variants. The tags are `X.Y.Z` and `latest` for `full`, and `X.Y.Z-slim` and `slim` for `slim`. Users can pull and run it from a pipeline or from Docker on Apple Silicon without building anything. The README explains how to use the image and what doesn't work in a container. See the spec (`../spec.md`), "Release workflow", "Documentation" and "Further Notes".

**Blocked by:** 03 (Full image with Chromium, e2e-tested)

**Status:** ready-for-agent

- [ ] The `release` job gets `packages: write`. After it creates the GitHub Release, it builds both stages for `linux/amd64,linux/arm64` with `docker/build-push-action` from the same build-context layout as the `image` job, and pushes them to GHCR with `GITHUB_TOKEN`. `workflow_dispatch` runs still never push.
- [ ] Tags and OCI labels (source, license, description, version, revision) come from `docker/metadata-action`, which also lowercases the owner. There are no hard-coded `LABEL` lines in the `Dockerfile`.
- [ ] A pre-release tag (e.g. `vX.Y.Z-rc.1`) gets only its version tag (and `-slim`) and doesn't move `latest` or `slim`.
- [ ] Provenance and SBOM attestations are enabled explicitly.
- [ ] Nothing in the workflow pushes a git ref.
- [ ] README has a "Container image" section: the two tags and when to pick which; the `docker run --rm -v "$PWD:/work" ...` example; passing secrets with `-e GC_...`; and running as your own UID with `--user "$(id -u):$(id -g)"` so that written reports belong to you.
- [ ] README documents these container limits instead of fixing them:
  - `login = "system"` has no browser in a container.
  - `keyring` secrets have no Secret Service in a container (use `env` or `file`).
  - `login = "manual"` needs `-it`.
  - `serve` binds to the container's `127.0.0.1`, which `-p` can't reach. Making it reachable would need a bind-address flag, which goes against the web UI's loopback-only rule, so the image targets `run`.
- [ ] README "Releases" says the release also publishes the GHCR images, and notes the one-time manual step: the first push creates the package as private, so a maintainer has to make it public (and link it to the repository if the source label didn't).
- [ ] The `Dockerfile` header comment explains how to build the image locally: build the musl binary, place it in the build-context layout, then run `docker build --target slim|full`.
- [ ] `BACKLOG.md`'s "Multi-arch Alpine image on GHCR" entry is removed, since this ticket finishes it.
- [ ] Committed as `feat:`. No version bump and no `CHANGELOG.md` edit.
