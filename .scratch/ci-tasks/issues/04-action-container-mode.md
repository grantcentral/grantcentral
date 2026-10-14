# 04: Action container mode

**What to build:** On a self-hosted Linux runner without Chrome, `container: true` runs the published GHCR image (the `full` variant, with Chromium) in place of the downloaded binary. Inputs, the environment, reports and the exit code behave as in binary mode. On macOS and Windows, `container: true` fails right away with an explanation. See the spec (`../spec.md`), "Container mode", "Documentation" and "Testing Decisions".

**Blocked by:** 03 (GitHub Action, binary mode), `.scratch/ghcr-image/issues/04-publish-ghcr-and-docs.md` (the image is published)

**Status:** ready-for-agent

- [ ] `container: true` runs `ghcr.io/<owner>/grantcentral:<version without v>` with `docker run`, as a step of the composite action, not `runs.using: docker`. `latest` maps to `:latest`. The owner is lowercased, as GHCR requires.
- [ ] Version resolution still runs, so the log shows the concrete tag. The download and verification are skipped.
- [ ] The workspace and the runner temp directory are mounted at their host paths. The working directory is the current one, the container runs as the caller's UID:GID and uses `--network host`.
- [ ] Every `GC_*` and `GRANTCENTRAL_*` variable is forwarded by name (`-e NAME`), so values never appear on the command line or in the log.
- [ ] Reports written in the container land at the paths the `junit`/`json` outputs name, belong to the caller, and are uploaded as in binary mode. The exit code propagates as in binary mode.
- [ ] On a runner other than Linux, the step fails before pulling anything and says that container mode needs a Linux runner with Docker.
- [ ] The `action` job in `ci.yml` gets a Linux case that runs the same smoke flows with `container: true` against the server-only OP.
- [ ] README "CI": the binary-or-container table (trimmed from the backlog) and the container limits. Only `GC_*`/`GRANTCENTRAL_*` variables reach the flows, `file` secrets outside the workspace and temp directory aren't visible, and the mode is Linux only.
- [ ] Committed as `feat:`. No version bump and no `CHANGELOG.md` edit.
