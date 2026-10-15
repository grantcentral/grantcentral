# 03: GitHub Action, binary mode, tested on Linux, macOS and Windows

**What to build:** `uses: <owner>/grantcentral@v0` works on GitHub-hosted Linux, macOS and Windows runners. The action resolves the requested GrantCentral version (`latest` by default), downloads the release asset for the runner, verifies it against `SHA256SUMS`, caches it in the tool cache and puts it on `PATH`. It then runs one `grantcentral run` built from its inputs and uploads the reports and screenshots as an artifact, including when flows fail. The step fails with GrantCentral's exit code, which is also an output. A new `action` job in `ci.yml` runs the action against the e2e OP on all three OSes. See the spec (`../spec.md`), "Shared behavior", "GitHub Action", "Documentation" and "Testing Decisions".

**Blocked by:** 01 (`SHA256SUMS` on every release), 02 (Server-only mode for the e2e runner), `.scratch/ghcr-image/issues/01-musl-release-binaries.md`, and a published release that already has `SHA256SUMS` and the musl tarballs (a human cuts it from Forgejo).

**Status:** ready-for-agent

- [ ] A composite `action.yml` at the repository root has `name`, `description` and `branding`. Every step uses `shell: bash`.
- [ ] Inputs: `version`, `project`, `env`, `flows`, `login`, `args`, `junit`, `json`, `container` and `artifact-name`, with the defaults and empty-value meanings from the spec. `container: true` may fail with "not implemented yet" until ticket 04.
- [ ] Outputs: `exit-code`, `junit`, `json` (the resolved paths, empty when disabled) and `version` (the resolved tag).
- [ ] No input is interpolated into a script with `${{ }}`. Every input reaches the scripts through `env:`.
- [ ] The install logic lives in one bash script next to `action.yml`, which the action calls through `github.action_path`. It:
  - [ ] resolves `latest` by following the `releases/latest` redirect to its tag, not through the REST API, and accepts `X.Y.Z` and `vX.Y.Z`. An unknown version fails the step and names the version;
  - [ ] maps Linux X64/ARM64 to the musl targets, macOS ARM64/X64 to the Apple targets, and Windows X64/ARM64 to `x86_64-pc-windows-gnu` (`.zip`). Any other platform fails and lists the supported ones;
  - [ ] verifies the asset with `sha256sum`, or with `shasum -a 256` where `sha256sum` is missing. A missing `SHA256SUMS` or a missing line for the asset is an error;
  - [ ] unpacks the verified binary into `RUNNER_TOOL_CACHE` under `grantcentral/<version>/<target>/`, skips the download when that directory already holds the binary, and adds the directory to `GITHUB_PATH`.
- [ ] On Linux the action sets `GRANTCENTRAL_NO_SANDBOX=true` unless the variable is already set. `false` keeps the sandbox. Other OSes are left alone. The action installs no browser, and an existing `CHROME` is respected.
- [ ] `GC_*` variables from the step or job reach the flows with no extra configuration.
- [ ] The upload step uses `actions/upload-artifact@v4` and runs on success and failure. It uploads the reports and the project's `.grantcentral/screenshots/`, ignores missing files and is skipped when `artifact-name` is empty.
- [ ] New `action` job in `ci.yml`, with a matrix of `ubuntu-latest`, `macos-latest` and `windows-latest`. It starts the OP in server-only mode and runs `uses: ./` with `version: latest`, `project: e2e/project` and `args: --tag smoke`. Each matrix leg sets its own `artifact-name`. If the OP can't run on Windows, the Windows leg uses `args: --version` instead, and the job log says why.
- [ ] Negative case on Linux: the action runs with a nonexistent `env` under `continue-on-error: true`. A following step asserts that the outcome is `failure` and `exit-code` is `2`.
- [ ] The existing `test` and `e2e` jobs still pass.
- [ ] README "CI": the bare `run:` example is replaced by the action example, with the inputs and outputs and a note that `version` pins the binary while `@v0` pins the action.
- [ ] README "Releases": after a release, a maintainer moves `v0` on Forgejo with an annotated tag and a force push. CI never moves it.
- [ ] Nothing in any workflow pushes a git ref.
- [ ] Committed as `feat:`. No version bump and no `CHANGELOG.md` edit.
