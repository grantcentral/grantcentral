# CI tasks: GitHub Action and Azure Pipelines template

Status: ready-for-agent

## Problem Statement

Running GrantCentral in a pipeline today means writing the glue yourself. The README's CI section shows a single `run:` line, but it assumes a `grantcentral` binary is already on the runner. Each pipeline author has to work out which release asset matches the runner's OS and architecture, download and unpack it, decide whether to trust it, point `CHROME` at a browser, remember `--no-sandbox` on Linux, and add steps that upload the JUnit/JSON reports and Chromium screenshots even when the run fails. Each step is easy to get wrong in a way that only shows up when a flow fails, which is exactly when the reports are needed.

Azure DevOps users have the same problem, plus the test-results tab: unless someone wires up `PublishTestResults`, a failed run shows only a red step and a log.

The release doesn't help either. Assets have no checksums, so a pipeline can't verify what it downloaded.

## Solution

Two packaged ways to run `grantcentral run` in CI. Both share the same inputs and behavior:

- **GitHub Action**: `uses: <owner>/grantcentral@v0`, from a composite `action.yml` at the repository root.
- **Azure Pipelines step template**: `ci/azure/grantcentral.yml`, consumed through `resources.repositories`.

Each one resolves the requested GrantCentral version (`latest` by default), downloads the release asset for the agent's OS and architecture, verifies it against the release's new `SHA256SUMS` file, caches it in the agent's tool cache and puts it on `PATH`. It then runs one `grantcentral run` invocation built from the inputs and publishes the reports. A failing flow fails the step with GrantCentral's exit code, and the reports are uploaded anyway.

```yaml
- uses: <owner>/grantcentral@v0
  with:
    project: idp-tests
    env: staging
    login: chromium
  env:
    GC_STAGING_CLIENT_SECRET: ${{ secrets.GC_STAGING_CLIENT_SECRET }}
```

By default they run the prebuilt binary, which works on Linux, macOS and Windows agents and inherits the job's environment. `container: true` runs the full GHCR image instead (from `.scratch/ghcr-image/spec.md`). This is for self-hosted Linux agents that have no Chrome.

## User Stories

1. As a GitHub Actions user, I want to run my GrantCentral project with one `uses:` step, so that I don't have to write download and install logic.
2. As a GitHub Actions user, I want the action to pick the right binary for `runner.os` and `runner.arch`, so that the same workflow works on Linux, macOS and Windows runners.
3. As a GitHub Actions user on an ARM runner, I want the action to install the Linux aarch64 binary, so that I don't need an x86_64 runner.
4. As a GitHub Actions user, I want to pin the GrantCentral version with a `version` input, so that a new release doesn't change my pipeline's results without me knowing.
5. As a GitHub Actions user, I want `version` to default to the latest release, so that trying the action needs no lookup.
6. As a GitHub Actions user, I want `version` to accept both `1.2.3` and `v1.2.3`, so that I don't have to remember which form it expects.
7. As a security-conscious user, I want the downloaded asset verified against a `SHA256SUMS` file from the same release, so that a corrupted or swapped download fails the step before anything runs.
8. As a security-conscious user, I want the action to stop with a clear error when the release has no `SHA256SUMS` or the asset isn't listed in it, so that verification can never be skipped silently.
9. As a self-hosted runner operator, I want the binary cached in the runner's tool cache by version and target, so that repeated jobs don't download it again.
10. As a GitHub Actions user, I want `grantcentral` on `PATH` after the action runs, so that later steps can call it directly (e.g. `grantcentral jwt ...`).
11. As a GitHub Actions user, I want inputs for `project`, `env`, `flows` and `login`, so that common invocations need no hand-written command line.
12. As a GitHub Actions user, I want an `args` input that is passed through to `grantcentral run`, so that I can use `--tag`, `--skip-tag`, `--var`, `--verbose` and future flags without the action having to change.
13. As a GitHub Actions user, I want JUnit and JSON reports written by default, so that every run leaves something to inspect.
14. As a GitHub Actions user, I want the report paths as outputs, so that I can feed them to a test-reporter action or my own step.
15. As a GitHub Actions user, I want the reports and any Chromium failure screenshots uploaded as a workflow artifact even when flows fail, so that I can debug the failure.
16. As a GitHub Actions user running a matrix, I want to set the artifact name, so that parallel jobs don't collide on the same name.
17. As a GitHub Actions user who uploads reports myself, I want to turn the built-in upload off, so that I don't get duplicate artifacts.
18. As a GitHub Actions user, I want the step to fail with GrantCentral's exit code, so that a failed flow fails the job.
19. As a GitHub Actions user, I want the exit code as an output, so that a `continue-on-error` job can tell a failed flow (1) from a configuration error (2).
20. As a GitHub Actions user, I want `env` secrets to work with no extra configuration, so that `GC_*` variables set on the step or job reach the flows.
21. As a GitHub Actions user on a hosted runner, I want `--login chromium` to find the runner's preinstalled Chrome, so that headless logins work without a setup step.
22. As a GitHub Actions user on Linux, I want the Chromium sandbox turned off by default, so that headless logins don't fail on AppArmor-restricted Ubuntu images.
23. As a GitHub Actions user who wants the sandbox, I want to override that default with `GRANTCENTRAL_NO_SANDBOX=false`, so that the action doesn't force the insecure option on me.
24. As a self-hosted Linux runner operator without Chrome, I want `container: true` to run the published image with Chromium inside, so that I don't have to install a browser on my runners.
25. As a container-mode user, I want my workspace mounted at the same path and the run executed as my UID, so that project paths, `file` secrets inside the workspace and report files behave as with the binary.
26. As a container-mode user, I want `GC_*` and `GRANTCENTRAL_*` variables forwarded into the container, so that `env` secrets work without `-e` plumbing.
27. As a container-mode user, I want the container on the host network, so that it can reach authorization servers on `localhost` or in service containers, and so that loopback redirects reach its listener.
28. As a container-mode user on macOS or Windows, I want an immediate, clear error, so that I don't wait for a Docker failure I can't fix.
29. As a GitHub Actions user, I want the action's README section to explain when to pick the binary and when to pick the container, so that I choose without trial and error.
30. As a GitHub Actions user, I want to reference the action by a moving `v0` tag, so that I get action fixes without editing workflows, while `version` pins the binary.
31. As an Azure Pipelines user, I want a step template with the same parameters as the action, so that I can switch CI systems without relearning it.
32. As an Azure Pipelines user, I want the JUnit report published with `PublishTestResults@2` even when flows fail, so that failures show in the pipeline's Tests tab.
33. As an Azure Pipelines user, I want the reports and screenshots published as a pipeline artifact, so that I can download them after a failure.
34. As an Azure Pipelines user, I want the binary cached in the agent's tools directory, so that self-hosted agents don't download it on every run.
35. As an Azure Pipelines user, I want a sample pipeline in the README, including the `resources.repositories` block and the GitHub service connection it needs, so that I can copy it and get started.
36. As an Azure Pipelines user on a self-hosted Linux agent without Chrome, I want the same `container` parameter, so that I get the same fallback as on GitHub.
37. As a maintainer, I want every release to publish `SHA256SUMS` covering all assets, so that both CI integrations and manual downloads can verify assets.
38. As a maintainer, I want the action tested in `ci.yml` against the e2e OP on Linux, macOS and Windows, so that a broken platform mapping or a broken install step shows up on the push that introduces it.
39. As a maintainer, I want the `v0` tag moved from Forgejo during a release, so that the Forgejo push-mirror rule keeps holding and CI never pushes a ref.
40. As a maintainer, I want the release instructions to say when and how to move `v0`, so that the moving tag doesn't fall behind.

## Implementation Decisions

**Release: `SHA256SUMS`**

- The `release` job writes a `SHA256SUMS` file in standard `sha256sum` format (hash, two spaces, bare file name) over every downloaded asset, and attaches it to the GitHub Release next to them. No signing.
- `workflow_dispatch` runs don't need it, since they publish nothing.

**Shared behavior (action and Azure template)**

- **Inputs / parameters** (same names in both):
  - `version`: `latest` (default), `X.Y.Z` or `vX.Y.Z`.
  - `project`: passed as `-C`. Empty means GrantCentral's own upward search from the working directory.
  - `env`: passed as `--env`.
  - `flows`: whitespace-separated flow names or paths, passed as positional `FLOWS`.
  - `login`: passed as `--login`.
  - `args`: extra arguments appended to `grantcentral run`, word-split by the shell. Documented as the escape hatch for every other flag.
  - `junit` / `json`: report paths. They default to files in a `grantcentral/` directory under the runner's temp directory, so that reports never dirty the checkout. An empty value disables that report.
  - `container`: `false` (default) or `true`.
  - `artifact-name` (GitHub) / `artifactName` (Azure): defaults to `grantcentral-report`. An empty value disables the upload.
- **Version resolution:** `latest` is resolved by following the redirect of the GitHub `releases/latest` page to its tag, not through the REST API. This avoids anonymous API rate limits on shared hosted-agent IPs and needs no token. Pre-releases are never `latest`. A missing version fails the step and names the version.
- **Platform mapping** (asset names follow the existing `grantcentral-<tag>-<target>.tar.gz|.zip` scheme):
  - Linux X64 → `x86_64-unknown-linux-musl`; Linux ARM64 → `aarch64-unknown-linux-musl`. These are static, so they don't depend on the agent's glibc. They come from the GHCR image spec's first ticket, which blocks this work.
  - macOS ARM64 → `aarch64-apple-darwin`; macOS X64 → `x86_64-apple-darwin`.
  - Windows X64 and ARM64 → `x86_64-pc-windows-gnu` (`.zip`). Windows on ARM runs x64 binaries under emulation.
  - Anything else fails with the list of supported platforms.
- **Verify:** download the asset and `SHA256SUMS` from the same release, and check the asset's line with `sha256sum`, or with `shasum -a 256` on macOS. A missing `SHA256SUMS` or a missing line is an error, never a warning.
- **Cache:** unpack into the agent's tool cache (`RUNNER_TOOL_CACHE` on GitHub, `Agent.ToolsDirectory` on Azure) under `grantcentral/<version>/<target>/`, and skip the download when that directory already holds the binary. The binary is verified before it goes into the cache, so a cached binary is trusted. Hosted agents start empty, so the cache only helps self-hosted agents. No `actions/cache`, because a cache round-trip costs as much as an 11 MiB download from GitHub.
- **Chrome:** the integrations don't install a browser. GitHub- and Microsoft-hosted images already ship Google Chrome, and chromiumoxide's executable detection finds it. An existing `CHROME` in the environment still wins. Self-hosted agents without Chrome use `container: true`. This drops the backlog's `browser-actions/setup-chrome` fallback, since detection already covers hosted agents.
- **Sandbox:** on Linux agents, set `GRANTCENTRAL_NO_SANDBOX=true` unless the variable is already set. Users can set it to `false` to keep the sandbox. Leave other OSes alone.
- **Exit code:** the run step records GrantCentral's exit code as an output (GitHub) or variable (Azure), then exits with it. Report and artifact upload steps run on success and failure (`if: always()` / `condition: succeededOrFailed()`). They skip missing files without failing, because an exit-2 configuration error may write no report.
- **Container mode** (Linux only; anything else fails immediately with an explanation):
  - Runs `ghcr.io/<owner>/grantcentral:<version without v>` (the `full` variant; `latest` → `:latest`) with `docker run`. It stays a step inside the composite action, not `runs.using: docker`, so that the non-container path keeps working on every OS.
  - It mounts the workspace and the runner temp directory at their host paths, sets the working directory to the current one, runs as the caller's UID:GID and uses `--network host`.
  - It forwards every `GC_*` and `GRANTCENTRAL_*` variable by name (`-e NAME`, so values never appear on the command line). Secrets read from other variable names, and `file` secrets outside the mounted paths, aren't visible. The README says so.
  - Version resolution still happens, so that `latest` maps to a concrete tag in the log. The download and verification are skipped.

**GitHub Action**

- A composite `action.yml` at the repository root, with `name`, `description` and `branding`, so that it can go on the Marketplace later without changes. All steps use `shell: bash`, which exists on all three hosted OSes.
- The install logic lives in one bash script next to `action.yml`, which the action calls via `github.action_path`. The run logic lives in `action.yml`.
- **Inputs never reach a script through `${{ }}` interpolation.** Every input goes through `env:`, so that a workflow can't inject shell through a crafted input.
- Outputs: `exit-code`, `junit`, `json` (the resolved paths, empty when disabled), and `version` (the resolved tag).
- Upload uses `actions/upload-artifact@v4` with the reports and the project's `.grantcentral/screenshots/`.
- `v0` is a moving major tag. A maintainer moves it on Forgejo after each release whose action changes are compatible. CI never moves it.

**Azure Pipelines template**

- A step template at `ci/azure/grantcentral.yml` with `parameters:` matching the inputs above. Users consume it through a `resources.repositories` entry of `type: github` pinned to `refs/tags/v0`. That entry needs a GitHub service connection even though the repository is public, and the README says so.
- It uses `bash:` steps (available on all Microsoft-hosted images). The install logic is inlined, because a template can't reference a file from its own repository without an extra `checkout`, which would move the consumer's `Build.SourcesDirectory`. The inlined copy duplicates the action's install script. A comment at the top of each copy points to the other.
- `PublishTestResults@2` (`testResultsFormat: JUnit`, `failTaskOnFailedTests: false`, since the run step already failed) and `PublishPipelineArtifact@1` for the reports and screenshots, both on `succeededOrFailed()`.
- No Marketplace task (VSIX, `tfx`, publisher account). Build it only if users ask.

**Documentation**

- README "CI": replace the bare `run:` example with the action example. Add the binary-or-container table (trimmed from the backlog), the Azure sample pipeline with its `resources.repositories` block, and the limits of container mode. Move the `Dockerfile` sentence to the container image section from the GHCR spec.
- README "Releases": the release attaches `SHA256SUMS`. After a release, move `v0` on Forgejo (`git tag -fa v0 ... && git push -f origin v0`). Never move it from CI.
- BACKLOG: point the entry to this spec.

## Testing Decisions

- A good test runs the action the way a user's workflow does, against a real authorization server, and judges it only by what a user sees: the step outcome, the `exit-code` output and the uploaded artifact. Don't test the install script's internals (URL construction, mapping tables) in isolation. A broken mapping shows up as a failed download on that OS.
- **The only seam is the e2e OP with the local action (`uses: ./`).** It's prior art from the `e2e` job in `ci.yml`, which already runs the suite against the local OP.
  - The e2e runner gains a server-only mode: generate certificates, start the OP, wait until it is ready, and leave it running for later steps. The normal mode is unchanged.
  - New `action` job in `ci.yml`, matrix `ubuntu-latest`, `macos-latest`, `windows-latest`: start the OP in server-only mode, then run the action with `version: latest`, `project: e2e/project` and `args: --tag smoke`. The smoke flows need no Chromium (03 uses `login = "http"`). This covers version resolution, download, checksum verification, platform mapping, `PATH` and report upload on every OS, and it tests the binary as users get it. This commit's binary stays covered by the existing `e2e` job.
  - Negative case, on Linux: run the action with a nonexistent `env` under `continue-on-error: true`, then assert that the step outcome is `failure` and `exit-code` is `2`.
  - Container case, on Linux: the same smoke run with `container: true`. Blocked by the GHCR image being published.
  - If the e2e OP can't run on the Windows runner, the Windows leg drops to `args: --version`. It then still covers install and mapping, and the job log says so.
- **Sequencing:** the action job needs a published release that has `SHA256SUMS` and the musl assets, so land the release-workflow changes and cut a release before adding that job.
- The Azure template has no CI here (no Azure organization). It's verified by hand once with the README's sample pipeline on a Microsoft-hosted Ubuntu agent, and the PR records that run.
- `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` and the existing `e2e` job are unaffected and must keep passing.

## Out of Scope

- An Azure DevOps Marketplace task (VSIX, `tfx`, publisher account, Node task runner).
- Publishing the action on the GitHub Marketplace. Do that once the inputs are stable, as a separate step.
- Installing Chrome from the action or template (`setup-chrome`). Self-hosted agents without Chrome use the container.
- A job summary, PR annotations or a built-in test reporter. The JUnit output feeds existing reporters.
- An install-only mode. The binary is on `PATH` after one run, and a separate setup action can come later if users ask.
- Forwarding arbitrary environment variable names into the container. Only `GC_*` and `GRANTCENTRAL_*` are forwarded.
- Signing release assets (cosign, minisign) beyond `SHA256SUMS`.
- GitLab CI, Jenkins and other CI systems.
- `serve` in CI.

## Further Notes

- Blocked by `.scratch/ghcr-image/issues/01-musl-release-binaries.md` (Linux assets). Container mode is also blocked by `.scratch/ghcr-image/issues/04-publish-ghcr-and-docs.md`. The GHCR spec notes that whichever of the two lands `SHA256SUMS` second has to include the musl tarballs. This spec adds `SHA256SUMS` over every asset, so that holds automatically.
- Check the current GitHub Marketplace listing requirements before listing the action, in particular any restriction on workflow files in the same repository. If one applies, the action may need its own mirror repository, which would change the `uses:` path. Decide that before telling users to depend on `@v0`.
- The `v0` tag has to exist on Forgejo before the README advertises `uses: <owner>/grantcentral@v0`.
