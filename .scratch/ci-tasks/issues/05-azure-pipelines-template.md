# 05: Azure Pipelines step template

**What to build:** Azure DevOps users get the same experience as the GitHub Action through a step template consumed with `resources.repositories`. The template takes the same parameters, including `container`. It installs and verifies the same release asset, caches it in the agent's tools directory and runs one `grantcentral run`. It publishes the JUnit report to the pipeline's Tests tab and the reports as a pipeline artifact, including when flows fail. See the spec (`../spec.md`), "Shared behavior", "Azure Pipelines template" and "Testing Decisions".

**Blocked by:** 03 (GitHub Action, binary mode), 04 (Action container mode)

**Status:** ready-for-agent

- [ ] A step template at `ci/azure/grantcentral.yml` with `parameters:` matching the action's inputs (`artifactName` instead of `artifact-name`) and the same defaults.
- [ ] It uses only `bash:` steps, so it runs on Microsoft-hosted Linux, macOS and Windows agents.
- [ ] The install logic is inlined from the action's install script, with `Agent.ToolsDirectory` as the cache and `##vso[task.prependpath]` for `PATH`. A comment at the top of each copy points to the other, so the two get changed together.
- [ ] Parameters reach scripts through `env:` mappings, never through `${{ }}` interpolation inside a script body.
- [ ] The Linux sandbox default, the container mode and the `GC_*`/`GRANTCENTRAL_*` forwarding match the action.
- [ ] The run step records the exit code in an output variable and fails with it.
- [ ] `PublishTestResults@2` (`testResultsFormat: JUnit`, `failTaskOnFailedTests: false`) and `PublishPipelineArtifact@1` run on `succeededOrFailed()`, and neither fails when a report is missing. Publishing the artifact is skipped when `artifactName` is empty.
- [ ] README "CI": a sample Azure pipeline with the `resources.repositories` entry (`type: github`, `ref: refs/tags/v0`) and a note that it needs a GitHub service connection even though the repository is public.
- [ ] Verified by hand once: the README sample runs on a Microsoft-hosted Ubuntu agent with one passing and one failing invocation. The PR records the run, including the Tests tab result.
- [ ] Committed as `feat:`. No version bump and no `CHANGELOG.md` edit.
