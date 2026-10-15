# 02: Server-only mode for the e2e runner

**What to build:** A prefactor for ticket 03. The e2e runner can start the local OP and leave it running, without running any flows. Later CI steps (the GitHub Action under test) can then run flows against it. See the spec (`../spec.md`), "Testing Decisions".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The server-only mode installs the Node dependencies, generates the mTLS certificates if they are missing, starts the OP, waits until discovery answers and returns while the OP keeps running. It does not kill the OP on exit.
- [ ] After it returns, `grantcentral -C e2e/project run --tag smoke` passes against the running OP from a separate shell or CI step.
- [ ] The OP log still goes to the same log file, so CI can upload it.
- [ ] The default mode (start the OP, run the flows, stop the OP) behaves exactly as before. The existing `e2e` job in `ci.yml` passes unchanged.
- [ ] The runner's header comment documents the new mode.
- [ ] Committed as `test:` or `ci:`. No version bump and no `CHANGELOG.md` edit.
