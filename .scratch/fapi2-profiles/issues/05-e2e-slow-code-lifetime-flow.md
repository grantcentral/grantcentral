# 05: e2e: slow flow for the authorization code lifetime

**What to build:** A user can verify FAPI 2.0's 60-second authorization code lifetime, a rule the client can't observe directly, with a flow that authorizes, waits just over 60 s, then redeems and expects an error. Ordinary e2e runs skip it so they don't get a minute slower.

**Blocked by:** 04 (e2e: FAPI client, happy-path flow and negative flow)

**Status:** ready-for-agent

- [ ] A code-lifetime flow against the dedicated FAPI client authorizes, waits just over 60 s, redeems the code with `expect = "error"`, and is tagged `slow`.
- [ ] `e2e/run.sh` skips flows tagged `slow` by default, the same way it skips `chromium` without a browser, and documents how to include them.
- [ ] README "Specification coverage" names this flow for the code-lifetime rule.
- [ ] `BACKLOG.md` FAPI 2.0 and OAuth 2.1 entries are updated to match what landed. In particular, the code lifetime is covered by this flow, not by a live check.
- [ ] `e2e/run.sh` passes with and without the `slow` flows.
