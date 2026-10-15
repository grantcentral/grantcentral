# 03: Full image with Chromium, e2e-tested

**What to build:** A `full` image variant, built on top of `slim`, adds Alpine's Chromium and is set up for headless logins in a container. `CHROME` and `GRANTCENTRAL_NO_SANDBOX=true` are preset, so `docker run ... run --login chromium` works with no extra flags, including when the container runs as the caller's UID. The `image` job from ticket 02 also builds `full` for `linux/amd64` and runs the whole e2e suite through it, `chromium`-tagged flows included, with Chromium running inside the image. See the spec (`../spec.md`), "Image" and "Testing Decisions".

**Blocked by:** 02 (Slim image, built and e2e-tested in the release workflow)

**Status:** ready-for-agent

- [ ] The `Dockerfile` has a `full` stage that starts `FROM slim`, so the two variants can't drift apart.
- [ ] `full` installs Alpine's `chromium` package plus whatever it needs at runtime that the package doesn't already pull in. Check `nss` against the package's own dependencies before listing it.
- [ ] `CHROME` points at the browser binary the pinned Alpine version actually installs (verify `chromium-browser` vs `chromium`). `GRANTCENTRAL_NO_SANDBOX=true` is set.
- [ ] The `image` job builds `full` for `linux/amd64` with `load: true` and runs `e2e/run.sh` through the wrapper with no skipped tags. The suite's Chrome auto-detection looks at the host, so the invocation has to tell it a browser exists. If it doesn't, the `chromium` flows are silently skipped.
- [ ] The `chromium` flows pass when the container runs as the caller's UID, not the image's user. This exercises the writable `HOME` and the temp-dir Chromium profile.
- [ ] On failure, the screenshots from `.grantcentral/screenshots/` are uploaded with the JUnit report and the OP log.
- [ ] The PR records the uncompressed size of the amd64 `slim` and `full` images, next to today's Debian image.
- [ ] Committed as `ci:` or `feat:`. No version bump and no `CHANGELOG.md` edit.
