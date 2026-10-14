# GrantCentral

A client-side test tool for OAuth 2.0 / OpenID Connect authorization servers. Users describe flows; GrantCentral runs them and reports which spec rules the server's responses meet.

## Language

### Checks

**Check**:
A built-in, spec-cited verdict on one fact about a server response or its metadata, with a severity of error, warning or info.
_Avoid_: Assertion (that is a user-written expression), test, rule

**Audit**:
The set of checks run against an authorization server's published metadata, as opposed to its live responses.
_Avoid_: Scan, lint

### Who the checks apply to

**Client type**:
The kind of client the server is judged for: confidential, browser or native. It decides which checks apply and how strict they are.
_Avoid_: Profile, client profile

**Profile**:
A named, versioned set of spec rules (e.g. FAPI 2.0 Security Profile) that tightens checks — raising severities, narrowing allowed values, adding profile-only checks — and never loosens them. Several profiles can apply at once; the strictest rule wins.
_Avoid_: Security profile, mode, conformance level

**Profile checks**:
The subset of a profile's rules that GrantCentral verifies. Passing them is not conformance.
_Avoid_: Conformance, certification, compliance

**Conformance**:
A claim that a server meets a profile in full, as established by the profile owner's official suite (e.g. the OpenID Foundation's). GrantCentral never makes this claim.
