# Client type and profiles are separate settings

Audit settings split into `client_type` (confidential, browser, native: who the client is) and `profiles` (a list of rule sets such as `fapi2` that tighten checks). They are independent axes — OAuth 2.1 applies to any client type, FAPI 2.0 only to confidential clients — and the single overloaded `profile = "browser"` setting could not express both. Profiles only ever tighten checks, so several combine order-independently by strictest-wins.

## Considered Options

- Keep `profile` for client type and add `security_profile`: the specs call themselves "profiles" (FAPI 2.0 Security *Profile*), so the new concept gets the natural word.
- One enum (`confidential | browser | native | fapi2`): cannot express "OAuth 2.1 for a browser client".

## Consequences

Breaking change (`feat!:`). The audit step's old `profile` and `discover --profile browser|native|confidential` stay as deprecated aliases for one release; the client type and profile value sets don't overlap, so the aliases are unambiguous.
