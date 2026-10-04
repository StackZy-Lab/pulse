# Security policy

## Reporting a vulnerability

Please report security issues privately using GitHub's
["Report a vulnerability"](https://github.com/StackZy-Lab/pulse/security/advisories/new)
flow, or by emailing the maintainers listed on the organization page. Do not
open a public issue for a vulnerability. We will acknowledge your report as
quickly as we can and keep you updated on the fix.

## Scope and threat model

`pulse` is a command-line HTTP(S) client that checks URLs the user provides. It
runs with the user's own privileges and connects wherever it is pointed, so it
deliberately does **not** include the private-network filtering a multi-tenant
server needs. Running `pulse` against an internal address is expected behavior,
not a vulnerability.

Security-relevant behaviors to be aware of:

- **Certificate verification is on by default.** `--insecure` disables it and
  records a warning finding on every affected check. Only use it to inspect
  servers you are authorized to test.
- **Request bodies are not downloaded by default.** `--max-body` reads up to a
  user-supplied byte count.
- **Cross-origin redirects drop caller headers**, including `Authorization` and
  `Cookie`, and any redirect that would resend a body to a different origin is
  refused.
- **URLs with embedded credentials are rejected**, and `--header` values are
  validated to prevent request smuggling via CRLF injection.

If you find a case where these guarantees do not hold, that is a vulnerability
worth reporting.
