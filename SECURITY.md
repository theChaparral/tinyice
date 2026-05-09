# Security Policy

## Reporting a vulnerability

If you've found a vulnerability in TinyIce — particularly anything that
lets an unauthenticated user inject content into a mount, exfiltrate
listener data, escalate privileges, or crash the server remotely —
please **do not** open a public issue.

Instead:

1. Use GitHub's [private vulnerability reporting][gh-pvr] on this
   repository (Security tab → "Report a vulnerability"). This
   encrypts the report and routes it directly to maintainers.
2. Or email **6614616+DatanoiseTV@users.noreply.github.com** with the
   word `SECURITY` in the subject line.

Please include:

- A description of the issue and what an attacker can do with it.
- Affected versions (and ideally the specific commit, if you've
  bisected it).
- A proof-of-concept or reproduction steps if you have one.
- Whether you'd like to be credited in the published advisory.

We'll acknowledge receipt within 72 hours and aim to ship a patched
release within 7 days for High/Critical, longer for lower severities.
We use GitHub's CVE Numbering Authority path, so once an advisory is
ready it will get a CVE ID assigned and pushed to the National
Vulnerability Database.

[gh-pvr]: https://github.com/DatanoiseTV/tinyice/security/advisories/new

## Supported versions

We patch security issues on the latest minor release line only.
Earlier minor lines may be backported on a best-effort basis at the
maintainers' discretion (high-severity issues, low backport cost).

| Version | Supported          |
|---------|--------------------|
| 2.5.x   | :white_check_mark: |
| 2.4.x   | :warning: critical fixes only |
| < 2.4   | :x:                |

If you are running a release earlier than 2.4, upgrade.

## Scope

In scope:

- Authentication and authorization bypasses on any endpoint.
- Stream injection, listener data exfiltration, or content tampering
  affecting other users of the same TinyIce instance.
- Remote code execution, command injection, path traversal.
- Server-side request forgery (SSRF) reachable from a network attacker.
- Denial of service that an unauthenticated attacker can trigger
  with a small request rate (a single packet that crashes the
  server, or a request that causes unbounded resource use).

Out of scope (please don't report):

- DoS by flooding the server with traffic. Tinyice is a streaming
  server; bandwidth is finite.
- Vulnerabilities in third-party dependencies that don't affect any
  reachable code path in TinyIce.
- Self-XSS or social-engineering scenarios that require an admin to
  paste hostile input into their own admin UI.
- Findings that require a malicious operator to harm their own server.
- Best-practice complaints (missing security headers, weak TLS
  ciphers when the operator can configure them) — open a regular
  issue or PR.

## Hall of Fame

Contributors who responsibly disclosed real issues will be credited
here once their advisory is published, unless they ask to remain
anonymous.

(no published advisories yet)
