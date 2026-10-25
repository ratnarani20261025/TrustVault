# Threat model — TrustVault

## Assets
Confidential file bytes, document metadata, user credentials, permission grants, and audit events.

## Trust boundaries
Browser to Flask routes; authenticated user to each document; Flask process to private filesystem and SQLite database.

## Threats and controls
1. **Guessing a document UUID / IDOR** — Every metadata/download/mutation route checks authorization on the server. Tests verify a different viewer cannot view or download a document.
2. **Revoked user reuses an old link** — Every request re-reads current grants from SQLite; revocation should block the next request. Tests cover grant and revoke.
3. **UI-only authorization** — Routes enforce authorization independently of hidden buttons.
4. **Unauthorized permission change** — Only owner/admin with edit access may change grants; unauthorized attempts are denied and logged.
5. **Malicious file path / overwrite** — Original filename is not used as a filesystem path; a UUID storage name is used. Downloads use a sanitized display name.
6. **Unexpected upload type / oversized upload** — Extension allow-list and 5 MB cap; production needs MIME/content signature checks and malware scanning.
7. **Cross-site request forgery** — POST forms require a per-session CSRF token. Production should also configure secure cookie attributes and review same-site behavior.
8. **Password disclosure in repository** — Demo passwords are intentionally documented for evaluator convenience; replace them before public deployment and never use real credentials.
9. **Audit repudiation / tampering** — Important events including denied access are logged. Limitation: SQLite logs can be changed by a host administrator; production should export to append-only remote storage.
10. **Brute-force login** — Not rate-limited in this demo; production must add rate limiting and alerting.
11. **Session theft / insecure transport** — HTTPS and secure cookie flags must be configured at deployment; do not deploy without HTTPS.
12. **Downloaded copy after revocation** — Revocation only blocks future server access; it cannot recall a file already downloaded.
13. **XSS through filenames/details** — Jinja autoescaping is enabled; avoid marking user-controlled content safe.
14. **Concurrent deletion/download** — A deletion between authorization and file read may cause a 404; no unauthorized bytes should be served.
15. **Admin account compromise** — Admin can read all documents. Production requires MFA and least-privilege operational controls.

## Tests that should be run
- Viewer A cannot see, open, or download Viewer B's unshared document.
- A granted viewer can download; after revocation, the same URL is denied.
- Viewer cannot upload, rename, delete, or grant access.
- A viewer cannot open the admin audit page.
- Unsupported extension and oversized file are rejected.
- Permission changes and denied access are present in audit records.

## Deliberately not implemented
No external sharing links, folder inheritance, AI-driven permission decisions, public file URLs, malware scanner, or cryptographically immutable audit store. The smaller permission model is easier to test and explain.
