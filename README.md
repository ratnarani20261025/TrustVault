# TrustVault — secure document sharing

TrustVault is a small Flask + SQLite demonstration of server-enforced document permissions and audit logging.

## Features
- Three roles: `admin`, `owner`, `viewer`.
- Upload, search, view, download, rename and delete documents.
- Per-document read/edit grants to named users; grant revocation is checked on every future request.
- Server-side authorization on document metadata, download, rename, delete and permission changes.
- Audit events for login success/failure, views, downloads, denied access, edits, deletes and permission changes.
- Admin-only audit page.
- Extension allow-list, 5 MB upload limit, randomized storage names, private file storage outside `static/`.
- CSRF tokens on POST forms and password hashes using Werkzeug.
- Automated authorization tests.

## Run locally
Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000.

## Demo accounts
| Username | Password | Role |
|---|---|---|
| admin | AdminDemo!2026 | admin |
| owner | OwnerDemo!2026 | owner |
| viewer | ViewerDemo!2026 | viewer |
| other | OtherDemo!2026 | viewer |

These are disposable demo credentials. Change them and set a strong `SECRET_KEY` before any internet deployment. Do not upload real confidential documents to this demo. For production, add password change/reset, rate limiting, secure cookie settings, malware scanning, content sniffing, backups, immutable/external audit storage, HTTPS, and a managed database.

## Tests
```bash
python -m unittest discover -s tests -v
```

## Permission model
- Admin: can read/manage every document and view the audit trail.
- Owner: owns documents they upload; can read/edit/manage those documents and grant/revoke access to named users.
- Viewer: can read/download only documents explicitly granted to them.
- Edit permission implies read permission.
- All authorization decisions happen server-side. Hiding a button is not considered security.
- Revoking a grant blocks future requests, including downloads. A file already downloaded cannot be recalled.

## Storage and audit
Uploaded bytes are stored under `private_uploads/` with random UUID filenames, not in the public static directory. Routes check authorization before serving bytes. SQLite stores metadata, grants and audit records. This demo audit table is not tamper-proof against a host/database administrator; production needs append-only or externally protected logging.

## API / routes overview
- `POST /login`, `POST /logout`
- `GET /documents` — current user's accessible list; filters: `q`, `category`, `owner`, `date`
- `POST /upload`
- `GET /document/<id>` — metadata and grant management UI
- `GET /document/<id>/download`
- `POST /document/<id>/grant`
- `POST /document/<id>/rename`
- `POST /document/<id>/delete`
- `GET /admin/audit` — admin only

## Known limitations
- This is a challenge/demo implementation, not production-ready document infrastructure.
- User creation and password changes are not implemented in the UI; demo users are seeded at startup.
- Audit rows are application-level logs, not cryptographically immutable.
- File validation is extension-based; production should also inspect actual content and scan for malware.
- Automated tests focus on authorization boundaries and basic workflow.
