# Project: [Your App Name]

> **Fork of [Baseline](https://github.com/revolv-build/baseline)** — a production-ready Flask starter kit.
> Update this file with your project's specific details after forking.

**Live:** [your-app-url]
**Repo:** [your-repo-url]

---

## Core Architecture

| Layer | Technology |
|---|---|
| **Framework** | Flask 3.x (Python 3.12) |
| **Database** | SQLite with WAL mode, foreign keys, cascading deletes |
| **Server** | Gunicorn (4 workers) behind Nginx reverse proxy |
| **SSL** | Let's Encrypt via Certbot (auto-renewing) |
| **Email** | Resend API (transactional emails — needs API key) |
| **Process manager** | systemd (auto-restarts on crash) |
| **Static files** | Served directly by Nginx with gzip + 7-day cache |
| **Uploads** | Stored on disk at `uploads/`, served by Nginx |
| **Tests** | pytest (`make test`) |

### Single-file architecture
The backend is `app.py`. This is intentional for early development — split into Flask Blueprints when the file exceeds ~1,500 lines or when multiple developers are contributing.

---

## What's Included (from Baseline)

### Authentication
- Login / Register with honeypot + time trap bot protection
- Password reset via email (Resend API)
- Email verification on registration
- Session-based auth with 7-day lifetime
- Session regeneration to prevent fixation
- `@login_required` and `@platform_admin_required` decorators

### Account Management
- Profile editing (name, email, bio, location, website)
- Password change
- Avatar upload
- GDPR data export (JSON download)
- GDPR account deletion (cascading deletes)

### Admin Dashboard
- Platform stats (total users, new this week)
- User list with role management
- Toggle admin status
- Delete users
- User impersonation (for debugging)

### Security
- CSRF protection (Flask-WTF) with auto-injection (`csrf.js`)
- Rate limiting (Flask-Limiter)
- Security headers (X-Frame-Options, CSP, HSTS, etc.)
- Honeypot + time trap on login/register (bot protection)
- File upload MIME validation
- Parameterised SQL queries (no injection)
- Password hashing (werkzeug/bcrypt)

### UI
- Dark theme throughout (#0f0f0f background)
- Toast notifications (auto-dismiss, stacked)
- Back to top button
- Cookie consent banner
- Error pages (404, 500, 429)
- Mobile responsive
- Markdown rendering with HTML sanitisation

### Infrastructure
- `Makefile` — run, setup, seed, test, deploy, backup
- `seed.py` — demo data generator
- `migrate.py` (built into app) — numbered SQL migrations
- `setup.sh` — first-time server provisioning
- `systemd/` and `nginx/` — example deployment configs
- GitHub Actions — deploy on push, tests on PR
- `.env.example` — documented config template

### Example CRUD (Notes)
A working create/read/update/delete flow for "notes" is included as a pattern to copy. **Delete the notes code when you build your own features.** The notes code lives in:
- `app.py` — routes in the "EXAMPLE CRUD" section
- `templates/notes/` — new, view, edit templates
- `tests/test_notes.py` — example tests

---

## Database Schema

```
users    — Platform accounts (name, email, password_hash, is_admin, email_verified, bio, location, website, avatar_path)
notes    — Example CRUD entity (delete when building your features)
```

Schema is created in `init_db()` in app.py. Migrations go in `migrations/` as numbered `.sql` files.

---

## Deployment

- **CI/CD:** GitHub Actions — pushes to main trigger deploy via SSH
- **GitHub Secrets needed:** `SSH_HOST`, `SSH_PRIVATE_KEY`, `APP_DIR`, `APP_SERVICE`
- **Manual deploy:** `make deploy` (update the SSH details in Makefile first)
- **First-time setup:** `bash setup.sh YOUR_APP your.domain.com 5000`
- **Logs:** `journalctl -u YOUR_APP -f`

---

## How To

### Add a new page
1. Add a route in `app.py` with `@login_required` (or `@platform_admin_required`)
2. Create a template in `templates/` extending `base.html`
3. Add a nav link in `templates/base.html` if it should appear in navigation

### Add a new database table
1. Add `CREATE TABLE IF NOT EXISTS` to `init_db()` in `app.py`
2. For existing databases, also add an `ALTER TABLE` or `CREATE TABLE` in a new file under `migrations/` (e.g. `002_add_projects.sql`)
3. The migration runs automatically on next boot

### Add a new CRUD feature
1. Copy the notes pattern (routes + templates + tests)
2. Add your table to `init_db()`
3. Create routes with `@login_required`
4. Create templates extending `base.html`
5. Add tests in `tests/`

### Add file uploads to a feature
1. Follow the avatar upload pattern in `account_avatar()`
2. Use `secure_filename()` and check against `ALLOWED_EXTENSIONS`
3. Store in `uploads/<feature_name>/`
4. Nginx serves `uploads/` directly in production

### Add a new admin feature
1. Add route with `@platform_admin_required`
2. Add to `admin.html` template
3. Add to admin bar in `base.html` if it's a top-level section

### Send an email
```python
send_email(
    to="user@example.com",
    subject="Your subject",
    html_body="<h1>Hello</h1><p>Your email content.</p>"
)
```
Emails are logged to console if `RESEND_API_KEY` is not set.

### Deploy
1. Push to main (auto-deploys via GitHub Actions)
2. Or manually: `make deploy`
3. First-time: `bash setup.sh appname domain.com 5000`

### Run tests
```bash
make test
```

### Common gotchas
- Always use parameterised queries (`?` placeholders) — never f-strings in SQL
- Always add CSRF token to new forms (handled automatically by `csrf.js`)
- New migrations must be idempotent (`IF NOT EXISTS`, `ALTER TABLE` with try/except)
- Test with `make run` before pushing
- The default admin is `admin@example.com` / `changeme` — change this in production

---

## Patterns & Conventions

### Route structure
- **Auth routes:** `/login`, `/register`, `/logout`, `/forgot-password`, `/reset-password/<token>`, `/verify-email/<token>`
- **App routes:** `/dashboard`, `/notes/new`, `/notes/<id>`, `/notes/<id>/edit`
- **Account routes:** `/account`, `/account/profile`, `/account/password`, `/account/avatar`, `/account/export`, `/account/delete`
- **Admin routes:** `/admin`, `/admin/users/<id>/toggle-admin`, `/admin/users/<id>/delete`, `/admin/users/<id>/impersonate`

### Auth decorators
- `@login_required` — any authenticated user
- `@platform_admin_required` — `is_admin` flag on users table

### Database access
- `get_db()` — returns SQLite connection from Flask `g` object, auto-closed on teardown
- `sqlite3.Row` row factory — access columns by name
- All queries use parameterised `?` placeholders (no SQL injection)

### Template hierarchy
- `templates/base.html` — main layout (nav, admin bar, flash messages, footer)
- Auth templates (login, register, etc.) — standalone, don't extend base
- App templates — extend `base.html`

### CSS
- `static/style.css` — all styles, dark theme
- No CSS framework — all custom
- Class naming: `.section-element` (e.g. `.adm-user-row`, `.item-card-title`)

### JavaScript
- `static/csrf.js` — auto-injects CSRF tokens into forms and fetch calls
- `static/toast.js` — toast notification system
- `static/platform.js` — back to top button
- No JS framework, no build step

### Helpers available in templates
- `current_user` — the logged-in user object (or None)
- `avatar_html(user, size)` — generates avatar HTML
- `app_name` — the application name from config
- `support_email` — support email from config
- `|markdown` — renders markdown to sanitised HTML
- `|strip_markdown` — strips markdown for plain text previews
- `|timeago` — converts ISO datetime to relative time ("3h ago")
- `|truncate(n)` — Jinja2 built-in, truncates text

---

## Do Not Touch

- **Database files** (`data/app.db`) — live data in production. Never delete. Always migrate with `ALTER TABLE`.
- **`app.secret_key`** — changing it invalidates all active sessions and password reset tokens.
- **Other apps on the server** — check what else is running on the same port range before deploying.

---

## Key Decisions Log

<!-- Add dated entries here when making architectural decisions -->

**YYYY-MM-DD** — Forked from Baseline. [Describe why, what the app will do]

---

## Session Protocol

At the end of every session, before finishing:
1. Update **Current State** to reflect what changed
2. Add a dated entry to **Session Log** below
3. Add any new architectural decisions to **Key Decisions Log**
4. Commit the updated CLAUDE.md with: `docs: session log YYYY-MM-DD`

---

## Current State

### Built and working
- Everything from Baseline (auth, admin, account, GDPR, security, deployment)
- Example CRUD (notes) — delete when building your features

### Not yet activated (needs config)
- **Resend email:** Set `RESEND_API_KEY` in `.env`
- **Production secret key:** Set `SECRET_KEY` in `.env` (auto-generated by `setup.sh`)

### Next priorities
- [ ] Define your app's core feature
- [ ] Add your database tables
- [ ] Build your first routes and templates
- [ ] Delete the example notes feature
- [ ] Update this CLAUDE.md with your project details

---

## Session Log

### YYYY-MM-DD
**Initial fork from Baseline.**

Forked from revolv-build/baseline. Updated CLAUDE.md with project details.

[Describe what was built, decisions made, where you left off]
