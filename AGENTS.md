# Repository guide for coding agents

## Purpose and layout

Honeytoken Logger is a self-hosted web honeypot and tracked-link service. `run.py` starts two Flask apps under Waitress: the public trap in `trap_app.py` and the authenticated dashboard in `admin_app.py`. `templates/` contains trap/error pages; most dashboard HTML, CSS, and JavaScript are embedded in `admin_app.py`, with final-action UI fragments in `admin_final_actions.py`.

- `models.py`, `db.py`, `store.py`: SQLAlchemy hit/link schema, SQLite engine and startup schema additions, and data access. The default database is `$DATA_DIR/honey.db` (`/data` in the container); SQLite uses WAL.
- `config_store.py`: defaults, validation, and atomic writes for `$DATA_DIR/config.json`, including host-specific final actions, notification rules, and spam-summary settings. This is distinct from the hit database.
- `proxy_trust.py`, `geoip2_lookup.py`, `fingerprint.py`, `visitor_fingerprint.py`: visitor IP trust, optional local GeoLite2 lookups, server-side clues, and bounded browser fingerprint data.
- `alerts.py`, `hit_notifications.py`, `notification_batch.py`, `background_tasks.py`: immediate/after-capture alerts, Discord rules and batching, and a bounded worker queue. `spam_analysis.py` and `spam_summary_scheduler.py` produce scheduled Discord summaries; `analyze_spam.py` is the read-oriented CLI.
- `maintenance.py` handles optional hit retention; `backup_db.py` creates a consistent SQLite online backup. `tests/` holds regression tests.

## Development and verification

Use Python 3.12 (`pyproject.toml` limits the project to 3.12). From the repository root, install `requirements.lock` and `requirements-dev.txt` in an isolated environment, then run:

```sh
ruff check .
pytest
bandit -r . -x ./.git,./data,./media,./tests -q
pip-audit -r requirements.lock --progress-spinner off
ADMIN_PASS=test ADMIN_SECRET_KEY=test CARTO_API_KEY=test \
  docker compose --env-file /dev/null -f docker-compose.example.yml config --quiet
```

`tests/conftest.py` sets dummy credentials and a temporary `DATA_DIR`/`DATABASE_URL` before importing the app. Follow that pattern for new tests; never point tests or ad hoc scripts at a live database. CI (`.github/workflows/ci.yml`) runs these checks on pushes to `main` and pull requests. The Dockerfile installs `requirements.lock`, copies an explicit file list, and runs as a non-root user; update that list when adding a runtime module. `docker-compose.example.yml` is the tracked deployment template; a local `docker-compose.yml` is an ignored override. Compose `config --quiet` validates configuration without starting services.

## Request and trust boundaries

- The trap logs each catch-all request, choosing tracked-link settings by `/l/<token>` or host/path, then returns `trap_loading.html`. The page posts browser data to `/capture`; only a matching per-hit `capture_token` permits updating that hit and sending after-capture alerts. Final actions may redirect, display media, or return a fake error. Preserve the distinction between immediate and after-capture notifications and the bounded, sanitized client payload.
- Client IP resolution belongs in `proxy_trust.py`: forwarded headers are ignored for untrusted peers, `X-Forwarded-For` is never trusted, and `CF-Connecting-IP` is honored only for a direct Cloudflare peer from configured ranges. For a trusted local reverse proxy, use proxy-controlled `X-Real-IP`; changes to proxy headers can corrupt hit attribution. Host-specific settings and tracked-link overrides are separate paths through `trap_app.py` and `config_store.py`.
- Admin routes use HTTP Basic Auth; state-changing forms use CSRF protection. `ADMIN_PASS` and a non-placeholder `ADMIN_SECRET_KEY` are required at startup, but there is no mandatory password length or complexity rule. `/healthz` is unauthenticated for the container healthcheck. The admin map reads `/api/geo-stats` and uses `CARTO_API_KEY` in browser tile URLs; GeoLite2 supplies coordinates only when its local database is configured.

## Deployment and data safeguards

Use `.env.example`, `docker-compose.example.yml`, and `README.md` as setup references. `.env`, local Compose files, GeoLite2 databases, `data/`, `media/`, and `backups/` are ignored local state. `data/` can contain visitor IPs, headers, fingerprint data, link settings, Discord webhook URLs, and live SQLite WAL files. Do not print, commit, overwrite, prune, or delete that state while working on code. Do not copy a live `honey.db` directly: use the SQLite backup API in `backup_db.py` when a backup is explicitly needed. `HIT_RETENTION_DAYS=0` disables automatic deletion; changing it can remove historical hits.

The example Compose binds the trap to loopback for a same-host reverse proxy and the admin to `ADMIN_BIND_IP` (loopback by default). A host's Tailscale IPv4 address can be used there to keep MagicDNS access to port 4090; keep the admin endpoint off the public internet. The process listens on all interfaces *inside* the container, so preserve the host-side bind and proxy boundary. The example runs with a read-only container filesystem and mounted `/data` and `/media`. GeoLite2 is optional and its mount is commented out; stale databases generate a warning. Never use the local deployment as a test fixture or restart it merely to verify a code change.

## History to interpret carefully

Recent commits added CSRF, trusted-proxy IP handling, bounded workers, SQLite/WAL safeguards, local tests, and CI. The CARTO map fix requires a tile key. An earlier password-complexity change was intentionally reversed; follow the current startup validation and the owner's preference rather than restoring it. Earlier geo lookup implementations were removed; `geoip2_lookup.py` is current. Git history helps explain decisions, but current code and tracked examples define present behavior.
