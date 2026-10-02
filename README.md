# Honeytoken Logger

Self-hosted, Grabify-style link tracker and web honeypot. A **Trap** service captures visitor requests and rich browser fingerprints; an **Admin** dashboard lets you manage tracked links, final actions, alerts, and hit analytics.

## Features

- **Catch-all trap** — any path on your domain logs headers, proxy-validated client IP, GeoIP, and TCP fingerprint clues
- **Tracked links** — `/l/<token>` URLs or custom root paths with per-link settings
- **Client capture** — canvas, WebGL/GPU, audio, fonts, timezone, and stable visitor fingerprinting
- **Final actions** — redirect, fake error page, or media; optional **random action pools** per domain or link
- **Alerts** — filterable Discord webhook rules (immediate vs after client capture)
- **Admin dashboard** — hit log, map, link stats, nginx snippet generator, basic auth

## Quick start

```bash
cp docker-compose.example.yml docker-compose.yml
cp .env.example .env
# Edit .env — set the required secrets, CARTO key, domain, and admin bind address

mkdir -p data media
docker compose up -d --build
```

- **Trap:** `http://localhost:4040` (or your public domain behind a reverse proxy)
- **Dashboard:** `http://localhost:4090` by default (login with `ADMIN_USER` / `ADMIN_PASS`)

Keep the admin port off the public internet. For Tailscale MagicDNS, set `ADMIN_BIND_IP` to the output of `tailscale ip -4`, then use `http://your-machine-name:4090`.

## Environment variables

| Variable | Description |
|----------|-------------|
| `ADMIN_USER` | Dashboard login username (default: `admin`) |
| `ADMIN_PASS` | Dashboard login password (**required**; no length or complexity policy is imposed) |
| `ADMIN_SECRET_KEY` | Random secret used to sign admin CSRF tokens (**required**) |
| `CARTO_API_KEY` | CARTO Basemaps key used by the dashboard map (**required**) |
| `ADMIN_BIND_IP` | Host address that publishes port 4090 (default: `127.0.0.1`; use the host's Tailscale IPv4 address for MagicDNS) |
| `TRAP_THREADS` / `ADMIN_THREADS` | Waitress worker threads (defaults: 8 / 4) |
| `TRAP_CONNECTION_LIMIT` / `ADMIN_CONNECTION_LIMIT` | Max concurrent connections per service (defaults: 64 / 32) |
| `ROOT_DOMAIN` | Primary domain for link previews (default: `example.com`) |
| `DISCORD_WEBHOOK_URL` | Optional legacy Discord webhook for immediate hits |
| `TELEGRAM_TOKEN` | Optional Telegram bot token |
| `TELEGRAM_CHAT_ID` | Optional Telegram chat ID |
| `DATA_DIR` | Persistence directory inside container (default: `/data`) |
| `TRAP_PORT` / `ADMIN_PORT` | Ports (defaults: 4040, 4090) |
| `TRAP_UPSTREAM` | Host:port for generated nginx config (default: `honey:4040`) |
| `GEOIP2_DB` | Path to GeoLite2-City.mmdb for lat/lng and city (optional) |
| `DATABASE_URL` | SQLAlchemy URL (default: `sqlite:///$DATA_DIR/honey.db`) |
| `MEDIA_DIR` | Folder for local media files (default: `/media`) |
| `HIT_RETENTION_DAYS` | Automatically delete older hits; `0` keeps them indefinitely |
| `BACKGROUND_WORKERS` / `BACKGROUND_QUEUE_CAPACITY` | Bounds asynchronous notification work (defaults: 4 / 128) |

## GeoLite2 (optional)

MaxMind’s GeoLite2 database is **not included** in this repository. Create a free account at [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data), download `GeoLite2-City.mmdb`, place it in the project root, and uncomment the volume mount in `docker-compose.yml`:

```yaml
- ./GeoLite2-City.mmdb:/data/GeoLite2-City.mmdb:ro
```

Honey logs a warning when the database is over 45 days old. MaxMind recommends automating binary database updates with [`geoipupdate`](https://dev.maxmind.com/geoip/updating-databases/). Store its account ID and license key outside this repository and schedule it at least weekly.

## Media folder

When using **Media** as a final action, drop files (`.mp4`, `.webm`, `.gif`, `.jpg`, etc.) into `./media` on the host. The compose file mounts it at `/media`. Select files in **Admin → Settings**; paths are stored as `/media/...` and served by the trap.

## Database and geo API

Hits are stored in SQLite (default: `DATA_DIR/honey.db`) with latitude, longitude, and city when GeoIP is configured.

**GET /api/geo-stats** (admin auth): aggregated coordinates for the dashboard map.

- Default: JSON `[{lat, lng, weight}, ...]`
- `?format=geojson` — GeoJSON FeatureCollection
- `?limit=5000` (max 20000), `?round=3` (grouping precision, 1–6)

## Reverse proxy (recommended)

Serve the trap on your domain through a trusted local proxy. Honey intentionally ignores `X-Forwarded-For`; the generated nginx configuration uses a proxy-controlled `X-Real-IP` instead. Example Caddy snippet:

```caddy
example.com {
    reverse_proxy localhost:4040
}
```

The admin UI includes an nginx/NPM custom config snippet (set `TRAP_UPSTREAM` to match your backend).

## Local overrides (not committed)

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Your deployment (copy from `docker-compose.example.yml`) |
| `.env` | Secrets and `ROOT_DOMAIN` |
| `GeoLite2-City.mmdb` | MaxMind database |
| `media/` | Your media files |
| `./data/` | SQLite DB (`honey.db`) and `config.json` (dashboard timezone, Discord rules, etc.) |
| `backups/` | Local SQLite backups created by `backup_db.py` |

## Data location

Runtime data is stored in `./data/` on the host (mounted to `/data` in the container). This makes backups and inspection straightforward — you can copy or snapshot the folder directly.

Do not copy `honey.db` directly while the service is writing to it. Create a consistent online backup, including WAL contents, with:

```bash
python backup_db.py
sqlite3 -readonly backups/honey-YYYYMMDDTHHMMSSZ.db 'PRAGMA quick_check'
```

Backups are written to the ignored `backups/` directory and should also be copied to storage outside this host. Configure `HIT_RETENTION_DAYS` only after deciding how long the logs need to remain useful.

## Development checks

```bash
python -m pip install -r requirements.lock -r requirements-dev.txt
ruff check .
pytest
bandit -r . -x ./.git,./data,./media,./tests -q
pip-audit -r requirements.lock
docker compose -f docker-compose.example.yml config --quiet
```

## Legal notice

This tool logs network and browser information about visitors who request your URLs. You are responsible for using it lawfully and with appropriate notice or consent in your jurisdiction. Do not use it to harass, stalk, or deceive people.
