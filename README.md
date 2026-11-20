# Cyber Sentinel

Cyber Sentinel is a local cybersecurity event triage prototype. It includes a static multi-page dashboard and a Flask API that assesses submitted event text using transparent rules, stores findings in SQLite, and exposes alert management and monitoring summaries.

## Features

- **Ten explainable detection rules**: SQL injection, XSS, command injection, JNDI/Log4Shell, XXE, path traversal, sensitive-file probes, SSRF, brute force and scanner activity. Each is mapped to MITRE ATT&CK and CWE and comes with remediation advice. Input is also checked after URL and HTML decoding.
- **Analyze Event**: risk score (0–100), severity, matched text highlighted in context, and what to do next.
- **Live Detection**: polling event feed, top indicators and sources, hourly detections and severity mix.
- **Security Alerts**: triage states (`Open`, `Acknowledged`, `In Progress`, `Resolved`, `False Positive`), required resolution notes, filters, pagination, read state and a per-alert history.
- **Dashboard**: system risk level (highest open severity), 7-day trend, recent alerts, account activity feed, and onboarding for new accounts.
- **Integrations**: per-account API keys (hashed at rest, shown once, revocable) for batch ingestion with `external_id` deduplication, plus copy-ready curl, Python and JavaScript examples.
- **Security**: Argon2id passwords, signed 8-hour sessions, CSRF checks, per-account data isolation, request size limits, input validation, security headers, configurable CORS and rate limits.

Detection is rule-based triage. It is not machine learning, a network sensor, a WAF, or a production SIEM. A match is an indicator for investigation, not proof of an attack. The API requires a signed-in account for assessment and alert access. The Compose stack targets a single host with SQLite; put it behind TLS and a trusted reverse proxy before public use, and configure managed secrets and tested backups.

## Run locally

From the project root, create a virtual environment and install dependencies:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python backend/app.py
```

In a second terminal, serve the frontend on port 5500 (the API expects this origin in development):

```sh
python3 -m http.server 5500 --directory frontend
```

Open `http://127.0.0.1:5500`, create an account, and sign in. The API health endpoint is `http://127.0.0.1:5050/api/health`. Local development uses port 5050 because macOS AirPlay Receiver occupies port 5000; if you change `PORT`, run `localStorage.cyberSentinelApiPort = "<port>"` in the browser console (the container stack is unaffected). SQLite defaults to `backend/security.db`; set `CYBER_SENTINEL_DB` to move it.

Set `CORS_ORIGINS` in `.env` to the exact origins used by the frontend. Use a long random `SECRET_KEY` in production and set `APP_ENV=production`; production mode requires an explicit secret and rejects wildcard CORS. Set `ALLOW_SIGNUP=0` after creating accounts to close public registration. `Procfile` provides a Gunicorn process entry point for hosts that provide `PORT`. For multiple API workers, configure `RATELIMIT_STORAGE_URI` to a shared store such as Redis; the default in-memory limiter is intended for a single local process.

Run the tests from the project root:

```sh
python -m unittest discover -s backend/tests -t .
```

## Project structure

```
backend/                Flask API (Python package)
  app.py                Entry point: `python backend/app.py` or `gunicorn backend.app:app`
  factory.py            create_app(): config, CORS, rate limiter, blueprints
  config.py             Environment settings and production checks
  security.py           Session auth, CSRF, API-key principal, headers, JSON errors
  validation.py         Request parsing (pagination, event normalization)
  constants.py          Risk levels, alert statuses and allowed transitions
  extensions.py         Rate limiter and Argon2 password hasher
  detection.py          Rule engine (RULES, assess_risk, rule_catalog)
  database.py           SQLite schema and every query (always scoped by owner_id)
  routes/               One blueprint per area: auth, health, detection, events, integrations, alerts
  tests/                unittest suite; support.py points tests at a temporary database
frontend/               Static site (served by Nginx in containers)
  index.html            Landing page
  login.html, register.html
  app.html              App shell: sidebar, top bar (notifications, account) and the page frame
  pages/                Pages shown inside the shell: dashboard, live-detection, alerts, analyze, integrations
  assets/css/           base.css (design tokens), components.css (shared UI), shell.css, auth.css, pages/*.css
  assets/js/core/       api.js (API client, CSRF), ui.js (modals, toasts, helpers), frame.js, charts.js
  assets/js/            shell.js (router, notifications), pages/*.js, auth/*.js
```

Inside the app, routes live in the URL hash (`app.html#/alerts?status=Open`), so refresh and browser back/forward work. Pages opened directly (for example `pages/alerts.html`) redirect into the shell.

## Container deployment

The Compose stack runs the API with Gunicorn, serves the UI through Nginx, stores SQLite data in a named volume, and uses Redis for shared rate limiting. The web port binds to loopback by default; put a TLS reverse proxy in front of it before exposing the service publicly.

```sh
cp .env.compose.example .env.compose
python3 -c 'import secrets; print(secrets.token_hex(32))'
# Put the generated value in SECRET_KEY in .env.compose.
docker compose --env-file .env.compose up --build -d
```

Open `http://127.0.0.1:8080` and create an account. Registration automatically stops after 10 total accounts; set `ALLOW_SIGNUP=0` in `.env.compose` and restart the API to close it earlier. For a TLS deployment, set `COOKIE_SECURE=1` and set `CORS_ORIGINS` to the exact HTTPS origin. Back up the SQLite volume using SQLite's online backup API; Redis contains only rate-limit counters and can be ephemeral. Run one API container per SQLite volume.

## Render deployment (free)

`render.yaml` is a Render Blueprint for a free web service that serves both the API and the frontend. Data lives in PostgreSQL (for example free Neon) because the free instance's disk is reset on every deploy.

1. Render dashboard → **New → Blueprint** → choose this repository.
2. When asked, paste the Neon **pooled** connection string as `DATABASE_URL`. `SECRET_KEY` is generated automatically, and `CORS_ORIGINS` defaults to the service URL (`RENDER_EXTERNAL_URL`).
3. Open `https://<service>.onrender.com` and register. Registration automatically stops after 10 total accounts; set `ALLOW_SIGNUP=0` in the service's Environment tab to close it earlier.

Free services sleep after a period without traffic; the first request afterwards takes up to about a minute. The health check uses `/api/health/live`, which does not touch the database, so Neon's free compute can scale to zero.

## Vercel deployment

Deploy the repository root (`.`), not only the `frontend` folder. The root `app.py` exposes the Flask app to Vercel, and Flask serves frontend files from `frontend/` so `/api/*` requests and session cookies use the same origin. In Vercel Project Settings, set **Root Directory** to the repository root.

Set these Vercel environment variables before deploying:

- `APP_ENV=production`
- `SECRET_KEY` to a unique random value of at least 32 characters
- `CORS_ORIGINS` to the exact `https://` origin of the deployed app
- `ALLOW_SIGNUP=1` to allow signups; registration stops automatically after 10 total accounts. Set it to `0` to close registration earlier.
- `COOKIE_SECURE=1`
- `DATABASE_URL` to a PostgreSQL connection string (see below)

Vercel's disk is temporary and not shared between function instances, so accounts and alerts must live in an external PostgreSQL database. Without `DATABASE_URL` the app falls back to SQLite in `/tmp`, which loses data on cold starts and makes sign-in fail at random. Free options that need no card:

- **Neon** (recommended): create a project at neon.tech, copy the connection string (it ends in `?sslmode=require`), and set it as `DATABASE_URL`. Idle databases wake automatically on the next request.
- **Supabase**: use the **pooler** connection string from Project Settings → Database (the direct host is IPv6-only). Free projects are paused after a week without activity and must be restored from the dashboard.

Tables are created automatically on the first request. To run the test suite against PostgreSQL, point `TEST_DATABASE_URL` at an empty database: `TEST_DATABASE_URL=postgresql://… python -m unittest discover -s backend/tests -t .`

Vercel Hobby (free) only builds commits whose author is the Vercel account owner when the GitHub repository is private. If a deployment shows "Deployment Blocked", commit with the Git email of the GitHub account connected to Vercel (`git config user.email …`), or make the repository public.

Create a consistent SQLite backup without stopping the API:

```sh
mkdir -p backups
backup_name="security-$(date -u +%Y%m%dT%H%M%SZ).db"
docker compose --env-file .env.compose exec -T api python -c 'import sqlite3,sys; src=sqlite3.connect("/data/security.db"); dst=sqlite3.connect(sys.argv[1]); src.backup(dst); dst.close(); src.close()' "/tmp/$backup_name"
docker compose --env-file .env.compose cp "api:/tmp/$backup_name" "backups/$backup_name"
docker compose --env-file .env.compose exec -T api rm -f "/tmp/$backup_name"
```

## API overview

- `GET /api/health` – readiness status including database availability; `GET /api/health/live` – process liveness.
- `POST /api/auth/register` and `POST /api/auth/login` – account creation and sign-in.
- `GET /api/auth/me` and `POST /api/auth/logout` – current session and sign-out.
- `POST /api/assess-risk` – JSON body: `{\"event_data\": \"...\"}` plus optional `event_type` (`general`, `url`, `request`, `log`). The result includes per-rule `findings` with evidence snippets, MITRE ATT&CK technique, CWE, and remediation.
- `GET /api/detection/rules` – the active rule catalog (engine in `backend/detection.py`).
- `GET /api/detection/overview?since_id=0&limit=25` – rolling 24-hour detection metrics, top indicators and sources, and events newer than `since_id`; used by the live Threat Detection page.
- `POST /api/events/ingest` – ingest a batch with `Authorization: Bearer cs_live_…`; each event can include `event_type`, `source`, `external_id`, `observed_at`, and `event_data`.
- `GET /api/events?page=1&per_page=50` – authenticated recent event history.
- `GET/POST /api/integrations/keys` and `DELETE /api/integrations/keys/<id>` – manage ingestion keys; the raw key is returned only once at creation.
- `GET /api/alerts?page=1&per_page=50&status=Open&risk_level=HIGH&is_read=false` – filtered, paginated alerts.
- `GET /api/stats` – totals, severity counts, today count, 24 hourly buckets, 7 daily buckets, open alerts by severity, `posture` (highest severity among open alerts, or `CLEAR`), and `last_event_at`.
- `GET /api/activity?limit=10` – newest alert activity across the account (created, status changes, read, archived) for the dashboard feed.
- `PATCH /api/alerts/<id>` – update alert status and/or boolean `is_read`.
- Alert statuses are `Open`, `Acknowledged`, `In Progress`, `Resolved`, and `False Positive`; terminal outcomes require a resolution note. `GET /api/alerts/<id>/activity` returns the account-scoped audit trail.
- `DELETE /api/alerts/<id>` – archive an alert from the active queue while preserving its audit history.
# Cyber_Sentinel
