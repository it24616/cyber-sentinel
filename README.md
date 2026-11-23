# Cyber Sentinel

Explainable cybersecurity event triage, risk assessment, and alert management.

## 2. Project Title

**Cyber Sentinel: Intelligent Cybersecurity Monitoring and Threat Detection System**

## 4. Project Overview

Cyber Sentinel is a web-based security event triage prototype. Users can submit event text or ingest events from an integration, review explainable rule matches, and manage resulting alerts from a dashboard.

The project contains a static HTML/CSS/JavaScript frontend and a Python Flask API. Data is stored in SQLite for local development or PostgreSQL for hosted deployments. Detection is performed by a transparent rule engine; it is not machine learning and does not monitor a network by itself.

## 5. Objectives

- Accept and assess security events from the dashboard or an API integration.
- Make detection results understandable by showing matched indicators, evidence, and remediation guidance.
- Provide account-scoped event history, alert triage, and activity records.
- Offer a small, documented API that can be used by other services.
- Support local development and deployment with managed PostgreSQL.

## 6. Key Features

- **Explainable detection:** Ten rules cover SQL injection, cross-site scripting, command injection, JNDI/Log4Shell, XXE, path traversal, sensitive-file probes, SSRF indicators, brute-force indicators, and scanner signatures.
- **Risk scoring:** Findings contribute weighted scores capped at 100 and are assigned `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` severity.
- **Event analysis:** Submit a URL, request, log, or general event and review matched rules, evidence snippets, and recommendations.
- **Website checks:** Passively check a public website's HTTPS/TLS, security headers, cookies, and information leaks. Private, local, and reserved addresses are blocked by default.
- **Security dashboard:** View current posture, alert totals, recent activity, and seven-day trends.
- **Live detection:** Review recent events, top indicators and sources, and rolling monitoring summaries.
- **Alert workflow:** Acknowledge, progress, resolve, mark false positive, archive, and review alert history. A resolution note is required for terminal statuses.
- **API integrations:** Create account-scoped bearer keys and submit batches of up to 100 events. Event IDs can be used for duplicate detection.
- **Authentication and access control:** Argon2id password hashing, signed sessions, CSRF checks, and owner-scoped records.
- **Deployment choices:** Run locally, with Docker Compose, on Render, or on Vercel.

## 7. Technologies Used

| Area | Technologies |
|---|---|
| Backend | Python 3.13 recommended, Flask, Flask-CORS |
| Authentication | Argon2id via `argon2-cffi`, signed Flask sessions |
| Database | SQLite locally; PostgreSQL with Psycopg for hosted deployments |
| Frontend | HTML, CSS, vanilla JavaScript |
| Web serving | Flask development server, Gunicorn, Nginx |
| Rate-limit storage | In-memory by default; Redis supported for shared/multi-worker deployments |
| Deployment | Docker Compose, Render Blueprint, Vercel |
| Tests | Python `unittest` |

The frontend is static and does not require an npm build step.

## 8. System Architecture

```mermaid
flowchart TD
    Browser[Browser UI<br/>HTML, CSS, JavaScript]
    Edge[Flask routes / Nginx reverse proxy]
    Auth[Authentication, CSRF, validation]
    Rules[Explainable detection engine]
    API[Session API and integration API]
    DB[(SQLite or PostgreSQL)]
    Redis[(Optional Redis<br/>shared rate limits)]

    Browser -->|HTTPS or local HTTP| Edge
    Edge --> Auth
    Auth --> API
    API --> Rules
    API --> DB
    Edge -. optional shared rate-limit backend .-> Redis
```

In the standard local setup, Flask serves both the frontend and API on one origin. Docker Compose serves the frontend with Nginx and forwards `/api/` requests to Flask. Vercel uses the repository-root `app.py` entry point to serve the frontend and API from the same origin.

## 9. Project Folder Structure

```text
.
├── backend/
│   ├── app.py                 Flask application entry point
│   ├── config.py              Environment-based settings and validation
│   ├── database.py            SQLite/PostgreSQL persistence and queries
│   ├── detection.py           Explainable rule engine
│   ├── site_check.py          Passive public-website checks
│   ├── pdf_report.py          Website-check PDF report
│   ├── security.py            Sessions, CSRF, API keys, and headers
│   ├── validation.py          Request and event validation
│   ├── routes/                Auth, health, detection, events, alerts, integrations
│   └── tests/                 API workflow and dashboard tests
├── frontend/
│   ├── index.html             Landing page
│   ├── login.html
│   ├── register.html
│   ├── app.html               Authenticated application shell
│   ├── pages/                 Dashboard, alerts, analysis, integrations, live detection
│   └── assets/                CSS, JavaScript, and images
├── docs/
│   └── screenshots/           README screenshots
├── app.py                     Vercel entry point
├── compose.yaml               API, Nginx, and Redis services
├── Dockerfile                 Flask/Gunicorn image
├── Dockerfile.frontend        Nginx frontend image
├── render.yaml                Render Blueprint
├── Procfile                   Gunicorn process definition
├── requirements.txt           Python dependencies
└── README.md
```

## 10. Installation Guide

### Prerequisites

- Git
- Python 3.13 (recommended; Docker and Render configuration use Python 3.13)
- Docker Desktop only if using Docker Compose

### Windows PowerShell

1. Clone the repository and enter the project directory:

   ```powershell
   git clone https://github.com/it24616/cyber-sentinel.git
   Set-Location cyber-sentinel
   ```

2. Create a virtual environment:

   ```powershell
   py -3.13 -m venv .venv
   ```

3. Install Python dependencies:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

4. Create a local environment file only if one does not already exist:

   ```powershell
   if (-not (Test-Path .env)) { Copy-Item .env.example .env }
   ```

5. Review `.env` and use development-only values for local work. Never commit `.env`.

### macOS / Linux

1. Clone the repository:

   ```bash
   git clone https://github.com/it24616/cyber-sentinel.git
   cd cyber-sentinel
   ```

2. Create and activate a virtual environment:

   ```bash
   python3.13 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies and create `.env` if needed:

   ```bash
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   test -f .env || cp .env.example .env
   ```

4. Review `.env` before starting the application.

## 11. Environment Setup

The application loads local settings from `.env`. Environment variables supplied by the hosting platform take precedence over values in the file.

| Variable | Purpose | Local default / guidance |
|---|---|---|
| `APP_ENV` | Runtime environment | `development`; use `production` when hosted |
| `SECRET_KEY` | Signs session cookies | Use a unique random value of at least 32 characters in production |
| `HOST` | API bind address | `127.0.0.1` locally; use `0.0.0.0` in a container |
| `PORT` | API port | `5050` locally; hosts may provide their own `PORT` |
| `FLASK_DEBUG` | Enables development debugging | `1` locally; keep `0` in production |
| `CORS_ORIGINS` | Allowed browser origins | Exact comma-separated origins; never use `*` in production |
| `COOKIE_SECURE` | HTTPS-only session cookies | Defaults to `1` in production |
| `ALLOW_SIGNUP` | Enables public registration | Defaults to `1` in development and `0` in production |
| `DATABASE_URL` | Selects PostgreSQL instead of SQLite | Optional locally; required on Vercel |
| `CYBER_SENTINEL_DB` | Custom SQLite database file | Optional; defaults to `backend/security.db` |
| `RATELIMIT_STORAGE_URI` | Flask-Limiter storage | Defaults to `memory://`; use shared Redis for multiple workers |
| `URL_SCAN_ALLOW_PRIVATE` | Allows checks of private/local URLs | Keep `0` unless a controlled local test specifically requires it |

Registration is limited to 50 total accounts and 10 requests per minute per client IP. Set `ALLOW_SIGNUP=0` to disable registration.

Generate a production secret locally, then store it directly in the hosting provider's secret settings:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Do not paste production secrets into source files, screenshots, issue trackers, or chat.

## 12. Database Configuration

### SQLite (default for local development)

If `DATABASE_URL` is unset, the application uses SQLite at `backend/security.db`. Set `CYBER_SENTINEL_DB` to choose another file path. SQLite is suitable for local development or a single-host Compose deployment with persistent storage.

### PostgreSQL (recommended for hosted deployments)

Set `DATABASE_URL` to a PostgreSQL connection string. The application uses Psycopg and initializes the required tables and indexes when the Flask application starts. For Neon, use the pooled connection URL for normal application traffic. Keep database credentials in environment variables, not in Git.

Vercel's filesystem is temporary, so Vercel deployments must use an external PostgreSQL database. Do not rely on SQLite on Vercel for persistent user data.

The application does not currently have a versioned migration framework. Schema initialization creates missing tables and indexes; review schema changes and back up production data before deploying database changes. `TEST_DATABASE_URL` is intended only for testing against a separate, empty PostgreSQL database.

## 13. How to Run

### Run the Flask app locally

From the repository root, start the API and frontend:

**Windows PowerShell**

```powershell
.\.venv\Scripts\python.exe -m backend.app
```

**macOS / Linux** (with the virtual environment activated)

```bash
python -m backend.app
```

Open `http://127.0.0.1:5050/`. Useful checks:

- Readiness (includes a database check): `http://127.0.0.1:5050/api/health`
- Liveness (does not query the database): `http://127.0.0.1:5050/api/health/live`

Stop the development server with `Ctrl+C`.

### Optional: serve the frontend separately

To run the static frontend on port 5500 while the API runs on port 5050, open another terminal:

```powershell
py -m http.server 5500 --directory frontend
```

Then open `http://127.0.0.1:5500/`. The sample CORS configuration allows both localhost origins.

### Run with Docker Compose

1. Create `.env.compose` without overwriting an existing file:

   ```powershell
   if (-not (Test-Path .env.compose)) { Copy-Item .env.compose.example .env.compose }
   ```

2. Replace the placeholder `SECRET_KEY` in `.env.compose` with a fresh random secret.
3. Start the stack:

   ```powershell
   docker compose --env-file .env.compose up --build
   ```

4. Open `http://127.0.0.1:8080/`. The stack uses Nginx, Flask/Gunicorn, Redis for shared rate limits, and a persistent SQLite volume.
5. Stop the stack with `Ctrl+C`, or run `docker compose --env-file .env.compose down`.

### Deploy to Vercel

1. Import the GitHub repository `it24616/cyber-sentinel` into Vercel and set the project root to the repository root.
2. Add these variables to the **Production** environment before deploying:
   - `APP_ENV=production`
   - `SECRET_KEY` (unique random value, at least 32 characters)
   - `CORS_ORIGINS` (the exact HTTPS site origin)
   - `COOKIE_SECURE=1`
   - `ALLOW_SIGNUP=1` to allow account registration, or `0` to disable it
   - `DATABASE_URL` (pooled PostgreSQL URL)
3. Deploy the `main` branch.
4. Verify `/api/health` on the deployed site; it should report `ready` and `database: ok`.

If the health check returns an error, confirm the variables were added to the correct Vercel project and the **Production** environment, then redeploy.

## 14. Screenshots

Screenshots below were captured from the local application with blank forms and contain no user data.

### Landing page

![Cyber Sentinel landing page](docs/screenshots/landing.png)

### Sign-in page

![Cyber Sentinel sign-in page](docs/screenshots/login.png)

### Registration page

![Cyber Sentinel registration page](docs/screenshots/register.png)

## 15. API Documentation

The API returns JSON. Use the same origin as the frontend in production. For local work, the base URL is `http://127.0.0.1:5050`.

### Authentication

- Registration and login are public endpoints.
- Successful login creates an HTTP session cookie and returns a `csrf_token`.
- Authenticated reads require the session cookie.
- Authenticated state-changing requests require both the session cookie and `X-CSRF-Token`.
- Event batch ingestion uses an API key in `Authorization: Bearer <key>` instead of a browser session.

### Endpoints

| Method and path | Access | Description |
|---|---|---|
| `GET /api/health/live` | Public | Liveness check |
| `GET /api/health` | Public | Readiness check, including database availability |
| `POST /api/auth/register` | Public | Create an account; `full_name`, email, password (12-128 chars), optional phone |
| `POST /api/auth/login` | Public | Sign in; returns user details and a CSRF token |
| `GET /api/auth/me` | Session | Return the current user and CSRF token |
| `POST /api/auth/logout` | Session + CSRF | Sign out |
| `POST /api/assess-risk` | Session + CSRF | Assess and store a manually submitted event |
| `POST /api/site-check` | Session + CSRF | Run passive checks against a public website |
| `POST /api/site-check/report` | Session + CSRF | Create a PDF from a completed site-check report |
| `GET /api/detection/rules` | Session | Get the rule catalog and remediation descriptions |
| `GET /api/detection/overview` | Session | Get rolling detection metrics and recent events |
| `GET /api/events` | Session | Get paginated event history |
| `POST /api/events/ingest` | API key | Validate, assess, and ingest a batch of 1-100 events |
| `GET /api/integrations/keys` | Session | List the account's API keys (never returns full key values) |
| `POST /api/integrations/keys` | Session + CSRF | Create a key; the raw key is returned only once |
| `DELETE /api/integrations/keys/<key_id>` | Session + CSRF | Revoke an API key |
| `GET /api/alerts` | Session | List and filter alerts |
| `PATCH /api/alerts/<alert_id>` | Session + CSRF | Update status/read state |
| `DELETE /api/alerts/<alert_id>` | Session + CSRF | Archive an alert; its history is retained |
| `GET /api/alerts/<alert_id>/activity` | Session | Get an alert's activity history |
| `GET /api/stats` | Session | Get dashboard counts and risk summaries |
| `GET /api/activity` | Session | Get recent account activity |

### Manual risk assessment

`event_type` is optional and may be `general`, `url`, `request`, or `log`. `event_data` must contain 1-10,000 characters.

```http
POST /api/assess-risk
Content-Type: application/json
X-CSRF-Token: <csrf-token-from-login>
Cookie: session=<session-cookie>

{
  "event_type": "log",
  "event_data": "Failed password for demo-user from 203.0.113.10"
}
```

The response contains the assessment under `result`, including `risk_score`, `risk_level`, `detected_threats`, `matched_rules`, `findings`, and `recommendation`. Risk levels are `LOW` (below 30), `MEDIUM` (30-59), `HIGH` (60-79), and `CRITICAL` (80-100).

### Batch event ingestion

Create an API key from the Integrations page or `POST /api/integrations/keys`, then send events to `/api/events/ingest`. Each event accepts:

- `event_data` (or `message`): text, object, or array; maximum 10,000 characters after normalization
- `source`: optional, up to 80 characters
- `event_type`: optional, 1-100 characters
- `external_id`: optional, non-empty and up to 200 characters; used for per-account/source deduplication
- `observed_at`: optional ISO 8601 timestamp

```bash
curl -X POST "http://127.0.0.1:5050/api/events/ingest" \
  -H "Authorization: Bearer cs_live_REPLACE_WITH_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "source": "web-01",
        "event_type": "authentication",
        "external_id": "demo-event-001",
        "observed_at": "2026-01-15T10:30:00Z",
        "event_data": "Failed password for demo-user from 203.0.113.10"
      }
    ]
  }'
```

The endpoint returns HTTP `202` with accepted/duplicate counts and per-event assessment results. Replace the example API key; never put a real key in source control.

### Common query parameters

- Event history: `page`, `per_page` (maximum 100), `risk_level`, `source`
- Alerts: `page`, `per_page`, `status`, `risk_level`, `is_read`
- Detection overview: `since_id`, `limit` (maximum 50)
- Activity feed: `limit` (maximum 50)

Invalid input returns HTTP `400`. Other common statuses include `401` (missing authentication), `403` (CSRF/signup restriction), `404` (not found), `409` (conflict), `429` (rate limit), and `500` (server error). Error responses use `{"success": false, "error": "..."}`.

## 16. Testing

Run the backend test suite from the repository root:

```powershell
python -m unittest discover -s backend/tests -t .
```

Tests use a temporary SQLite database by default and cover registration/login, permissions, event ingestion, alert workflows, validation, and dashboard data. To run against PostgreSQL, set `TEST_DATABASE_URL` to a separate empty test database before running the suite. Never point tests at production data.

## 17. Security Considerations

- Use unique production secrets and store them in the hosting provider's environment settings.
- Use HTTPS in production and set `COOKIE_SECURE=1`.
- Set `CORS_ORIGINS` to exact trusted origins; wildcard CORS is rejected in production.
- Passwords are hashed with Argon2id. Sessions are signed and expire after eight hours.
- State-changing session requests require CSRF tokens. Records are scoped to the owning account.
- API keys are stored as hashes; the raw value is shown only when created. Revoke unused keys.
- API requests have a default rate limit, with tighter limits on authentication and assessment routes; public registration also has a 50-account cap.
- Website checks block private, local, and reserved IP addresses by default and validate every redirect.
- Set `RATELIMIT_STORAGE_URI` to a shared store such as Redis when running multiple workers.
- Back up production data and test restores. The default local SQLite database is not a production backup strategy.

## 18. Future Improvements

- Add versioned database migrations and automated backup/restore workflows.
- Add MFA, password reset, and configurable account lifecycle management.
- Add more event sources, notifications, and response integrations.
- Improve rule tuning and provide organization-specific rule configuration.
- Add production observability, load testing, and deployment smoke tests.
- Evaluate an ML-assisted prioritization layer while keeping rule evidence explainable.

## 19. Limitations

- Detection is a heuristic rule-based triage aid, not proof of compromise.
- The application is not a packet sensor, endpoint agent, WAF, or full SIEM.
- Website checks are passive and limited to a single public HTTP(S) request and redirects; they do not perform penetration testing.
- The current account limit is 50. Registration can be disabled with `ALLOW_SIGNUP=0`.
- Schema initialization is not a substitute for a versioned migration system.
- In-memory rate-limit storage is not shared across multiple processes; configure Redis for multi-worker deployments.
- SQLite is not appropriate for multi-instance hosted deployments.

## 20. Contribution

1. Fork the repository and create a feature branch.
2. Keep changes focused and add tests for behavior changes.
3. Run `python -m unittest discover -s backend/tests -t .`.
4. Do not commit `.env` files, API keys, database dumps, or user data.
5. Open a pull request describing the change, validation performed, and any deployment/configuration impact.

## 22. Author & Contact

**Project:** Cyber Sentinel

**Repository:** [it24616/cyber-sentinel](https://github.com/it24616/cyber-sentinel)

**Contact:** Open a GitHub issue in the repository for questions, bugs, or feature requests.
