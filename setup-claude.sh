#!/bin/bash

# ═══════════════════════════════════════════════════════
# Claude AI Development System Setup
# Usage: ./setup-claude.sh
# ═══════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ───────────────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────────────

print_step() { echo -e "\n${BLUE}═══ $1 ═══${NC}"; }
print_ok()   { echo -e "${GREEN}✅ $1${NC}"; }
print_warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${CYAN}ℹ️  $1${NC}"; }

make_file() {
  mkdir -p "$(dirname "$1")"
  if [ -f "$1" ]; then
    print_warn "Skipped (already exists): $1"
    cat > /dev/null  # consume stdin so heredoc doesn't hang
  else
    cat > "$1"
    print_ok "Created: $1"
  fi
}

# ───────────────────────────────────────────────────────
# SAFETY CHECK
# ───────────────────────────────────────────────────────

print_step "Safety Check"

SAFE_MODE=false
if [ -f "CLAUDE.md" ] || [ -d ".claude" ]; then
  echo ""
  print_warn "Existing Claude setup detected!"
  print_info "Running in SAFE MODE — existing files will NOT be touched"
  print_info "Only missing files and folders will be created"
  echo ""
  SAFE_MODE=true
else
  print_info "Fresh project — creating full setup"
fi

# ───────────────────────────────────────────────────────
# DETECT PROJECT
# ───────────────────────────────────────────────────────

print_step "Detecting Project"

PROJECT_NAME="Cyber Sentinel"
TODAY=$(date +%Y-%m-%d)

if [ ! -f "backend/app.py" ] || [ ! -f "backend/detection.py" ]; then
  echo -e "${RED}❌ Run this script from the Cyber Sentinel project root (backend/app.py not found).${NC}"
  exit 1
fi

# Stack is fixed for this project; report what is actually present.
STACK="Python/Flask API + SQLite"
grep -qi "gunicorn" requirements.txt 2>/dev/null && STACK="$STACK, Gunicorn"
[ -f "compose.yaml" ] && STACK="$STACK, Docker Compose (Nginx + Redis)"
STACK="$STACK, static HTML/CSS/JS frontend"

# Pick a Python interpreter: project venv first, then system python3.
if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
else
  PYTHON="python3"
fi

print_info "Project: $PROJECT_NAME"
print_info "Stack:   $STACK"
print_info "Backend: backend/ (app.py, database.py, detection.py, tests/)"
print_info "Frontend: frontend/ (app.html shell, pages/, assets/)"
print_info "Python:  $PYTHON"

# ───────────────────────────────────────────────────────
# STEP 1: CREATE FOLDER STRUCTURE
# ───────────────────────────────────────────────────────

print_step "Creating Folder Structure"

mkdir -p .claude/memory
mkdir -p .claude/modules
mkdir -p .claude/tasks/todo
mkdir -p .claude/tasks/inprogress
mkdir -p .claude/tasks/done
mkdir -p .claude/tasks/plans
mkdir -p .claude/tasks/logs
mkdir -p .claude/tasks/eod
mkdir -p .claude/commands/system
mkdir -p .claude/commands/custom

touch .claude/tasks/eod/.gitkeep

print_ok "Folder structure created"

# ───────────────────────────────────────────────────────
# STEP 2: settings.json
# ───────────────────────────────────────────────────────

print_step "Creating Settings Files"

# Shared team settings. Rule syntax: "./path" is relative to the project root.
# Edit rules cover every file-editing tool (Edit and Write).
make_file ".claude/settings.json" << 'EOF'
{
  "permissions": {
    "allow": [
      "Edit(./backend/**)",
      "Edit(./frontend/**)",
      "Edit(./README.md)",
      "Edit(./CLAUDE.md)",
      "Edit(./.claude/tasks/**)",
      "Edit(./.claude/memory/**)",
      "Edit(./.claude/modules/**)",
      "Edit(./.claude/commands/**)",
      "Bash(.venv/bin/python -m unittest:*)",
      "Bash(.venv/bin/python -m backend.app:*)",
      "Bash(python3 -m unittest:*)",
      "Bash(python -m unittest:*)",
      "Bash(git status:*)",
      "Bash(git diff:*)",
      "Bash(git log:*)",
      "Bash(docker compose config:*)"
    ],
    "deny": [
      "Read(./.env)",
      "Read(./.env.compose)",
      "Edit(./.env)",
      "Edit(./.env.compose)",
      "Edit(./backend/security.db)",
      "Read(~/.ssh/**)",
      "Edit(~/**)",
      "Edit(../**)"
    ]
  }
}
EOF

# Personal Claude Code settings (valid settings keys only). Gitignored.
make_file ".claude/settings.local.json" << 'EOF'
{
  "permissions": {
    "allow": []
  }
}
EOF

# Developer name used by /r-add-task, /r-pickup, /r-done. Gitignored.
GIT_NAME=$(git config user.name 2>/dev/null || true)
echo "${GIT_NAME}" | make_file ".claude/developer.local"
[ -z "$GIT_NAME" ] && print_warn "git user.name not set — put your name in .claude/developer.local"

# ───────────────────────────────────────────────────────
# STEP 3: CLAUDE.md
# ───────────────────────────────────────────────────────

print_step "Creating CLAUDE.md"

make_file "CLAUDE.md" << 'EOF'
# CLAUDE.md — Cyber Sentinel

Cyber Sentinel is a self-hosted security event triage prototype. A Flask API
scores event text against transparent regex rules, stores events and alerts in
SQLite, and serves alert triage and monitoring data to a static frontend.
It is rule-based triage — not ML, not a WAF, not a SIEM.

## Project Structure
- `backend/` — Flask API package (app factory + blueprints)
  - `app.py` entry (`app = create_app()`), `factory.py`, `config.py`, `security.py` (auth, CSRF, API keys, JSON errors)
  - `routes/` — `auth`, `health`, `detection`, `events`, `integrations`, `alerts` blueprints
  - `detection.py` rule engine · `database.py` all SQL (scoped by `owner_id`) · `validation.py` · `constants.py`
  - `tests/` — unittest; `support.py` sets a temp DB and gives `client_for(user_id)`
- `frontend/` — static site
  - `app.html` shell (sidebar, top bar, page frame) + `assets/js/shell.js` hash router
  - `pages/*.html` — dashboard, live-detection, alerts, analyze, integrations (shown inside the shell)
  - `assets/css/base.css` tokens · `components.css` shared UI · `pages/*.css` layout only
  - `assets/js/core/` — `api.js` (apiFetch/apiJson), `ui.js` (csUI: el, modals, toasts), `frame.js`, `charts.js`

## Dev Commands
- Install: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && cp .env.example .env`
- API: `.venv/bin/python backend/app.py` → http://127.0.0.1:5050/api/health
- Frontend: `python3 -m http.server 5500 --directory frontend` → http://127.0.0.1:5500
- Test: `.venv/bin/python -m unittest discover -s backend/tests -t .`
- Production-like: `docker compose --env-file .env.compose up --build -d` → http://127.0.0.1:8080

## Rules
- Every DB query on user data filters by `owner_id`; never return another account's rows.
- New API routes go in the matching `backend/routes/*.py` blueprint with `@require_auth` and `@limiter.limit(...)`;
  return errors via `security.error(message, status)`.
- Frontend: call the API with `apiJson()`/`apiFetch()`; build DOM with `csUI.el()` (textContent, never innerHTML with data).
- Never use `alert()`/`confirm()`/`prompt()` — use `csUI.toast`, `csUI.confirm`, `csUI.prompt`.
- Styles use tokens from `base.css` and components from `components.css`; page CSS handles layout only.
- New page: `frontend/pages/<name>.html` loading `frame.js` first in `<head>`, then register it in `ROUTES` in `shell.js`.
- Adding a detection rule: add a `Rule(...)` to `RULES` with weight, MITRE, CWE, remediation; add a test.
- Deleting an alert archives it (`is_deleted`) and writes `alert_activity`.
- Never commit `.env`, `.env.compose`, secrets, or a populated `security.db`.

## Gotchas
- `database.py` reads `CYBER_SENTINEL_DB` at import; tests must import `backend.tests.support` before `backend.*`.
- Pages under `pages/` redirect to `app.html#/<page>` when opened directly (frame.js); test them through the shell.
- Links inside pages use `../app.html#/route`; frame.js routes them through the shell.
- `api.js` calls `:5050` only when the page is served on port 5500 (macOS AirPlay holds :5000); otherwise same origin.
- `CORS_ORIGINS` must list the exact frontend origin, or cookie-auth requests fail.
- Production refuses to start without a ≥32-char `SECRET_KEY` or with wildcard CORS.
- Rate limits are per process by default; multiple Gunicorn workers need `RATELIMIT_STORAGE_URI` (Redis).
- `backend/security.db` and `__pycache__` are tracked in git; don't commit changes to them.

## Claude Memory System
- Deeper notes: `.claude/memory/` · per-module notes: `.claude/modules/`
- Tasks: `.claude/tasks/{todo,inprogress,done,plans,logs}`; personal EOD notes in `.claude/tasks/eod/` (gitignored)
- Commands: `/r-help` lists all. Common: `/r-start`, `/r-task`, `/r-plan`, `/r-fix`, `/r-done`, `/r-end`

## Before / After Every Task
1. Read the relevant `.claude/modules/<module>.md` and `.claude/memory/gotchas.md`; state the plan and files first
2. Run the tests; update the module changelog; log new gotchas/patterns/decisions; save a task log
EOF

# ───────────────────────────────────────────────────────
# STEP 4: MEMORY FILES
# ───────────────────────────────────────────────────────

print_step "Creating Memory Files"

make_file ".claude/memory/context.md" << 'EOF'
# Project Context

- **Product Name**: Cyber Sentinel
- **Purpose**: Local / single-host security event triage. Users paste or ingest event text
  (URLs, HTTP requests, log lines); the API flags injection, file-probe, SSRF, brute-force and
  scanner indicators with an explainable score, then tracks alerts through a triage workflow.
- **Target Users**: Developers and small security teams triaging application logs.
- **Current Phase**: Prototype / MVP.
- **What Must Never Break**:
  - Per-account isolation (every query scoped by `owner_id`)
  - Auth: Argon2id passwords, signed sessions, CSRF checks on writes
  - Alert audit trail (`alert_activity`); archive instead of delete
  - API key secrecy (hashed at rest, shown once)
- **Known Technical Debt**:
  - Test coverage limited to risk assessment (no auth, ingest, API key, triage tests)
  - `security.db` and `__pycache__` tracked in git
  - README feature list out of date vs. the 10 detection rules
  - Some pages contain hard-coded placeholder numbers until the first refresh
EOF

make_file ".claude/memory/architecture.md" << 'EOF'
# Architecture

## Stack
- Backend: Python 3, Flask 3 (app factory + blueprints), Flask-Cors, Flask-Limiter, argon2-cffi, SQLite
- Serving: Gunicorn (gthread, `preload_app=True`); Nginx serves `frontend/` and proxies `/api/`
- Frontend: plain HTML/CSS/JS, no build step; Chart.js 4.4.1 from jsDelivr

## Backend Layers
1. `factory.create_app()` → config validation, CORS, limiter, security headers, blueprints
2. `routes/<area>.py` → `@require_auth` (session + CSRF) or API-key principal → `validation.py`
3. `detection.assess_risk(text)` → findings, score, level
4. `database.py` → `record_event()` stores the event and, when indicators match, an alert

## Frontend Layers
- `app.html` shell: sidebar, top bar (notifications, account), `<iframe id="pageFrame">`
- `shell.js`: hash routes `#/<route>?query` → `pages/<page>.html?query`; aliases for old names
- Each page: `frame.js` (head) → `api.js` → `ui.js` → [`charts.js`] → `pages/<page>.js`
- Inside the shell, `csUI.confirm/prompt/toast` render in the shell window (cover the whole app)
- Pages notify the shell of alert changes with `csNotifyChanged()`; the shell sends `cs:data-changed` to the page

## Detection
- 10 `Rule`s (regex, weight, MITRE, CWE, remediation); input checked raw, URL-decoded (2x) and HTML-unescaped
- Score = sum of weights, capped at 100. CRITICAL ≥80, HIGH ≥60, MEDIUM ≥30, else LOW

## Auth Flow
- Login → Argon2id verify → HttpOnly session (8 h) + `csrf_token`; frontend keeps the token in sessionStorage
- 401 → `api.js` sends the whole window to `login.html?next=#/<route>`; login returns there
- Ingestion uses hashed per-account API keys (`cs_live_…`)

## Tables
`users`, `api_keys`, `security_events`, `security_alerts`, `alert_activity`
EOF

make_file ".claude/memory/rules.md" << 'EOF'
# Rules — Non Negotiable

## Data Access
✅ DO: pass `owner_id` into every `database.py` function and filter by it in SQL
✅ DO: use parameterized queries (`?` placeholders)
❌ DON'T: build SQL with string formatting from request data

## API Routes
✅ DO: put routes in the matching blueprint under `backend/routes/`
✅ DO: use `@require_auth`, a `@limiter.limit(...)`, and `security.error()` for failures
✅ DO: parse input with helpers in `validation.py`; shared constants live in `constants.py`
❌ DON'T: add state-changing GET routes (CSRF is enforced only on non-GET)

## Frontend
✅ DO: `apiJson()` for API calls, `csUI.el()` for DOM, design tokens for colours
✅ DO: give every list an empty state (`csUI.emptyState`) and every action feedback (`csUI.toast`)
❌ DON'T: `innerHTML` with event data, or `alert()` / `confirm()` / `prompt()`

## Detection Rules
✅ DO: id, weight, category, MITRE ID/name, CWE, description and remediation for each rule, plus a test
❌ DON'T: describe a match as a confirmed attack in UI or API text — it is an indicator

## Testing
✅ DO: `.venv/bin/python -m unittest discover -s backend/tests -t .` before finishing
✅ DO: import `backend.tests.support` first in new test modules

## Environment Variables
✅ DO: document new variables in `.env.example` (and `.env.compose.example` if used in Compose)
❌ DON'T: hard-code secrets or commit `.env` files
EOF

make_file ".claude/memory/patterns.md" << 'EOF'
# Established Patterns

#### Authenticated route
- **Example**: `backend/routes/alerts.py` — `@bp.get(...)`, `@limiter.limit(...)`, `@require_auth`, `current_user_id()`
- **Anti-pattern**: reading `session["user_id"]` inside a handler

#### Data-layer function
- **Example**: `backend/database.py` — `with get_connection() as connection:`, `owner_id` first argument

#### Page in the shell
- **Example**: `frontend/pages/integrations.html` + `assets/css/pages/integrations.css` + `assets/js/pages/integrations.js`
- `frame.js` first in `<head>`; scripts `api.js` → `ui.js` → page script; route registered in `shell.js`

#### Confirm / note before a change
- **Example**: `frontend/assets/js/pages/alerts.js` — `await csUI.prompt({ required: true, suggestions })`

#### Detection rule
- **Example**: `backend/detection.py` — `Rule("SSRF", ..., 35, re.compile(...), ..., "T1552.005", ..., "CWE-918")`

## Template
#### [Pattern Name]
- **When to use**:
- **Example**: [file path + snippet]
- **Anti-pattern**:
EOF

make_file ".claude/memory/decisions.md" << EOF
# Architecture Decisions

#### Rule-based detection, not ML
- **Decision**: transparent regex rules with weights, MITRE and CWE mapping
- **Reason**: every result is explainable with evidence; easy to test
- **Tradeoffs**: misses novel or obfuscated payloads; false positives possible
- **Revisit If**: rule maintenance becomes the bottleneck

#### SQLite on a single host
- **Decision**: one SQLite file, one API container per volume
- **Reason**: zero-ops for a prototype; online backup API covers backups
- **Tradeoffs**: no horizontal scaling of the API
- **Revisit If**: multiple API instances or heavy ingest volume are needed

#### Session cookies + CSRF for the UI, API keys for ingestion
- **Decision**: browser uses HttpOnly session + X-CSRF-Token; machines use hashed \`cs_live_\` keys
- **Reason**: keeps browser credentials out of JS and machine credentials revocable

#### Archive instead of delete
- **Decision**: \`DELETE /api/alerts/<id>\` sets \`is_deleted\` and logs activity
- **Reason**: preserve the audit trail

#### $TODAY — Claude memory system
- **Decision**: project-scoped Claude Code memory in .claude/ (setup-claude.sh)
- **Reason**: shared team context, task tracking, consistent workflow

## Template
#### [date] — [Title]
- **Problem**:
- **Options Considered**:
- **Decision**:
- **Reason**:
- **Tradeoffs**:
- **Revisit If**:
EOF

make_file ".claude/memory/gotchas.md" << 'EOF'
# Gotchas

#### tests — database path is read at import
- **What Happens**: tests write into the real `backend/security.db`
- **How to Avoid**: import `backend.tests.support` before anything from `backend`

#### frontend — pages redirect when opened directly
- **What Happens**: opening `pages/alerts.html` lands on `app.html#/alerts`
- **Why**: `frame.js` keeps the sidebar shell around every page
- **How to Avoid**: test pages through the shell; links use `../app.html#/route`

#### frontend — API origin depends on port
- **Why**: `api.js` uses `:5050` only when the page is on port 5500, otherwise the same origin
- **How to Avoid**: serve `frontend/` on 5500 locally; keep `CORS_ORIGINS` in sync

#### deployment — rate limits per process
- **How to Avoid**: set `RATELIMIT_STORAGE_URI` to Redis when running more than one worker

#### deployment — .dockerignore patterns
- **What Happens**: root-only patterns would let `backend/security.db` into the API image
- **How to Avoid**: keep the `**/` patterns in `.dockerignore`

#### repo — tracked generated files
- **What Happens**: `backend/security.db` and `__pycache__` show up as modified
- **How to Avoid**: don't commit them; `git rm --cached` them in a dedicated cleanup change

## Template
#### [Module] — [Title]
- **What Happens**:
- **Why**:
- **How to Avoid**:
- **Discovered**:
EOF

make_file ".claude/memory/dependencies.md" << 'EOF'
# Module Dependencies

## Backend
- `routes/*` → `security`, `validation`, `constants`, `extensions`, `database`, `detection`
- `factory` → `config`, `routes`, `security`, `extensions`, `database`
- `database.py`, `detection.py` → stdlib only

## Frontend
- Every page → `core/api.js`, `core/ui.js`; dashboard and live-detection → `core/charts.js`
- `shell.js` ROUTES ↔ `pages/*.html` names; `frame.js` ↔ `shell.js` (`CS_SHELL`, `csNavigate`)
- `nginx.conf` → API service name `api:5000`

## High Risk (largest blast radius)
- `security.require_auth`, `database.record_event`, `detection.assess_risk` / `RULES`
- `core/api.js`, `core/ui.js`, `base.css` tokens, `components.css`

## Response Shape Contracts
- `risk_score`, `risk_level`, `findings[]`, `matched_rules`, `recommendation` are read by analyze.js, live-detection.js,
  dashboard.js and alerts.js; `/api/stats` fields by dashboard.js, alerts.js, live-detection.js
EOF

make_file ".claude/memory/pre-task-checklist.md" << 'EOF'
# Pre Task Checklist

- [ ] Read CLAUDE.md
- [ ] Read .claude/modules/[relevant].md
- [ ] Read .claude/memory/gotchas.md
- [ ] Check .claude/memory/dependencies.md for blast radius
- [ ] State the plan and list files that will change
- [ ] Confirm plan follows .claude/memory/rules.md
EOF

make_file ".claude/memory/post-task-checklist.md" << 'EOF'
# Post Task Checklist

- [ ] Tests pass: .venv/bin/python -m unittest discover -s backend/tests -t .
- [ ] New queries scoped by owner_id; new routes have @require_auth + rate limit
- [ ] Frontend: csUI.el (no innerHTML with data), empty state, toast feedback, no native dialogs
- [ ] .env.example / README updated if config or API changed
- [ ] .claude/modules/[affected].md changelog updated
- [ ] New gotchas / patterns / decisions logged in .claude/memory/
- [ ] Task log saved to .claude/tasks/logs/YYYY-MM-DD-[title].md
EOF

make_file ".claude/memory/INDEX.md" << 'EOF'
# Memory System Index

## Directory Structure
.claude/
├── memory/              → core memory files
├── modules/             → detection, api, database, frontend, deployment
├── tasks/
│   ├── todo/            → tasks waiting to be picked up
│   ├── inprogress/      → tasks being worked on
│   ├── done/            → completed tasks
│   ├── plans/           → feature plans before coding
│   ├── logs/            → completed task logs
│   └── eod/             → personal EOD (gitignored)
├── commands/
│   ├── system/          → built-in r- commands
│   └── custom/          → your custom r- commands
├── settings.json        → shared permissions (commit)
├── settings.local.json  → personal settings (gitignored)
└── developer.local      → your name for task commands (gitignored)

## Quick Reference
| Situation | Command |
|---|---|
| Start session | /r-start |
| See all tasks | /r-todo |
| Add a task | /r-add-task [desc] |
| Pick up a task | /r-pickup |
| Execute a task | /r-task [desc] |
| Plan a feature | /r-plan [feature] |
| Fix something | /r-fix [desc] |
| Mark task done | /r-done |
| Review last task | /r-review |
| Find something | /r-where [thing] |
| Check blast radius | /r-impact [thing] |
| Log a decision | /r-decisions [desc] |
| Log a gotcha | /r-gotcha [desc] |
| Log a pattern | /r-pattern [desc] |
| Sync memory | /r-memory-update |
| Full rescan | /r-memory-scan |
| Memory health | /r-memory-status |
| End session | /r-end |
| Check tokens | /r-tokens |
| All commands | /r-help |

## Core Memory Files
| File | Purpose |
|---|---|
| CLAUDE.md | Auto-loaded every session |
| memory/context.md | Product purpose and priorities |
| memory/architecture.md | System design and data flow |
| memory/rules.md | Non-negotiable coding rules |
| memory/patterns.md | Established code patterns |
| memory/decisions.md | Architecture decision log |
| memory/gotchas.md | Known traps |
| memory/dependencies.md | Module dependency map |
| memory/pre-task-checklist.md | Run before every task |
| memory/post-task-checklist.md | Run after every task |
EOF

make_file ".claude/memory/VERSION" << EOF
Memory System Version: 1.1.0 (Cyber Sentinel)
Created: $TODAY
Project: $PROJECT_NAME
Memory Root: .claude/memory/
Modules Root: .claude/modules/
Tasks Root: .claude/tasks/
Commands Root: .claude/commands/
Last Full Scan: $TODAY (pre-filled by setup-claude.sh)
Generated By: setup-claude.sh
EOF

# ───────────────────────────────────────────────────────
# STEP 4b: MODULE FILES
# ───────────────────────────────────────────────────────

print_step "Creating Module Files"

make_file ".claude/modules/detection.md" << 'EOF'
# Module: Detection Engine
**Files**: backend/detection.py
**Confidence**: high (pre-filled from code)

## Responsibility
Score event text against `RULES` and return findings with evidence, MITRE, CWE and remediation.

## Public API
- `assess_risk(event_data) -> dict` — risk_score, risk_level, detected_threats, matched_rules, findings, recommendation, engine
- `rule_catalog() -> list` — served by `GET /api/detection/rules`
- `risk_level_for(score)` — CRITICAL ≥80, HIGH ≥60, MEDIUM ≥30, LOW

## Rules (id · weight)
SQL_INJECTION 40 · XSS 40 · COMMAND_INJECTION 40 · JNDI_INJECTION 50 · XXE 40 ·
PATH_TRAVERSAL 30 · SENSITIVE_FILE_PROBE 25 · SSRF 35 · BRUTE_FORCE 30 · SCANNER_ACTIVITY 20

## Notes
- Each rule matches at most once per event, against raw, URL-decoded (2x) or HTML-unescaped text.
- Bump `ENGINE_VERSION` when rule behavior changes.

## Changelog
EOF

make_file ".claude/modules/api.md" << 'EOF'
# Module: API
**Files**: backend/app.py, factory.py, config.py, security.py, validation.py, constants.py, extensions.py, routes/*.py
**Confidence**: high (pre-filled from code)

## Blueprints
- `auth`: POST /api/auth/register (5/h), POST /api/auth/login (10/min), GET /api/auth/me, POST /api/auth/logout
- `health`: GET /api/health, GET /api/health/live
- `detection`: POST /api/assess-risk (20/min), GET /api/detection/rules, GET /api/detection/overview
- `events`: POST /api/events/ingest (300/min, API key), GET /api/events
- `integrations`: GET/POST /api/integrations/keys, DELETE /api/integrations/keys/<id>
- `alerts`: GET /api/alerts, GET /api/stats, GET /api/activity, PATCH/DELETE /api/alerts/<id>, GET /api/alerts/<id>/activity
- Default limit 120/hour per IP; unknown routes return JSON 404

## Changelog
EOF

make_file ".claude/modules/database.md" << 'EOF'
# Module: Database
**Files**: backend/database.py
**Confidence**: high (pre-filled from code)

## Responsibility
SQLite schema creation and every query. Path from `CYBER_SENTINEL_DB` (default backend/security.db).

## Tables
users, api_keys, security_events, security_alerts, alert_activity

## Notes
- `get_connection()` is a context manager: commit on success, rollback on error, foreign keys on, busy timeout 10 s.
- First registered user claims pre-account alerts (`owner_id IS NULL`) and gets an import activity entry.
- Alerts are archived via `is_deleted`, never removed.

## Changelog
EOF

make_file ".claude/modules/frontend.md" << 'EOF'
# Module: Frontend
**Files**: frontend/
**Confidence**: high (pre-filled from code)

## Routes (app.html#/<route>)
dashboard, live-detection, alerts, activities (dashboard section), analyze, integrations
Aliases: threat-detection, live-monitoring → live-detection · risk-assessment → analyze · security-alerts → alerts

## Notes
- Live Detection polls every 5 s (backoff on errors); dashboard refreshes every 30 s; shell checks unread alerts every 30 s.
- Analyze accepts `?sample=<key>`, `?rules=1`, and a sessionStorage handoff (`cs:analyze-prefill`).
- Alerts accepts `?status=`, `?risk_level=`, `?is_read=false`.

## Changelog
EOF

make_file ".claude/modules/deployment.md" << 'EOF'
# Module: Deployment
**Files**: Dockerfile, Dockerfile.frontend, nginx.conf, compose.yaml, gunicorn.conf.py, Procfile, .env*.example
**Confidence**: high (pre-filled from code)

## Notes
- Compose: api (Gunicorn, SQLite volume /data), web (Nginx on 127.0.0.1:8080, proxies /api/), redis (rate limits only).
- Gunicorn: gthread, WEB_CONCURRENCY workers (default 2), preload_app so schema init runs once.
- Production needs SECRET_KEY ≥32 chars, explicit CORS_ORIGINS, COOKIE_SECURE=1 behind TLS.
- Back up with SQLite's online backup API (see README).

## Changelog
EOF

# ───────────────────────────────────────────────────────
# STEP 5: TASK READMES
# ───────────────────────────────────────────────────────

print_step "Creating Task Folders"

make_file ".claude/tasks/todo/README.md" << EOF
# 📋 Todo Tasks
Anyone on the team can add tasks here.
Anyone on the team can pick up any task.

## How to add a task
Run: /r-add-task [description]
Or create: .claude/tasks/todo/$TODAY-[title].md

## Task template
---
# Task: [title]
**Added By**: [name]
**Date Added**: $TODAY
**Priority**: 🔴 High / 🟡 Medium / 🟢 Low
**Module**: [which module]
**Estimated Effort**: Small / Medium / Large
**Assigned To**: unassigned

## Description
[what needs to be done and why]

## Acceptance Criteria
- [ ] [what done looks like]

## Notes
[context, gotchas, links]

## Related Files
[relevant file paths]
---

## How to pick up a task
Run: /r-pickup
Commit and push so team knows it is taken.
EOF

make_file ".claude/tasks/inprogress/README.md" << 'EOF'
# 🔄 In Progress
Tasks currently being worked on.
Move here from todo/ when you start.
Commit so team knows who is working on what.
EOF

make_file ".claude/tasks/done/README.md" << 'EOF'
# ✅ Done
Completed tasks.
Team and Claude read these to understand project history.
EOF

make_file ".claude/tasks/plans/README.md" << 'EOF'
# 📐 Plans
Feature plans created before coding.
Always plan large features before starting.
Run: /r-plan [feature name]
EOF

make_file ".claude/tasks/logs/README.md" << 'EOF'
# 📝 Task Logs
Logs of completed tasks.
Auto-created by /r-task and /r-done commands.
EOF

# ───────────────────────────────────────────────────────
# STEP 6: SYSTEM COMMANDS
# ───────────────────────────────────────────────────────

print_step "Creating System Commands"

make_file ".claude/commands/system/r-start.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read only from this project's .claude/ directory.

Load full memory system:
1. CLAUDE.md (already loaded by Claude Code)
2. .claude/memory/context.md
3. .claude/memory/architecture.md
4. .claude/memory/rules.md
5. .claude/memory/patterns.md
6. .claude/memory/gotchas.md
7. .claude/memory/dependencies.md
8. Last 3 files in .claude/tasks/logs/
9. Last file in .claude/tasks/eod/ if exists
10. Scan all .claude/modules/ — flag any 🔴 Stale
11. Read .claude/tasks/todo/ — count and sort by priority
12. Read .claude/tasks/inprogress/ — list what is in progress

Report:
- ✅ Memory loaded — what you know about this project
- ⚠️ Stale modules — list with suggested action
- 🔴 Risk flags — anything broken or outdated
- 📋 Todo: [count] tasks — top 3 by priority
- 🔄 In Progress: [what is being worked on]
- 💡 Suggested focus — highest priority todo task
- 🛠️ Dev commands quick ref

At the very end of the report show a token usage meter:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧠 TOKEN USAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Used:      [████░░░░░░░░░░░░░░░░]  ~XX%  (~XXk / 200k)
Remaining: [████████████████░░░░]  ~XX%  (~XXk tokens)
Status:    🟢 Safe / 🟡 Medium / 🔴 Critical
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟢 Safe 0–60%  → keep working
🟡 Medium 60–80% → wrap up current task, run /r-end soon
🔴 Critical 80%+ → run /r-end NOW before context cuts off
Tip: run /r-tokens anytime to check remaining context.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You are now senior dev partner for this session.
Never ask to re-explain anything already in memory.
EOF

make_file ".claude/commands/system/r-end.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Save to .claude/tasks/eod/ only.

Session ending:
1. List all tasks completed this session
2. List all files changed
3. List all memory files updated
4. List anything unfinished or still in progress
5. Suggest what to pick up first tomorrow
6. Check if CLAUDE.md needs updating

Save to .claude/tasks/eod/YYYY-MM-DD-EOD-summary.md
Confirm saved. Remind: this file is personal and gitignored.
EOF

make_file ".claude/commands/system/r-task.md" << 'EOF'
> ⚠️ PROJECT SCOPED: All outputs save to .claude/ only.

Execute the given task:
1. Read .claude/memory/pre-task-checklist.md — complete every item
2. Read .claude/modules/[relevant].md
3. State complete plan before writing any code
4. Wait for approval if change touches more than 3 files
5. Execute the task
6. Read .claude/memory/post-task-checklist.md — complete every item
7. Update all affected .claude/modules/ files
8. Save log to .claude/tasks/logs/YYYY-MM-DD-[title].md

Log format:
# Task: [title]
**Date**:
**Summary**:
**Files Changed**:
**Modules Affected**:
**Decisions Made**:
**Memory Updated**:
**Notes**:

Confirm log saved with full path.
EOF

make_file ".claude/commands/system/r-plan.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Save to .claude/tasks/plans/ only.

Do NOT write any code yet.
Plan the requested feature:
1. Read full memory system
2. Read all relevant .claude/modules/ files
3. List all files to create/change/delete
4. List patterns to follow
5. List rules that apply
6. Map blast radius
7. List risks and gotchas
8. Write step by step execution order

Save to .claude/tasks/plans/YYYY-MM-DD-[feature]-PLAN.md
Confirm saved. Wait for explicit approval before coding.
EOF

make_file ".claude/commands/system/r-fix.md" << 'EOF'
> ⚠️ PROJECT SCOPED: All reads and updates stay in .claude/ only.

Diagnose and fix what is broken:
1. Read .claude/memory/gotchas.md first
2. Read .claude/modules/[relevant].md
3. Trace actual root cause — never guess
4. Explain what is broken and exactly why
5. Propose fix with clear reasoning
6. Apply the fix
7. Verify fix works
8. New gotcha? Add to .claude/memory/gotchas.md
9. Add to .claude/modules/[relevant].md gotchas section
10. Update module changelog
11. Save log to .claude/tasks/logs/YYYY-MM-DD-fix-[title].md
EOF

make_file ".claude/commands/system/r-review.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read from .claude/ only.

Review the last completed task:
1. Read most recent file in .claude/tasks/logs/
2. Check every rule in .claude/memory/rules.md was followed
3. Check correct patterns were used
4. Check memory files were properly updated
5. Check error handling is correct

Report:
- ✅ Pass / ❌ Fail for each check
- Issues found with file references
- Suggested improvements
- New gotchas or patterns to log
EOF

make_file ".claude/commands/system/r-todo.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read from .claude/tasks/ only.

Show all tasks and status:
1. Read all files in .claude/tasks/todo/
2. Read all files in .claude/tasks/inprogress/
3. Read last 5 files in .claude/tasks/done/

Report:

## 📋 Todo ([count])
| Priority | Task | Module | Effort | Added By |
|---|---|---|---|---|
[sorted: 🔴 first, then 🟡, then 🟢]

## 🔄 In Progress ([count])
| Task | Module | Assigned To | Started |
|---|---|---|---|

## ✅ Recently Done (last 5)
| Task | Module | Completed By |
|---|---|---|
EOF

make_file ".claude/commands/system/r-add-task.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Save to .claude/tasks/todo/ only.

Create a new task for the team todo list.
Infer developer name from:
1. .claude/developer.local (first line)
2. git config user.name
3. Ask if neither found

Gather or infer:
- Task title
- Which module it touches
- Priority (🔴 High / 🟡 Medium / 🟢 Low)
- Description
- Acceptance criteria
- Estimated effort (Small / Medium / Large)
- Related file paths

Save to .claude/tasks/todo/YYYY-MM-DD-[title].md

# Task: [title]
**Added By**: [name]
**Date Added**: [today]
**Priority**: [priority]
**Module**: [module]
**Estimated Effort**: [effort]
**Assigned To**: unassigned

## Description
[description]

## Acceptance Criteria
- [ ] [criteria]

## Notes
[notes]

## Related Files
[paths]

Confirm saved. Remind: commit and push so team can see it.
EOF

make_file ".claude/commands/system/r-pickup.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Move files within .claude/tasks/ only.

Pick up a task from todo list:
1. Read all files in .claude/tasks/todo/
2. Show list sorted by priority
3. Identify which task to pick up from context or ask
4. Get developer name from:
   a. .claude/developer.local (first line)
   b. git config user.name
   c. Ask if neither found
5. Move file: .claude/tasks/todo/ → .claude/tasks/inprogress/
6. Add to file:
   - Assigned To: [name]
   - Started: [today]
7. Automatically run r-task with the task description

Confirm moved with full path.
Remind: commit and push so team knows it is taken.
EOF

make_file ".claude/commands/system/r-done.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Move files within .claude/tasks/ only.

Mark current task as done:
1. Read files in .claude/tasks/inprogress/
2. Identify task from context or ask
3. Get developer name from .claude/developer.local or git config
4. Update task file:
   - Completed By: [name]
   - Completed Date: [today]
   - Check off all met acceptance criteria
   - Add ## Summary of what was done
5. Move: .claude/tasks/inprogress/ → .claude/tasks/done/
6. Save log to .claude/tasks/logs/YYYY-MM-DD-[title].md
7. Suggest git commit message for team

Confirm moved. Remind: commit and push so team sees it is done.
EOF

make_file ".claude/commands/system/r-memory-update.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read and write .claude/ only.
> ⚠️ SAFE MODE: Never delete or overwrite existing content.

Sync memory with current codebase — SAFE MODE rules:
- NEVER delete existing memory files
- NEVER overwrite existing content
- ONLY add missing information
- When updating an outdated field → keep old value in comment:
  <!-- previous: old value here -->
- Always append to changelogs — never rewrite them
- If unsure whether to update → leave existing and flag:
  ⚠️ NEEDS REVIEW: [what was found]

Process:
1. Read every file in the project
2. Compare against all .claude/memory/ files
3. Compare against all .claude/modules/ files
4. Find everything outdated, missing, or wrong
5. ADD missing sections only — never replace existing
6. APPEND new findings — never overwrite
7. Set confidence: 🟢 High / 🟡 Medium / 🔴 Stale
8. Update all Last Updated dates
9. Update CLAUDE.md missing sections only
10. Bump VERSION minor version

Report all changes made with file paths.
EOF

make_file ".claude/commands/system/r-memory-save.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Save to .claude/ only.

Save all memory files modified this session:
1. Save all updated .claude/memory/ files
2. Save all updated .claude/modules/ files
3. Confirm each with full path and Last Updated date
4. List summary of what changed in each
EOF

make_file ".claude/commands/system/r-memory-status.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read from .claude/modules/ only.

Read all .claude/modules/ files.
Report:

| Module | Confidence | Last Updated | Notes |
|---|---|---|---|

Then:
- List all 🔴 Stale with fix action
- List all 🟡 Medium with reason
- Overall memory health score
EOF

make_file ".claude/commands/system/r-memory-scan.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Update .claude/ only. Never touch global paths.
> ⚠️ SAFE MODE: Never delete or overwrite existing content.

Full project re-scan — SAFE MODE rules:
- NEVER delete any existing file in .claude/
- NEVER overwrite any existing content in .claude/
- ONLY append new findings to existing files
- ONLY create files that do not exist yet
- ALWAYS append to changelogs — never rewrite them
- If unsure → keep existing content and add below it

Process:
1. Read every single file in the project
2. For each file in .claude/memory/:
   - Read existing content first
   - Compare with current codebase
   - ADD missing sections only
   - APPEND new findings below existing content
   - Never touch content that already exists
3. For each module in .claude/modules/:
   - If file exists → read first, then append new findings only
   - If file does not exist → create fresh
   - Always append to Changelog — never rewrite it
4. For new modules not yet in .claude/modules/:
   - Create new file only
5. Update CLAUDE.md:
   - Only add missing sections
   - Never overwrite existing sections
   - Append to existing sections where needed
6. Bump .claude/memory/VERSION minor version

Report:
- ✅ Files updated (what was appended)
- ✅ New files created
- ⏭️ Files skipped (already up to date)
- ⚠️ Nothing deleted
- ⚠️ Nothing overwritten
- New modules discovered
- Major changes found since last scan
EOF

make_file ".claude/commands/system/r-impact.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read from .claude/ only.

Analyze blast radius:
1. Read .claude/memory/dependencies.md
2. Read all relevant .claude/modules/ files
3. Trace direct and indirect dependencies
4. List all files that need updating
5. List tests affected

Report:
- Risk: 🟢 Low / 🟡 Medium / 🔴 High
- Direct impact with file paths
- Indirect impact with file paths
- Files to update
- Tests to check
- Recommendation
EOF

make_file ".claude/commands/system/r-where.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read from .claude/ only.

Find where the requested thing lives:
1. Read .claude/memory/dependencies.md
2. Read relevant .claude/modules/ files
3. Search actual codebase

Report:
- Exact file paths and line numbers
- Which module owns it
- What imports it
- What it exports to
EOF

make_file ".claude/commands/system/r-decisions.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Save to .claude/memory/decisions.md only.

Log a new architecture decision.
Add to .claude/memory/decisions.md:

#### [today] — [title]
- **Problem**:
- **Options Considered**:
- **Decision**:
- **Reason**:
- **Tradeoffs**:
- **Revisit If**:

Confirm saved to .claude/memory/decisions.md
EOF

make_file ".claude/commands/system/r-gotcha.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Save to .claude/ only.

Log a new gotcha:
1. Add to .claude/memory/gotchas.md
2. Add to .claude/modules/[relevant].md gotchas section
3. Append to module changelog

#### [Module] — [Title]
- **What Happens**:
- **Why**:
- **How to Avoid**:
- **Discovered**: [today]

Confirm saved to both files.
EOF

make_file ".claude/commands/system/r-pattern.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Save to .claude/memory/patterns.md only.

Log a new pattern:
#### [Pattern Name]
- **When to use**:
- **Example**: [file path + snippet]
- **Anti-pattern**:

Confirm saved to .claude/memory/patterns.md
EOF

make_file ".claude/commands/system/r-tokens.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read from .claude/ only.

Estimate current token usage for this session.

Calculate approximate tokens used based on:
- All memory files loaded this session
- All files read from the project
- Full conversation length so far
- All responses generated

Then display:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧠 TOKEN USAGE — Current Session
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Used:      [fill bar with █ and ░]  ~XX%  (~XXk / 200k)
Remaining: [fill bar with █ and ░]  ~XX%  (~XXk tokens)
Status:    🟢 Safe / 🟡 Medium / 🔴 Critical
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟢 Safe      0–60%  → keep working
🟡 Medium   60–80%  → wrap up task, run /r-end soon
🔴 Critical  80%+   → run /r-end NOW before cutoff
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Bar is 20 chars wide:
- Each █ = 5% used
- Each ░ = 5% remaining
- Example 60% used: ████████████░░░░░░░░

Note: This is an estimate based on conversation size.
Actual token count may vary slightly.
Run /r-end before hitting 85% to save session safely.
EOF

make_file ".claude/commands/system/r-help.md" << 'EOF'
> ⚠️ PROJECT SCOPED: Read from .claude/commands/ only.

Read .claude/commands/system/ and .claude/commands/custom/
Display all available commands:

## System Commands
| Command | Description |
|---|---|
| /r-start | Load memory, show project status + token meter |
| /r-end | EOD summary, save session |
| /r-todo | Show all tasks and status |
| /r-add-task [desc] | Add task to team todo list |
| /r-pickup | Pick up a task from todo |
| /r-task [desc] | Execute a task with full memory |
| /r-done | Mark current task as done |
| /r-plan [feature] | Plan before coding |
| /r-fix [desc] | Diagnose and fix something broken |
| /r-review | Review last task quality |
| /r-where [thing] | Find where something lives |
| /r-impact [thing] | Blast radius of a change |
| /r-decisions [desc] | Log architecture decision |
| /r-gotcha [desc] | Log a new gotcha |
| /r-pattern [desc] | Log a new pattern |
| /r-memory-update | Sync memory with codebase |
| /r-memory-save | Force save all memory files |
| /r-memory-status | Show module confidence levels |
| /r-memory-scan | Full project rescan |
| /r-tokens | Show token usage meter for this session |
| /r-help | Show this list |

## Custom Commands
[list any found in .claude/commands/custom/]
[if empty: No custom commands yet — see .claude/commands/custom/README.md]
EOF

# ───────────────────────────────────────────────────────
# STEP 7: CUSTOM COMMANDS README
# ───────────────────────────────────────────────────────

print_step "Creating Custom Commands"

make_file ".claude/commands/custom/README.md" << 'EOF'
# Custom Commands
> ⚠️ PROJECT SCOPED: Save to .claude/commands/custom/ only.
> All custom commands use r- prefix.

## Template
Create: .claude/commands/custom/r-[name].md

Content:
---
> ⚠️ PROJECT SCOPED: All reads and writes stay within .claude/ only.
[Exact instructions for Claude to execute when this command is typed]
---

## To add a custom command
/r-task create custom command /r-[name] that does [description]

## Ideas
- /r-deploy   → your deployment steps
- /r-test     → run test suite your way
- /r-migrate  → database migration workflow
- /r-seed     → database seeding workflow
- /r-lint-fix → auto fix linting issues
EOF

# ───────────────────────────────────────────────────────
# STEP 8: UPDATE .gitignore
# ───────────────────────────────────────────────────────

print_step "Updating .gitignore"

GITIGNORE_BLOCK="
# ─────────────────────────────────────────────────────
# Claude AI Memory System
# Shared with team: everything in .claude/ except below
# ─────────────────────────────────────────────────────
.claude/settings.local.json
.claude/developer.local
.claude/tasks/eod/
"

if [ -f ".gitignore" ]; then
  if grep -q "Claude AI Memory System" .gitignore; then
    print_warn ".gitignore already has Claude entries — skipping"
  else
    echo "$GITIGNORE_BLOCK" >> .gitignore
    print_ok "Appended to existing .gitignore"
  fi
else
  echo "$GITIGNORE_BLOCK" > .gitignore
  print_ok "Created .gitignore"
fi

# ───────────────────────────────────────────────────────
# STEP 9: UPDATE README.md
# ───────────────────────────────────────────────────────

print_step "Updating README.md"

README_BLOCK="
## 🧠 Claude AI Development System

This project uses a shared Claude Code memory system in \`.claude/\`

### First time setup
\`\`\`bash
npm install -g @anthropic-ai/claude-code
claude
\`\`\`
Your name for task commands is read from \`.claude/developer.local\` (pre-filled from \`git config user.name\`).
\`CLAUDE.md\` and \`.claude/memory/\` are pre-filled for this project; run \`/r-memory-scan\` after large changes.

### Daily workflow
\`\`\`
/r-start              → load memory, see project status
/r-todo               → see all pending tasks
/r-pickup             → pick up a task to work on
/r-task [desc]        → execute any task
/r-plan [feature]     → plan a big feature before coding
/r-fix [desc]         → diagnose and fix a bug
/r-done               → mark current task as complete
/r-end                → end of day summary
\`\`\`

### Team rules
- Commit all \`.claude/\` changes after tasks
- Only \`settings.local.json\`, \`developer.local\` and \`tasks/eod/\` are personal/gitignored
- Add tasks for teammates with \`/r-add-task\`
- Update module memory after touching any module
"

if [ -f "README.md" ]; then
  if grep -q "Claude AI Development System" README.md; then
    print_warn "README.md already has Claude section — skipping"
  else
    echo "$README_BLOCK" >> README.md
    print_ok "Appended to existing README.md"
  fi
else
  echo "# $PROJECT_NAME $README_BLOCK" > README.md
  print_ok "Created README.md"
fi

# ───────────────────────────────────────────────────────
# DONE
# ───────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Claude AI Development System Setup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Project:${NC}   $PROJECT_NAME"
echo -e "${CYAN}Stack:${NC}     $STACK"
echo -e "${CYAN}Date:${NC}      $TODAY"
if [ "$SAFE_MODE" = true ]; then
  echo -e "${YELLOW}Mode:${NC}      ⚠️  SAFE MODE — existing files were not touched"
else
  echo -e "${CYAN}Mode:${NC}      🆕 Fresh setup — all files created"
fi
echo ""
echo -e "${YELLOW}Next steps:${NC}"
if ! command -v claude >/dev/null 2>&1; then
  echo "  0. Install Claude Code: npm install -g @anthropic-ai/claude-code"
fi
if [ ! -d ".venv" ]; then
  echo "  1. Python env: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
fi
[ ! -f ".env" ] && echo "  1b. Config: cp .env.example .env"
echo "  2. Run: claude   (CLAUDE.md and .claude/memory/ are pre-filled for Cyber Sentinel)"
echo "  3. Check your name in .claude/developer.local"
echo "  4. Verify: $PYTHON -m unittest discover -s backend/tests -t ."
echo "  5. Commit: git add .claude/ CLAUDE.md .gitignore README.md && git push"
echo ""
echo -e "${YELLOW}Daily workflow:${NC}"
echo "  /r-start    → load memory"
echo "  /r-todo     → see tasks"
echo "  /r-pickup   → grab a task"
echo "  /r-task     → do the work"
echo "  /r-done     → mark complete"
echo "  /r-end      → end of day"
echo ""
echo -e "${GREEN}Happy coding! 🚀${NC}"
echo ""