"""Domain constants shared by routes and validation."""

RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

ALERT_STATUSES = ("Open", "Acknowledged", "In Progress", "Resolved", "False Positive")
TERMINAL_STATUSES = ("Resolved", "False Positive")

# Allowed alert workflow moves: current status -> statuses it may change to.
ALERT_TRANSITIONS = {
    "Open": {"Acknowledged", "Resolved", "False Positive"},
    "Acknowledged": {"Open", "In Progress", "Resolved", "False Positive"},
    "In Progress": {"Acknowledged", "Resolved", "False Positive"},
    "Resolved": {"Open"},
    "False Positive": {"Open"},
}

MANUAL_EVENT_TYPES = ("general", "url", "request", "log")

MAX_EVENT_CHARS = 10_000
MAX_BATCH_EVENTS = 100
MAX_ACTIVE_API_KEYS = 25
API_KEY_PREFIX = "cs_live_"
