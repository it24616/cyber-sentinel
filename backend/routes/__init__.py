"""HTTP API blueprints, one module per area."""

from backend.routes import alerts, auth, detection, events, health, integrations

BLUEPRINTS = (health.bp, auth.bp, detection.bp, events.bp, integrations.bp, alerts.bp)


def register_blueprints(app):
    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)
