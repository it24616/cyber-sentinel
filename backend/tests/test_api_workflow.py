"""End-to-end API behaviour against a real (temporary) SQLite database."""

import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from backend.tests.support import CSRF, app, client_for, disable_rate_limits, limiter, new_user
from backend import database

SQLI = "GET /products?id=1' UNION SELECT password FROM users-- HTTP/1.1"
WRITE = {"X-CSRF-Token": CSRF}


class AuthTests(unittest.TestCase):
    def setUp(self):
        disable_rate_limits(self)
        self._database_dir = tempfile.TemporaryDirectory(prefix="cyber-sentinel-auth-tests-")
        self.addCleanup(self._database_dir.cleanup)
        database_patch = patch.multiple(
            database,
            IS_POSTGRES=False,
            DATABASE=Path(self._database_dir.name) / "security.db",
        )
        database_patch.start()
        self.addCleanup(database_patch.stop)
        database.initialize_database()
        signup_patch = patch.dict(os.environ, {"ALLOW_SIGNUP": "1"})
        signup_patch.start()
        self.addCleanup(signup_patch.stop)
        self.client = app.test_client()
        self.email = f"{uuid.uuid4().hex}@example.test"

    def register(self, **overrides):
        body = {"full_name": "Analyst", "email": self.email, "password": "correct-horse-battery"} | overrides
        return self.client.post("/api/auth/register", json=body)

    def test_register_login_me_logout(self):
        self.assertEqual(self.register().status_code, 201)
        self.assertEqual(self.register().status_code, 409)  # same email again

        login = self.client.post("/api/auth/login", json={"email": self.email.upper(), "password": "correct-horse-battery"})
        self.assertEqual(login.status_code, 200)
        token = login.get_json()["csrf_token"]

        me = self.client.get("/api/auth/me").get_json()
        self.assertEqual(me["user"]["email"], self.email)
        self.assertNotIn("password_hash", me["user"])

        self.assertEqual(self.client.post("/api/auth/logout").status_code, 403)  # CSRF token missing
        self.assertEqual(self.client.post("/api/auth/logout", headers={"X-CSRF-Token": token}).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)

    def test_wrong_password_and_unknown_email_look_the_same(self):
        self.register()
        wrong = self.client.post("/api/auth/login", json={"email": self.email, "password": "not-the-password"})
        unknown = self.client.post("/api/auth/login", json={"email": "nobody@example.test", "password": "not-the-password"})
        self.assertEqual((wrong.status_code, unknown.status_code), (401, 401))
        self.assertEqual(wrong.get_json(), unknown.get_json())

    def test_register_validation(self):
        self.assertEqual(self.register(password="short").status_code, 400)
        self.assertEqual(self.register(email="not-an-email").status_code, 400)
        self.assertEqual(self.register(full_name="").status_code, 400)

    def test_registration_is_limited_to_ten_accounts(self):
        self.assertEqual(self.register().status_code, 201)
        for index in range(9):
            self.assertIsNotNone(database.create_user(
                f"Analyst {index}",
                f"{uuid.uuid4().hex}@example.test",
                "",
                "test-password-hash",
            ))

        response = self.client.post("/api/auth/register", json={
            "full_name": "Eleventh Analyst",
            "email": f"{uuid.uuid4().hex}@example.test",
            "password": "correct-horse-battery",
        })
        self.assertEqual(response.status_code, 403)
        self.assertIn("50 accounts", response.get_json()["error"])

    def test_protected_routes_require_login(self):
        for path in ("/api/stats", "/api/alerts", "/api/events", "/api/activity", "/api/integrations/keys"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)

    def test_frontend_files_are_not_rate_limited(self):
        limiter.enabled = True
        for _ in range(130):  # above the 120/hour default API limit
            response = self.client.get("/login.html")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Frame-Options"], "SAMEORIGIN")
        self.assertEqual(self.client.get("/api/health").headers["X-Frame-Options"], "DENY")

    def test_unknown_api_route_returns_json_404(self):
        response = self.client.get("/api/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertFalse(response.get_json()["success"])


class IngestionTests(unittest.TestCase):
    def setUp(self):
        disable_rate_limits(self)
        self.client = client_for(new_user())
        created = self.client.post("/api/integrations/keys", json={"name": "web-01"}, headers=WRITE)
        self.assertEqual(created.status_code, 201)
        self.key = created.get_json()["api_key"]

    def ingest(self, events, key=None):
        return app.test_client().post("/api/events/ingest", json={"events": events},
                                      headers={"Authorization": f"Bearer {key or self.key['key']}"})

    def test_ingest_scores_dedupes_and_creates_alerts(self):
        batch = [{"external_id": "e-1", "event_data": SQLI}, {"external_id": "e-2", "event_data": "Health check OK"}]
        first = self.ingest(batch).get_json()
        self.assertEqual((first["accepted"], first["duplicates"], first["alerts_created"]), (2, 0, 1))
        self.assertEqual(first["results"][0]["matched_rules"], ["SQL_INJECTION"])

        again = self.ingest(batch).get_json()
        self.assertEqual((again["accepted"], again["duplicates"]), (0, 2))

        events = self.client.get("/api/events").get_json()
        self.assertEqual(events["pagination"]["total"], 2)
        self.assertEqual(events["events"][0]["source"], "web-01")  # defaults to the key name

    def test_invalid_batch_is_rejected_without_partial_import(self):
        response = self.ingest([{"event_data": SQLI}, {"event_data": ""}])
        self.assertEqual(response.status_code, 400)
        self.assertIn("events[1]", response.get_json()["error"])
        self.assertEqual(self.client.get("/api/events").get_json()["pagination"]["total"], 0)

    def test_revoked_or_missing_key_is_refused(self):
        self.assertEqual(self.ingest([{"event_data": SQLI}], key="cs_live_unknown").status_code, 401)
        self.client.delete(f"/api/integrations/keys/{self.key['id']}", headers=WRITE)
        self.assertEqual(self.ingest([{"event_data": SQLI}]).status_code, 401)
        listed = self.client.get("/api/integrations/keys").get_json()["api_keys"]
        self.assertIsNotNone(listed[0]["revoked_at"])
        self.assertNotIn("key", listed[0])  # raw key is never listed


class AlertWorkflowTests(unittest.TestCase):
    def setUp(self):
        disable_rate_limits(self)
        self.client = client_for(new_user())
        result = self.client.post("/api/assess-risk", json={"event_data": SQLI, "event_type": "request"}, headers=WRITE)
        self.alert_id = result.get_json()["alert_id"]
        self.assertIsNotNone(self.alert_id)

    def patch(self, body, client=None):
        return (client or self.client).patch(f"/api/alerts/{self.alert_id}", json=body, headers=WRITE)

    def status(self):
        alerts = self.client.get("/api/alerts").get_json()["alerts"]
        return next(alert["status"] for alert in alerts if alert["id"] == self.alert_id)

    def test_full_triage_flow_with_history(self):
        self.assertEqual(self.patch({"status": "Acknowledged"}).status_code, 200)
        self.assertEqual(self.patch({"status": "In Progress"}).status_code, 200)
        self.assertEqual(self.patch({"status": "Resolved"}).status_code, 400)  # note required
        self.assertEqual(self.patch({"status": "Resolved", "resolution_note": "Blocked IP"}).status_code, 200)
        self.assertEqual(self.status(), "Resolved")
        self.assertEqual(self.patch({"status": "In Progress"}).status_code, 409)  # only reopen allowed
        self.assertEqual(self.patch({"status": "Open"}).status_code, 200)

        activity = self.client.get(f"/api/alerts/{self.alert_id}/activity").get_json()["activity"]
        transitions = [(a["details"].get("from"), a["details"].get("to")) for a in activity if a["action"] == "status_changed"]
        self.assertEqual(transitions[0], ("Resolved", "Open"))
        self.assertEqual(len(transitions), 4)

    def test_read_flag_and_filters(self):
        self.assertEqual(self.client.get("/api/alerts?is_read=false").get_json()["pagination"]["total"], 1)
        self.patch({"is_read": True})
        self.assertEqual(self.client.get("/api/alerts?is_read=false").get_json()["pagination"]["total"], 0)
        self.assertEqual(self.client.get("/api/alerts?status=Bogus").status_code, 400)
        self.assertEqual(self.client.get("/api/alerts?risk_level=medium").status_code, 200)

    def test_archive_hides_alert_but_keeps_history(self):
        self.assertEqual(self.client.delete(f"/api/alerts/{self.alert_id}", headers=WRITE).status_code, 200)
        self.assertEqual(self.client.get("/api/alerts").get_json()["pagination"]["total"], 0)
        self.assertEqual(self.client.delete(f"/api/alerts/{self.alert_id}", headers=WRITE).status_code, 404)

    def test_other_accounts_cannot_see_or_change_the_alert(self):
        other = client_for(new_user("Someone Else"))
        self.assertEqual(other.get("/api/alerts").get_json()["pagination"]["total"], 0)
        self.assertEqual(self.patch({"status": "Acknowledged"}, client=other).status_code, 404)
        self.assertEqual(other.get(f"/api/alerts/{self.alert_id}/activity").status_code, 404)
        self.assertEqual(other.delete(f"/api/alerts/{self.alert_id}", headers=WRITE).status_code, 404)
        self.assertEqual(self.status(), "Open")


if __name__ == "__main__":
    unittest.main()
