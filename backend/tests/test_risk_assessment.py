import atexit
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

test_database = tempfile.TemporaryDirectory(prefix="cyber-sentinel-risk-tests-")
original_database = os.environ.get("CYBER_SENTINEL_DB")
os.environ["CYBER_SENTINEL_DB"] = str(Path(test_database.name) / "security.db")
from backend import app as app_module
if original_database is None:
    os.environ.pop("CYBER_SENTINEL_DB", None)
else:
    os.environ["CYBER_SENTINEL_DB"] = original_database
atexit.register(test_database.cleanup)


class RiskAssessmentApiTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()
        with self.client.session_transaction() as session:
            session["user_id"] = 7
            session["csrf_token"] = "test-csrf-token"
        self.auth_patch = patch.object(
            app_module, "get_user_by_id", return_value={"id": 7, "is_active": 1}
        )
        self.auth_patch.start()
        self.addCleanup(self.auth_patch.stop)

    def post_assessment(self, payload):
        return self.client.post(
            "/api/assess-risk",
            json=payload,
            headers={"X-CSRF-Token": "test-csrf-token"},
        )

    def test_detected_event_returns_findings_and_saves_alert(self):
        with patch.object(
            app_module, "record_event",
            return_value={"event_id": 41, "alert_id": 19, "duplicate": False},
        ) as record_event:
            response = self.post_assessment({
                "event_data": "Multiple failed login attempts detected",
                "event_type": "log",
            })

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        result = body["result"]
        self.assertTrue(body["success"])
        self.assertEqual((body["event_id"], body["alert_id"]), (41, 19))
        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["matched_rules"], ["BRUTE_FORCE"])
        self.assertEqual(result["findings"][0]["category"], "Authentication")
        self.assertTrue(result["findings"][0]["remediation"])
        record_event.assert_called_once()
        self.assertEqual(record_event.call_args.args[0:4], (7, "manual-ui", "manual_log", None))

    def test_clean_event_is_saved_without_creating_alert(self):
        with patch.object(
            app_module, "record_event",
            return_value={"event_id": 42, "alert_id": None, "duplicate": False},
        ) as record_event:
            response = self.post_assessment({
                "event_data": "Scheduled maintenance completed successfully.",
            })

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["result"]["risk_score"], 0)
        self.assertEqual(body["result"]["risk_level"], "LOW")
        self.assertEqual(body["alert_id"], None)
        record_event.assert_called_once()

    def test_invalid_assessment_inputs_are_rejected(self):
        for payload in (
            {"event_data": "   "},
            {"event_data": "valid event", "event_type": "unknown"},
            {"event_data": "x" * 10001},
        ):
            with self.subTest(payload_keys=tuple(payload)):
                response = self.post_assessment(payload)
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()["success"])


if __name__ == "__main__":
    unittest.main()
