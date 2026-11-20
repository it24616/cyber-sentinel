import unittest

from backend.tests.support import CSRF, app, client_for, disable_rate_limits, new_user
from backend import database
from backend.detection import assess_risk



class DashboardDataTests(unittest.TestCase):
    """Uses the real SQLite layer so stats, posture and activity are checked end to end."""

    def setUp(self):
        disable_rate_limits(self)
        self.user_id = new_user("Dash Tester")
        self.client = client_for(self.user_id)

    def record(self, text, source="test-source"):
        return database.record_event(self.user_id, source, "log", None, text,
                                     "2026-01-01T00:00:00+00:00", assess_risk(text))

    def stats(self, client=None):
        response = (client or self.client).get("/api/stats")
        self.assertEqual(response.status_code, 200)
        return response.get_json()["stats"]

    def test_empty_account_is_clear_with_seven_zero_days(self):
        stats = self.stats()
        self.assertEqual(stats["posture"], "CLEAR")
        self.assertIsNone(stats["last_event_at"])
        self.assertEqual(len(stats["daily"]), 7)
        self.assertTrue(all(bucket["count"] == 0 for bucket in stats["daily"]))

    def test_posture_follows_highest_open_alert(self):
        self.record("Multiple failed login attempts detected")            # MEDIUM (30)
        critical = self.record("id=1' UNION SELECT password FROM users-- ${jndi:ldap://x/a}")
        self.record("Scheduled maintenance completed successfully.")      # no alert

        stats = self.stats()
        self.assertEqual(stats["posture"], "CRITICAL")
        self.assertEqual(stats["open_by_risk_level"]["CRITICAL"], 1)
        self.assertEqual(stats["open_by_risk_level"]["MEDIUM"], 1)
        self.assertEqual(stats["daily"][-1]["count"], 2)  # today, events with indicators only
        self.assertIsNotNone(stats["last_event_at"])

        response = self.client.patch(f"/api/alerts/{critical['alert_id']}",
                                     json={"status": "Resolved", "resolution_note": "Blocked at WAF"},
                                     headers={"X-CSRF-Token": CSRF})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.stats()["posture"], "MEDIUM")

    def test_activity_feed_is_newest_first_and_account_scoped(self):
        saved = self.record("Multiple failed login attempts detected")
        self.client.patch(f"/api/alerts/{saved['alert_id']}", json={"is_read": True},
                          headers={"X-CSRF-Token": CSRF})

        response = self.client.get("/api/activity?limit=5")
        self.assertEqual(response.status_code, 200)
        activity = response.get_json()["activity"]
        self.assertEqual([item["action"] for item in activity[:2]], ["marked_read", "created"])
        self.assertEqual(activity[1]["details"]["source"], "test-source")
        self.assertEqual(activity[1]["risk_level"], "MEDIUM")

        other = client_for(new_user())
        self.assertEqual(other.get("/api/activity").get_json()["activity"], [])
        self.assertEqual(self.stats(other)["posture"], "CLEAR")

    def test_activity_limit_must_be_integer(self):
        self.assertEqual(self.client.get("/api/activity?limit=abc").status_code, 400)


if __name__ == "__main__":
    unittest.main()
