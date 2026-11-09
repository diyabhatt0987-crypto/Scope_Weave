"""Exercise the live ZAP result conversion without contacting ZAP or a target."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server  # noqa: E402


class ZapResultTests(unittest.TestCase):
    def test_live_alerts_preserve_request_details_and_optional_evidence(self):
        origin = "http://127.0.0.1:3000"
        alerts = [
            {
                "name": "Cookie Alert",
                "description": "ZAP supplied this description.",
                "url": f"{origin}/account?tab=profile",
                "method": "GET",
                "param": "session",
                "evidence": "session=example",
                "risk": "Medium",
            },
            {
                "name": "Content Security Policy Header Not Set",
                "description": "ZAP reported a missing response header.",
                "url": f"{origin}/login",
                "method": "GET",
                "evidence": "",
            },
            {"name": "Alert without an affected URL"},
        ]
        job = {"state": "starting"}
        responses = [{"status": "100"}, {"recordsToScan": "0"}, {"alerts": alerts}, {}]
        with patch.object(server, "JOBS", {"test-job": job}), \
                patch.object(server, "zap_api", side_effect=responses):
            server.scan_worker("test-job", origin, "test-context", "0")

        self.assertEqual(job["state"], "completed")
        self.assertEqual(job["alert_count"], 2)
        self.assertTrue(job["partial"])
        first, missing_header = job["report"]["site"][0]["alerts"]
        self.assertEqual(first["desc"], alerts[0]["description"])
        self.assertEqual(first["instances"], [{
            "uri": alerts[0]["url"],
            "method": "GET",
            "param": "session",
            "evidence": "session=example",
        }])
        self.assertEqual(missing_header["desc"], alerts[1]["description"])
        self.assertEqual(missing_header["instances"][0]["uri"], alerts[1]["url"])
        self.assertEqual(missing_header["instances"][0]["method"], "GET")
        self.assertEqual(missing_header["instances"][0]["evidence"], "")
