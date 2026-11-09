"""Personal practice lab authorization boundaries; no network or real credentials."""

import copy
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server  # noqa: E402


def local_scope(origin="http://127.0.0.1:3000"):
    return {
        "environment": "self-owned-local-lab",
        "origin": origin,
        "attested": True,
        "approvalReference": "Self-owned local Juice Shop practice lab",
        "permissions": ["Web checks", "Scanner result import"],
        "exclusions": ["/private/"],
    }


class LocalScopeTests(unittest.TestCase):
    def assert_rejected_by_both_flows(self, scope):
        for validate in (server.validate_scope, server.validate_planner_scope):
            with self.subTest(flow=validate.__name__):
                with self.assertRaises(ValueError):
                    validate(scope)

    def test_personal_loopback_origins_are_accepted_and_canonicalized(self):
        origins = {
            "http://127.0.0.1:3000": "http://127.0.0.1:3000",
            "http://localhost:3000/": "http://localhost:3000",
            "HTTP://LOCALHOST:3000": "http://localhost:3000",
            "http://[::1]:3000": "http://[::1]:3000",
            "https://localhost:443": "https://localhost",
        }
        for supplied, expected in origins.items():
            with self.subTest(origin=supplied):
                scope = local_scope(supplied)
                self.assertEqual(server.validate_scope(scope), (expected, ["/private"]))
                self.assertEqual(
                    server.validate_planner_scope(scope),
                    (expected, ["/private"], {"Web checks", "Scanner result import"}),
                )

    def test_public_owasp_pages_and_other_hosts_cannot_claim_local_ownership(self):
        origins = (
            "https://owasp.org/projects/juice-shop",
            "https://owasp.org",
            "https://demo.owasp-juice.shop",
            "http://192.168.1.5:3000",
            "http://127.0.0.1.example.test:3000",
            "http://localhost.example.test:3000",
            "http://localhost.:3000",
            "http://127.1:3000",
            "http://[::ffff:127.0.0.1]:3000",
        )
        for origin in origins:
            with self.subTest(origin=origin):
                self.assert_rejected_by_both_flows(local_scope(origin))

    def test_authorization_must_be_explicit_not_a_truthy_value(self):
        for attested in (False, None, 1, "true"):
            with self.subTest(attested=attested):
                scope = local_scope()
                scope["attested"] = attested
                self.assert_rejected_by_both_flows(scope)

    def test_local_mode_keeps_required_reference(self):
        for reference in (None, "", "  ", "x" * 161):
            with self.subTest(reference=reference):
                scope = local_scope()
                scope["approvalReference"] = reference
                self.assert_rejected_by_both_flows(scope)

    def test_local_mode_keeps_exclusion_gates(self):
        for exclusions in (["/"], ["https://example.test/private"], ["/private?query=yes"], "private"):
            with self.subTest(exclusions=exclusions):
                scope = local_scope()
                scope["exclusions"] = exclusions
                self.assert_rejected_by_both_flows(scope)

    def test_local_scan_requires_existing_web_and_import_permissions(self):
        for permissions in ([], ["Web checks"], ["Scanner result import"], ["Network diagnostics"]):
            with self.subTest(permissions=permissions):
                scope = local_scope()
                scope["permissions"] = permissions
                with self.assertRaises(ValueError):
                    server.validate_scope(scope)
        scope = local_scope()
        scope["permissions"] = ["Network diagnostics"]
        self.assertEqual(server.validate_planner_scope(scope)[2], {"Network diagnostics"})

    def test_planner_still_rejects_unknown_permissions(self):
        scope = local_scope()
        scope["permissions"].append("Unapproved action")
        with self.assertRaises(ValueError):
            server.validate_planner_scope(scope)

    def test_legacy_organizer_scopes_are_preserved_without_loopback_restriction(self):
        scope = local_scope("https://approved-lab.example.test")
        scope["environment"] = "organizer-designated-lab"
        scope["approvalReference"] = "Organizer lab approval reference"
        self.assertEqual(server.validate_scope(scope), (scope["origin"], ["/private"]))
        self.assertEqual(server.validate_planner_scope(scope)[0], scope["origin"])
        unapproved = copy.deepcopy(scope)
        unapproved["attested"] = False
        self.assert_rejected_by_both_flows(unapproved)

    def test_unknown_authorization_basis_is_rejected(self):
        for environment in (None, "local", "owner", ["self-owned-local-lab"]):
            with self.subTest(environment=environment):
                scope = local_scope()
                scope["environment"] = environment
                self.assert_rejected_by_both_flows(scope)


if __name__ == "__main__":
    unittest.main()
