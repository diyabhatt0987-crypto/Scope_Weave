"""Groq contract and local endpoint tests; no external requests or real keys."""

import copy
from email.message import Message
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server  # noqa: E402


FINDING_ID = "F-00000001"
OPTIONS = {"review_existing_evidence": "Review imported evidence"}
DUMMY_KEY = "gsk_dummy_for_unit_tests_only"


def valid_analysis():
    return {
        "next_step": "review_existing_evidence",
        "reason": "Review the response evidence supplied for the selected lab.",
        "summary": "The supplied report contains one scanner observation needing human review.",
        "observations": [{
            "finding_id": FINDING_ID,
            "explanation": "The scanner reported a response configuration observation; it remains unvalidated.",
            "next_review": "Check the original response and the approved application's configuration.",
        }],
        "limitations": ["The provided excerpt does not independently confirm exploitability."],
    }


def api_response(data):
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = json.dumps({
        "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(data)}}],
    }).encode("utf-8")
    return response


class AnalysisValidationTests(unittest.TestCase):
    def validate(self, value, evidence_ids=None):
        return server.validate_groq_analysis(
            value, OPTIONS, {FINDING_ID} if evidence_ids is None else evidence_ids,
        )

    def test_valid_analysis_preserves_grounded_observation(self):
        result = self.validate(valid_analysis())
        self.assertEqual(result["suggestion"]["next_step"], "review_existing_evidence")
        self.assertEqual(result["analysis"]["observations"][0]["finding_id"], FINDING_ID)

    def test_action_outside_saved_permissions_is_rejected(self):
        value = valid_analysis()
        value["next_step"] = "run_zap_passive_crawl"
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_invented_evidence_reference_is_rejected(self):
        value = valid_analysis()
        value["observations"][0]["finding_id"] = "FND-not-supplied"
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_duplicate_evidence_reference_is_rejected(self):
        value = valid_analysis()
        value["observations"].append(copy.deepcopy(value["observations"][0]))
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_absent_evidence_cannot_produce_observations(self):
        with self.assertRaises(ValueError):
            self.validate(valid_analysis(), evidence_ids=set())
        value = valid_analysis()
        value["observations"] = []
        self.assertEqual(self.validate(value, evidence_ids=set())["analysis"]["observations"], [])

    def test_missing_and_additional_fields_are_rejected(self):
        mutations = []
        missing_summary = valid_analysis()
        del missing_summary["summary"]
        mutations.append(missing_summary)
        extra_top_level = valid_analysis()
        extra_top_level["execute"] = "scan"
        mutations.append(extra_top_level)
        extra_observation_field = valid_analysis()
        extra_observation_field["observations"][0]["confirmed"] = True
        mutations.append(extra_observation_field)
        for value in mutations:
            with self.subTest(keys=list(value)):
                with self.assertRaises(ValueError):
                    self.validate(value)

    def test_invalid_text_and_excessive_output_are_rejected(self):
        values = []
        for key, replacement in (("reason", "short"), ("summary", "s" * 1201),
                                 ("observations", {}), ("limitations", ["short"]),
                                 ("limitations", ["Valid limitation text."] * 6)):
            value = valid_analysis()
            value[key] = replacement
            values.append((key, value))
        for key, value in values:
            with self.subTest(field=key):
                with self.assertRaises(ValueError):
                    self.validate(value)


class GroqTransportTests(unittest.TestCase):
    def call(self):
        return server.call_groq_planner(
            "openai/gpt-oss-120b", "Only synthetic evidence for a unit test.", OPTIONS, {FINDING_ID},
        )

    @patch.dict("os.environ", {"GROQ_API_KEY": ""})
    @patch.object(server, "build_opener")
    def test_missing_key_never_calls_remote_service(self, build_opener):
        with self.assertRaises(RuntimeError):
            self.call()
        build_opener.assert_not_called()

    @patch.dict("os.environ", {"GROQ_API_KEY": DUMMY_KEY})
    @patch.object(server, "build_opener")
    def test_success_uses_fixed_host_auth_and_structured_output(self, build_opener):
        opener = build_opener.return_value
        opener.open.return_value = api_response(valid_analysis())
        result = self.call()
        self.assertEqual(result["analysis"]["observations"][0]["finding_id"], FINDING_ID)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + DUMMY_KEY)
        self.assertEqual(request.get_header("User-agent"), "ScopeWeave/1.0")
        self.assertNotIn(DUMMY_KEY, request.full_url)
        self.assertNotIn(DUMMY_KEY, request.data.decode("utf-8"))
        body = json.loads(request.data)
        self.assertEqual(body["model"], "openai/gpt-oss-120b")
        self.assertEqual(body["response_format"]["type"], "json_schema")
        timeout = opener.open.call_args.kwargs["timeout"]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 60)

    @patch.dict("os.environ", {"GROQ_API_KEY": DUMMY_KEY})
    @patch.object(server, "build_opener")
    def test_auth_and_rate_limit_failures_do_not_leak_provider_body_or_key(self, build_opener):
        for status, expected_detail in (
            (401, "could not authenticate"),
            (403, "denied this request"),
            (429, "request or token limit"),
            (500, "temporarily unavailable"),
        ):
            with self.subTest(status=status):
                error_body = ("provider-private-detail " + DUMMY_KEY).encode("utf-8")
                build_opener.return_value.open.side_effect = HTTPError(
                    "https://api.groq.com/openai/v1/chat/completions", status,
                    "Provider error", {}, io.BytesIO(error_body),
                )
                with self.assertRaises(RuntimeError) as raised:
                    self.call()
                self.assertIn(expected_detail, str(raised.exception))
                self.assertNotIn(DUMMY_KEY, str(raised.exception))
                self.assertNotIn("provider-private-detail", str(raised.exception))

    @patch.dict("os.environ", {"GROQ_API_KEY": DUMMY_KEY})
    @patch.object(server, "build_opener")
    def test_network_failure_is_reported_without_raw_error_details(self, build_opener):
        build_opener.return_value.open.side_effect = URLError("private-network-info " + DUMMY_KEY)
        with self.assertRaises(RuntimeError) as raised:
            self.call()
        self.assertNotIn("private-network-info", str(raised.exception))
        self.assertNotIn(DUMMY_KEY, str(raised.exception))

    @patch.dict("os.environ", {"GROQ_API_KEY": DUMMY_KEY})
    @patch.object(server, "build_opener")
    def test_invalid_model_output_never_becomes_valid_analysis(self, build_opener):
        value = valid_analysis()
        value["observations"][0]["finding_id"] = "FND-invented"
        build_opener.return_value.open.return_value = api_response(value)
        with self.assertRaises(RuntimeError):
            self.call()

    @patch.dict("os.environ", {"GROQ_API_KEY": DUMMY_KEY})
    @patch.object(server, "build_opener")
    def test_incomplete_generation_is_not_accepted(self, build_opener):
        response = api_response(valid_analysis())
        response.read.return_value = json.dumps({
            "choices": [{"finish_reason": "length", "message": {"content": json.dumps(valid_analysis())}}],
        }).encode("utf-8")
        build_opener.return_value.open.return_value = response
        with self.assertRaises(RuntimeError):
            self.call()

    @patch.dict("os.environ", {"GROQ_API_KEY": DUMMY_KEY})
    @patch.object(server, "build_opener")
    def test_redirect_handler_does_not_forward_authenticated_request(self, build_opener):
        build_opener.return_value.open.return_value = api_response(valid_analysis())
        self.call()
        redirect_handlers = [
            handler for handler in build_opener.call_args.args
            if isinstance(handler, HTTPRedirectHandler)
        ]
        self.assertTrue(redirect_handlers, "Groq requests must explicitly disable HTTP redirects.")
        request = Request("https://api.groq.com/openai/v1/chat/completions")
        request.add_header("Authorization", "Bearer " + DUMMY_KEY)
        try:
            redirected = redirect_handlers[0].redirect_request(
                request, None, 307, "Temporary Redirect", {}, "https://untrusted.example.test/",
            )
        except HTTPError:
            redirected = None
        self.assertIsNone(redirected)


class PlannerEndpointTests(unittest.TestCase):
    """Exercise the actual handler in memory, with no socket or external service."""

    def payload(self):
        return {
            "provider": "groq", "cloudConsent": True,
            "scope": {
                "origin": "https://approved.example.test",
                "environment": "organizer-designated-lab", "attested": True,
                "approvalReference": "test-authorization-reference-do-not-send",
                "permissions": ["Web checks", "Scanner result import"],
                "exclusions": ["/excluded"],
            },
            "request": "Explain only the supplied scanner observation.",
            "evidence": [{
                "id": FINDING_ID, "title": "Response header observation",
                "asset": "https://approved.example.test/login", "sources": ["OWASP ZAP"],
                "severity": "Low", "cvss": None, "summary": "A synthetic source observation.",
                "validation": "Scanner-reported; unvalidated",
                "source_reports": [{
                    "tool": "OWASP ZAP", "severity": "Low", "cvss": None,
                    "excerpt": "Synthetic excerpt from a unit-test source.",
                }],
            }],
        }

    def post(self, payload, origin=None):
        body = json.dumps(payload).encode("utf-8")
        handler = object.__new__(server.LocalOnlyHandler)
        handler.path = "/api/planner/suggest"
        handler.headers = Message()
        handler.headers["Origin"] = origin or f"http://127.0.0.1:{server.PORT}"
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = str(len(body))
        handler.rfile = io.BytesIO(body)
        handler.send_json = lambda data, status=200: (status, data)
        return handler.do_POST()

    @patch.object(server, "call_local_planner")
    @patch.object(server, "call_groq_planner", create=True)
    def test_cloud_consent_must_be_explicit_boolean(self, groq, local):
        for consent in (False, None, "true", 1):
            with self.subTest(consent=consent):
                payload = self.payload()
                payload["cloudConsent"] = consent
                status, _body = self.post(payload)
                self.assertIn(status, (400, 403))
        groq.assert_not_called()
        local.assert_not_called()

    @patch.object(server, "call_local_planner")
    @patch.object(server, "call_groq_planner", create=True)
    def test_untrusted_origin_and_invalid_scope_never_call_models(self, groq, local):
        status, _body = self.post(self.payload(), origin="https://untrusted.example.test")
        self.assertEqual(status, 403)
        payload = self.payload()
        payload["scope"]["attested"] = False
        status, _body = self.post(payload)
        self.assertEqual(status, 400)
        groq.assert_not_called()
        local.assert_not_called()

    @patch.object(server, "call_local_planner")
    @patch.object(server, "call_groq_planner", create=True)
    def test_unknown_provider_never_silently_uses_another_model(self, groq, local):
        payload = self.payload()
        payload["provider"] = "unrecognized-provider"
        status, _body = self.post(payload)
        self.assertEqual(status, 400)
        groq.assert_not_called()
        local.assert_not_called()

    @patch.dict("os.environ", {"GROQ_MODEL": "openai/gpt-oss-120b"})
    @patch.object(server, "call_local_planner")
    @patch.object(server, "call_groq_planner")
    def test_success_sends_bounded_source_context_without_authorization_reference(self, groq, local):
        groq.return_value = server.validate_groq_analysis(valid_analysis(), OPTIONS, {FINDING_ID})
        payload = self.payload()
        payload["evidence"][0]["summary"] = "s" * 500
        payload["evidence"][0]["source_reports"] *= 4
        for report in payload["evidence"][0]["source_reports"]:
            report["excerpt"] = "e" * 500
        payload["tool_coverage"] = [{"tool": "OWASP ZAP", "status": "usable"}]
        payload["evidence"][0]["review_status"] = "false_positive"
        payload["evidence"][0]["review_reason"] = "private-review-reason"
        payload["evidence"][0]["review_evidence"] = "private-review-evidence"
        payload["evidence"][0]["extra_not_for_model"] = "not-forwarded"
        status, body = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["mode"], "groq")
        self.assertEqual(body["evidence_count"], 1)
        self.assertEqual(body["analysis"]["observations"][0]["finding_id"], FINDING_ID)
        model_input = groq.call_args.args[1]
        self.assertNotIn(payload["scope"]["approvalReference"], model_input)
        self.assertNotIn("not-forwarded", model_input)
        self.assertNotIn("private-review-", model_input)
        model_payload = json.loads(model_input)
        self.assertEqual(model_payload["tool_coverage"], payload["tool_coverage"])
        evidence = model_payload["evidence_summaries"][0]
        self.assertEqual(evidence["review_status"], "false_positive")
        self.assertEqual(len(evidence["summary"]), 240)
        self.assertEqual(len(evidence["source_reports"]), 3)
        self.assertTrue(all(len(report["excerpt"]) == 180 for report in evidence["source_reports"]))
        self.assertEqual(groq.call_args.args[3], {FINDING_ID})
        local.assert_not_called()

    @patch.object(server, "call_local_planner")
    @patch.object(server, "call_groq_planner")
    def test_duplicate_or_excessive_evidence_is_rejected_before_network(self, groq, local):
        for count in (2, 11):
            with self.subTest(count=count):
                payload = self.payload()
                payload["evidence"] *= count
                status, _body = self.post(payload)
                self.assertEqual(status, 400)
        groq.assert_not_called()
        local.assert_not_called()

    @patch.object(server, "call_local_planner")
    @patch.object(server, "call_groq_planner")
    def test_invalid_adaptive_context_is_rejected_before_model_calls(self, groq, local):
        scanner = {"tool": "OWASP ZAP", "status": "usable"}
        for invalid in (None, [scanner, scanner], [scanner] * 7,
                        [{"tool": "other", "status": "usable"}],
                        [{**scanner, "status": "invented"}], [{**scanner, "note": "private"}]):
            with self.subTest(coverage=invalid):
                payload = self.payload()
                payload["tool_coverage"] = invalid
                status, _body = self.post(payload)
                self.assertEqual(status, 400)
        payload = self.payload()
        payload["provider"] = "ollama"
        payload["evidence"][0]["review_status"] = "unknown"
        status, _body = self.post(payload)
        self.assertEqual(status, 400)
        groq.assert_not_called()
        local.assert_not_called()

    @patch.dict("os.environ", {"GROQ_MODEL": "openai/gpt-oss-120b"})
    @patch.object(server, "call_local_planner")
    @patch.object(server, "call_groq_planner")
    def test_cloud_failure_is_explicit_and_does_not_call_local_provider(self, groq, local):
        groq.side_effect = RuntimeError("Groq's request or token limit was reached.")
        status, body = self.post(self.payload())
        self.assertEqual(status, 503)
        self.assertEqual(body["mode"], "fallback")
        self.assertIn("limit", body["error"])
        self.assertNotIn("analysis", body)
        local.assert_not_called()

    @patch.dict("os.environ", {"OLLAMA_MODEL": "qwen2.5:3b"})
    @patch.object(server, "call_local_planner")
    @patch.object(server, "call_groq_planner")
    def test_existing_default_local_flow_never_sends_cloud_request(self, groq, local):
        local.return_value = {
            "next_step": "review_existing_evidence", "reason": valid_analysis()["reason"], "attempts": 1,
        }
        payload = self.payload()
        del payload["provider"]
        del payload["cloudConsent"]
        status, body = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["mode"], "ollama")
        local.assert_called_once()
        model_payload = json.loads(local.call_args.args[1])
        self.assertEqual(model_payload["tool_coverage"], [])
        self.assertNotIn("review_status", model_payload["evidence_summaries"][0])
        groq.assert_not_called()


if __name__ == "__main__":
    unittest.main()
