"""Startup regressions tested without opening sockets, browsers, or credentials."""

import io
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server  # noqa: E402


class StartupTests(unittest.TestCase):
    def assert_failed_bind_is_not_reported_ready(self, error, expected_error):
        output = io.StringIO()
        errors = io.StringIO()
        with patch.object(sys, "argv", ["server.py", "--open-browser"]), \
                patch.object(sys, "stdout", output), \
                patch.object(sys, "stderr", errors), \
                patch.object(server, "ThreadingHTTPServer", side_effect=error), \
                patch.object(server.threading, "Timer") as timer, \
                patch.object(server.webbrowser, "open") as open_browser:
            with self.assertRaises(SystemExit) as raised:
                server.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertNotIn("is available at", output.getvalue())
        self.assertIn(expected_error, errors.getvalue())
        timer.assert_not_called()
        open_browser.assert_not_called()

    def test_occupied_port_does_not_claim_ready_or_schedule_browser(self):
        self.assert_failed_bind_is_not_reported_ready(
            OSError(98, "Address already in use"), "already in use",
        )

    def test_other_bind_failure_does_not_claim_ready_or_schedule_browser(self):
        self.assert_failed_bind_is_not_reported_ready(
            OSError(13, "Permission denied"), "could not start its local server",
        )

    def test_browser_is_scheduled_only_after_successful_bind_and_server_closes(self):
        events = []
        local_server = MagicMock()
        local_server.serve_forever.side_effect = KeyboardInterrupt
        browser_timer = MagicMock()
        browser_timer.start.side_effect = lambda: events.append("start-browser-timer")

        def bind(*_args):
            events.append("bind")
            return local_server

        def make_timer(*_args):
            events.append("schedule-browser")
            return browser_timer

        output = io.StringIO()
        with patch.object(sys, "argv", ["server.py", "--open-browser"]), \
                patch.object(sys, "stdout", output), \
                patch.object(server, "ThreadingHTTPServer", side_effect=bind) as http_server, \
                patch.object(server.threading, "Timer", side_effect=make_timer) as timer, \
                patch.object(server.webbrowser, "open") as open_browser:
            server.main()
        self.assertEqual(events, ["bind", "schedule-browser", "start-browser-timer"])
        http_server.assert_called_once_with((server.ADDRESS, server.PORT), server.LocalOnlyHandler)
        self.assertEqual(timer.call_args.args[0], 0.5)
        self.assertTrue(browser_timer.daemon)
        self.assertIn(f"is available at http://{server.ADDRESS}:{server.PORT}/", output.getvalue())
        self.assertIn("Keep this window open", output.getvalue())
        local_server.serve_forever.assert_called_once()
        local_server.server_close.assert_called_once()
        open_browser.assert_not_called()

    def test_default_cli_does_not_open_browser_and_still_closes_server(self):
        local_server = MagicMock()
        with patch.object(sys, "argv", ["server.py"]), \
                patch.object(sys, "stdout", io.StringIO()), \
                patch.object(server, "ThreadingHTTPServer", return_value=local_server), \
                patch.object(server.threading, "Timer") as timer, \
                patch.object(server.webbrowser, "open") as open_browser:
            server.main()
        local_server.serve_forever.assert_called_once()
        local_server.server_close.assert_called_once()
        timer.assert_not_called()
        open_browser.assert_not_called()

    def test_browser_failure_prints_manual_url_without_stopping_server_startup(self):
        local_server = MagicMock()
        output = io.StringIO()
        with patch.object(sys, "argv", ["server.py", "--open-browser"]), \
                patch.object(sys, "stdout", output), \
                patch.object(server, "ThreadingHTTPServer", return_value=local_server), \
                patch.object(server.threading, "Timer") as timer, \
                patch.object(server.webbrowser, "open", side_effect=OSError("No desktop browser")):
            server.main()
            timer.call_args.args[1]()
        self.assertIn(f"Open http://{server.ADDRESS}:{server.PORT}/", output.getvalue())
        local_server.server_close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
