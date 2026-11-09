import io
import json
import os
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import server


def pdf_with_title(title):
    return b"%PDF-1.7\n1 0 obj\n<< /Title " + title + b" >>\nendobj\n%%EOF\n"


class SavedPdfTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(dir=server.ROOT.parent)
        self.addCleanup(directory.cleanup)
        self.downloads = Path(directory.name)
        self.report = pdf_with_title(b"(VAPT Assessment Report)")
        self.private = pdf_with_title(b"(Private document)")
        (self.downloads / "renamed.pdf").write_bytes(self.report)
        (self.downloads / "private.pdf").write_bytes(self.private)

    def request(self, path, *, host=None, origin=None, payload=None):
        handler = server.LocalOnlyHandler.__new__(server.LocalOnlyHandler)
        handler.path = path
        handler.headers = Message()
        handler.headers["Host"] = host or f"127.0.0.1:{server.PORT}"
        if origin is not None:
            handler.headers["Origin"] = origin
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            handler.headers["Content-Type"] = "application/json"
            handler.headers["Content-Length"] = str(len(body))
            handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        with patch.object(server, "saved_pdf_directory", return_value=self.downloads):
            handler.do_POST()
        return handler

    def test_list_uses_metadata_and_only_direct_downloads(self):
        second = self.downloads / "newest.PDF"
        utf16 = b"\xfe\xff" + "ScopeWeave VAPT Assessment Report".encode("utf-16-be")
        second.write_bytes(pdf_with_title(b"<" + utf16.hex().encode("ascii") + b">"))
        os.utime(self.downloads / "renamed.pdf", (1_700_000_000, 1_700_000_000))
        os.utime(second, (1_700_000_001, 1_700_000_001))
        (self.downloads / "invalid.pdf").write_bytes(b"/Title (VAPT Assessment Report)")
        nested = self.downloads / "folder"
        nested.mkdir()
        (nested / "nested.pdf").write_bytes(self.report)

        handler = self.request("/api/saved-pdfs", origin=f"http://127.0.0.1:{server.PORT}")

        handler.send_response.assert_called_once_with(200)
        reports = json.loads(handler.wfile.getvalue())["reports"]
        self.assertEqual([report["name"] for report in reports], ["newest.PDF", "renamed.pdf"])
        self.assertEqual(reports[0]["modifiedAt"], 1_700_000_001_000)
        self.assertEqual(reports[1]["size"], len(self.report))

    def test_open_validates_filename_and_pdf_metadata(self):
        origin = f"http://127.0.0.1:{server.PORT}"
        for name, status in (("../renamed.pdf", 400), ("C:\\renamed.pdf", 400), ("renamed.pdf:secret.pdf", 400), ("private.pdf", 404)):
            with self.subTest(name=name):
                handler = self.request("/api/saved-pdfs/open", origin=origin, payload={"name": name})
                handler.send_response.assert_called_once_with(status)
                self.assertNotIn(self.private, handler.wfile.getvalue())

        handler = self.request("/api/saved-pdfs/open", origin=origin, payload={"name": "renamed.pdf"})
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_any_call("Content-Type", "application/pdf")
        self.assertEqual(handler.wfile.getvalue(), self.report)

    def test_both_endpoints_require_exact_local_origin_and_host(self):
        for path in ("/api/saved-pdfs", "/api/saved-pdfs/open", "/api/saved-pdfs/trash", "/api/saved-pdfs/restore"):
            for origin in (None, "https://example.test", f"http://localhost:{server.PORT}"):
                with self.subTest(path=path, origin=origin):
                    handler = self.request(path, origin=origin)
                    handler.send_response.assert_called_once_with(403)

    def test_reparse_points_are_rejected_before_opening(self):
        info = Mock(st_mode=server.stat.S_IFREG, st_file_attributes=server.stat.FILE_ATTRIBUTE_REPARSE_POINT)
        with patch.object(Path, "lstat", return_value=info), patch.object(Path, "open") as open_file:
            with self.assertRaises(FileNotFoundError):
                server.open_saved_pdf(self.downloads, "link.pdf")
        open_file.assert_not_called()

    def test_delete_and_restore_report_without_overwriting(self):
        origin = f"http://127.0.0.1:{server.PORT}"
        payload = {"name": "renamed.pdf"}
        self.request("/api/saved-pdfs/trash", origin=origin, payload=payload).send_response.assert_called_once_with(200)
        original = self.downloads / payload["name"]
        self.assertFalse(original.exists())
        listing = json.loads(self.request("/api/saved-pdfs", origin=origin).wfile.getvalue())
        self.assertEqual(listing["reports"], [])
        self.assertEqual([report["name"] for report in listing["trashed"]], [payload["name"]])

        original.write_bytes(self.private)
        self.request("/api/saved-pdfs/restore", origin=origin, payload=payload).send_response.assert_called_once_with(409)
        self.assertEqual(original.read_bytes(), self.private)
        original.unlink()
        self.request("/api/saved-pdfs/restore", origin=origin, payload=payload).send_response.assert_called_once_with(200)
        self.assertEqual(original.read_bytes(), self.report)
        listing = json.loads(self.request("/api/saved-pdfs", origin=origin).wfile.getvalue())
        self.assertEqual(listing["trashed"], [])

    def test_delete_rejects_non_report_and_path_traversal(self):
        origin = f"http://127.0.0.1:{server.PORT}"
        for name, status in (("private.pdf", 404), ("../renamed.pdf", 400)):
            with self.subTest(name=name):
                handler = self.request("/api/saved-pdfs/trash", origin=origin, payload={"name": name})
                handler.send_response.assert_called_once_with(status)
        self.assertEqual((self.downloads / "private.pdf").read_bytes(), self.private)
