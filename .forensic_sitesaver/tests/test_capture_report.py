# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression checks for capture accounting and case-file/PDF reports."""
from __future__ import annotations

import base64
import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from capture import capture_website
from common import sha256_file
from reports import export_reports


def run_synthetic_capture(output: Path, segment_pages: int = 20) -> Path:
    """Exercise the real capture/report pipeline with controlled browser input."""
    context = Mock()
    browser = Mock(version="synthetic-browser")
    browser.new_context.return_value = context
    playwright = SimpleNamespace(chromium=Mock())
    playwright.chromium.launch.return_value = browser
    page = Mock()
    context.new_page.return_value = page
    active_archive: Path | None = None
    entries: list[dict] = []
    route_guard = None
    blocked_checks_done = False

    def register_guard(pattern, guard):
        nonlocal route_guard
        route_guard = guard

    context.route.side_effect = register_guard

    def start_har(path, **kwargs):
        nonlocal active_archive, entries
        active_archive = Path(path)
        entries = []

    def stop_har():
        with zipfile.ZipFile(active_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("capture.har", json.dumps({"log": {"version": "1.2", "entries": entries}}))
            if any(e["response"]["content"].get("_file") == "style.css" for e in entries):
                archive.writestr("style.css", "body { color: navy; }")

    context.tracing.start_har.side_effect = start_har
    context.tracing.stop_har.side_effect = stop_har

    def goto(url, **kwargs):
        nonlocal blocked_checks_done
        page.url = url
        if not blocked_checks_done:
            blocked_checks_done = True
            for method, target in [("POST", "/submit"), ("GET", "/add-to-cart")]:
                route = Mock()
                route_guard(route, SimpleNamespace(method=method, url="http://example.test" + target))
                route.abort.assert_called_once()
        if url.endswith("/broken"):
            raise RuntimeError("simulated navigation failure")
        status = 503 if url.endswith("/error") else 200
        entries.append({
            "request": {"url": url, "method": "GET"},
            "response": {"status": status, "content": {"mimeType": "text/html", "text": content()}},
        })
        if not url.endswith("/error"):
            entries.append({
                "request": {"url": "http://example.test/style.css", "method": "GET"},
                "response": {"status": 200, "content": {"mimeType": "text/css", "_file": "style.css"}},
            })
        return SimpleNamespace(status=status)

    def content():
        if page.url.endswith("/error"):
            return "<html><head><title>Test: HTTP 503</title></head><body>Unavailable</body></html>"
        return (
            "<html><head><title>Synthetic fixture</title><link rel='stylesheet' href='/style.css'></head>"
            "<body><a href='/broken'>Broken</a><a href='/error'>HTTP error</a>"
            "<a href='/remaining'>Remaining</a><a href='/add-to-cart'>Blocked</a>"
            "<a href='https://external.invalid/'>External</a></body></html>"
        )

    def screenshot(path, **kwargs):
        if page.url.endswith("/error"):
            raise RuntimeError("simulated screenshot failure")
        Path(path).write_bytes(base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jBzQAAAAASUVORK5CYII="
        ))

    page.goto.side_effect = goto
    page.content.side_effect = content
    page.screenshot.side_effect = screenshot
    page.title.side_effect = lambda: "Test: HTTP 503" if page.url.endswith("/error") else "Synthetic fixture"
    current = datetime.fromisoformat("2026-10-05T12:00:00+02:00")

    def now():
        nonlocal current
        result = current.isoformat(timespec="seconds")
        current += timedelta(seconds=1.5)
        return result

    # Only browser I/O, external analyses and clocks are simulated. HAR reading,
    # mirroring, reporting, PDF rendering and hashing execute their real code.
    with (
        patch("capture.sync_playwright") as manager,
        patch("capture.analyze_domain", return_value={"external_calls": []}),
        patch("capture.capture_tls", return_value={"hosts_attempted": ["example.test"]}),
        patch("capture.iso_now", side_effect=now),
        patch("capture.time.monotonic", side_effect=[100.0, 112.5]),
        contextlib.redirect_stdout(io.StringIO()),
    ):
        manager.return_value.__enter__.return_value = playwright
        result = capture_website(
            "http://example.test", output, headless=True, max_pages=2,
            segment_pages=segment_pages, delay_ms=0, timeout_ms=1000,
            allow_hosts=["EXTRA.TEST."],
        )
    browser.close.assert_called_once()
    return result


class CaptureReportTests(unittest.TestCase):
    def test_measured_statistics_match_capture_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = run_synthetic_capture(Path(tmp))
            stats = json.loads((case / "04_metadaten/Sicherungsstatistik.json").read_text())
            tool_info = json.loads((case / "00_tool/tool_info.json").read_text())
            visited = json.loads((case / "04_metadaten/visited_pages.json").read_text())
            text = (case / "Sicherungsvermerk.txt").read_text()
            self.assertEqual(stats["started_at"], "2026-10-05T12:00:00+02:00")
            self.assertEqual(tool_info["started_at"], stats["started_at"])
            self.assertLess(stats["started_at"], stats["browser_started_at"])
            self.assertLess(stats["browser_started_at"], stats["browser_finished_at"])
            self.assertLess(stats["browser_finished_at"], stats["finished_at"])
            self.assertEqual(stats["duration_seconds"], 12.5)
            self.assertEqual(stats["pages_captured"], len(visited))
            self.assertEqual(stats["pages_captured"], 2)
            self.assertEqual(stats["page_capture_errors"], 1)
            self.assertEqual(stats["http_error_pages"], 1)
            self.assertEqual(stats["screenshots_captured"], len(list((case / "03_screenshots").glob("*.png"))))
            self.assertEqual(stats["screenshots_captured"], 1)
            self.assertEqual(stats["screenshot_errors"], 1)
            self.assertEqual(stats["har_entries"], 3)
            self.assertEqual(stats["har_segments"], 1)
            self.assertEqual(stats["har_bytes"], sum(p.stat().st_size for p in (case / "01_har").glob("*.har.zip")))
            self.assertEqual(stats["mirror_pages"], 2)
            self.assertEqual(stats["mirror_resources"], 1)
            self.assertEqual(stats["blocked_network_requests"], 2)
            self.assertEqual(stats["blocked_navigation_links"], 1)
            self.assertEqual(stats["external_links_not_followed"], 1)
            self.assertEqual(stats["remaining_pages"], 1)
            self.assertEqual(stats["allow_hosts"], ["extra.test"])
            self.assertIn("Beginn der Sicherung: " + stats["started_at"], text)
            self.assertIn("Ende der Browseraufzeichnung: " + stats["browser_finished_at"], text)
            self.assertIn("Ende der Datenerhebung und Auswertung: " + stats["finished_at"], text)
            self.assertIn(f"({stats['har_bytes']} Bytes)", text)
            self.assertIn("Dauer bis zum Ende der Datenerhebung und Auswertung: 12,5 Sekunden", text)
            self.assertNotIn("Beginn/Erstellung:", text)
            self.assertTrue(list((case / "04_metadaten").glob("seitenfehler_*.txt")))
            self.assertTrue(list((case / "03_screenshots").glob("*_SCREENSHOT_FEHLER.txt")))

            for line in (case / "SHA256SUMS.txt").read_text().splitlines():
                digest, relative = line.split("  ", 1)
                self.assertFalse(relative.startswith("PDF-Berichte/"))
                self.assertEqual(digest, sha256_file(case / relative))
            self.assertIn("04_metadaten/Sicherungsstatistik.json", (case / "SHA256SUMS.txt").read_text())
            manifest = json.loads((case / "PDF-Berichte/EXPORT_MANIFEST.json").read_text())
            row = next(r for r in manifest["reports"] if r["title"] == "Sicherungsvermerk")
            self.assertEqual(row["source_sha256"], sha256_file(case / "Sicherungsvermerk.txt"))
            self.assertEqual(row["pdf_sha256"], sha256_file(case / "PDF-Berichte" / row["pdf_file"]))

    def test_mitschnitt_size_sums_all_segments(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = run_synthetic_capture(Path(tmp), segment_pages=1)
            stats = json.loads((case / "04_metadaten/Sicherungsstatistik.json").read_text())
            archives = list((case / "01_har").glob("*.har.zip"))
            self.assertEqual(len(archives), 2)
            self.assertEqual(stats["har_segments"], 2)
            self.assertEqual(stats["har_entries"], 3)
            self.assertEqual(stats["har_bytes"], sum(p.stat().st_size for p in archives))

    @unittest.skipUnless(shutil.which("pdftotext"), "pdftotext is required for PDF text validation")
    def test_pdf_contains_narrative_and_actual_run_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = run_synthetic_capture(Path(tmp))
            for filename in ["01_Sicherungsvermerk.pdf", "Forensic_SiteSaver_Aktenberichte.pdf"]:
                result = subprocess.run(
                    ["pdftotext", str(case / "PDF-Berichte" / filename), "-"],
                    check=True, capture_output=True, text=True,
                )
                text = " ".join(result.stdout.split())
                self.assertIn("BROWSERGESTÜTZTE ERFASSUNG", text)
                self.assertIn("neue, nicht persistente Browsersitzung", text)
                self.assertIn("ABGESICHERTE LOKALE AUSWERTUNGSFASSUNG", text)
                self.assertIn("2026-10-05T12:00:00+02:00", text)
                self.assertIn("Erfasste Seiten (gespeicherter DOM): 2", text)
                self.assertIn("Fehler bei der Screenshot-Erstellung: 1", text)
                self.assertIn("Mitschnittgröße (gespeicherte HAR-Segmente):", text)
                self.assertNotIn("DISCLAIMER", text)

    def test_export_preserves_legacy_capture_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp)
            source = case / "Sicherungsvermerk.txt"
            source.write_text("Historischer Sicherungsvermerk\nBeginn/Erstellung: 2025-01-01T10:00:00+01:00\n", encoding="utf-8")
            digest = sha256_file(source)
            first = export_reports(case, case / "PDF-Berichte")
            second = export_reports(case, case / "PDF-Berichte")
            self.assertEqual(sha256_file(source), digest)
            self.assertFalse((case / "04_metadaten/Sicherungsstatistik.json").exists())
            self.assertEqual(first["reports"][0]["source_sha256"], digest)
            self.assertEqual(second["reports"][0]["source_sha256"], digest)


if __name__ == "__main__":
    unittest.main()
