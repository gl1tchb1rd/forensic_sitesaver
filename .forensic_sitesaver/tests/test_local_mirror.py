# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Archive fixtures and browser checks for the derived offline mirror."""
from __future__ import annotations

import base64
import functools
import json
import os
import tempfile
import threading
import unittest
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from capture import _image_sources, build_local_mirror, rebuild_local_mirror
from offline_links import LINK_SCRIPT_HASH


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII="
)
DATA_IMAGE = "data:image/png;base64," + base64.b64encode(PNG).decode()
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"><rect width="4" height="4" fill="red"/></svg>'


def make_case(root: Path, *, selected: bool = False) -> list[dict]:
    har_dir = root / "01_har"
    har_dir.mkdir()
    raw_dir = root / "02_website/_dom_roh"
    raw_dir.mkdir(parents=True)
    markup = f"""<!doctype html><html><head>
    <base href="https://example.test/assets/">
    <link rel="stylesheet" href="main.css">
    <link rel="dns-prefetch" href="https://external.invalid">
    <link rel="icon" href="icon.svg">
    <style>@import 'theme.css'; #inline {{ background-image: url(photo.png); }} .missing {{background:url(missing-css.png)}}</style>
    </head><body>
    <a id="next" href="../next#details" target="_blank" ping="https://external.invalid/ping">Next</a>
    <a id="jump" href="../start#section">Section</a>
    <a id="missing-page" href="../uncaptured">Missing</a>
    <a id="external" href="https://external.invalid">External</a>
    <map><area id="area" href="../next#details"></map>
    <script>window.untrustedRan = true; fetch('https://external.invalid');</script>
    <form action="https://external.invalid"><input><button>Submit</button></form>
    <img id="data" src="{DATA_IMAGE}">
    <img id="svg" src="icon.svg">
    <img id="redirect" src="redirect.png">
    <img id="responsive" src="missing.png" srcset="missing.png 1x, photo.png 2x, missing-large.png 3x">
    <picture><source srcset="photo.png 1x, missing.png 2x"><img id="picture" src="missing.png"></picture>
    <img id="lazy" src="{DATA_IMAGE}" data-src="photo.png" loading="lazy">
    <img id="missing-image" src="https://external.invalid/missing.png">
    <img id="data-srcset" srcset="{DATA_IMAGE} 1x, photo.png 2x">
    <svg><image id="svg-image" href="photo.png"/><use href="#symbol"/></svg>
    <div id="inline" style="background-image:url('icon.svg');width:4px;height:4px"></div>
    <div id="background" style="width:4px;height:4px"></div>
    <div id="section" style="margin-top:1000px">Section</div>
    </body></html>"""
    (raw_dir / "1.dom.txt").write_text(markup, encoding="utf-8")
    (raw_dir / "2.dom.txt").write_text("<html><head></head><body><h1 id='details'>Next page</h1></body></html>")
    resources = [
        ("photo.png", "image/png", PNG),
        ("icon.svg", "image/svg+xml", SVG),
        ("main.css", "text/css", b'@import url("theme.css"); #background {background-image:url(photo.png)}'),
        ("theme.css", "text/css", b'body {color:rgb(1, 2, 3)}'),
    ]
    entries = [{"request": {"url": "https://example.test/assets/photo.png"},
                "response": {"status": 404, "content": {"mimeType": "image/png", "text": "error"}}}]
    with zipfile.ZipFile(har_dir / "segment_0001.har.zip", "w") as archive:
        for index, (name, mime, body) in enumerate(resources):
            reference = f"body-{index}"
            archive.writestr(reference, body)
            entries.append({
                "request": {"url": "https://example.test/assets/" + name},
                "response": {"status": 200, "headers": [{"name": "Content-Type", "value": mime}],
                             "content": {"_file": reference}},
            })
        entries.append({"request": {"url": "https://example.test/assets/redirect.png"},
                        "response": {"status": 302, "redirectURL": "photo.png"}})
        archive.writestr("archive.har", json.dumps({"log": {"entries": entries}}))
    visited = [
        {"index": 1, "final_url": "https://example.test/start", "requested_url": "https://example.test/",
         "html_name": "1.html", "raw_dom_relative": "02_website/_dom_roh/1.dom.txt",
         "title": "<img src='https://external.invalid' onerror='alert(1)'>"},
        {"index": 2, "final_url": "https://example.test/next", "html_name": "2.html",
         "raw_dom_relative": "02_website/_dom_roh/2.dom.txt", "title": "Next"},
    ]
    if selected:
        # The selected picture image is the fifth <img> in the raw DOM.
        visited[0]["image_sources"] = ["", "", "", "", "https://example.test/assets/photo.png"]
    return visited


class LocalMirrorTests(unittest.TestCase):
    def test_images_navigation_and_evidence_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = make_case(root)
            raw = (root / visited[0]["raw_dom_relative"]).read_bytes()
            archive = (root / "01_har/segment_0001.har.zip").read_bytes()
            result = build_local_mirror(root, visited)
            website = root / "02_website"
            page = BeautifulSoup((website / "seiten/1.html").read_text(), "html.parser")
            self.assertEqual(result, {"pages": 2, "resources": 4})
            self.assertEqual(page.select_one("#data")["src"], DATA_IMAGE)
            for selector in ["#svg", "#redirect", "#lazy"]:
                image = page.select_one(selector)
                local = website / "seiten" / image["src"]
                self.assertEqual(local.read_bytes(), SVG if selector == "#svg" else PNG)
            self.assertIn("photo.png 2x", page.select_one("#responsive")["srcset"])
            self.assertNotIn("missing", page.select_one("#responsive")["srcset"])
            self.assertTrue(page.select_one("picture source")["srcset"].endswith("photo.png 1x"))
            self.assertTrue(page.select_one("#data-srcset")["srcset"].startswith(DATA_IMAGE + " 1x,"))
            self.assertEqual(page.select_one("#next")["href"], "2.html#details")
            self.assertEqual(page.select_one("#jump")["href"], "1.html#section")
            self.assertEqual(page.select_one("#area")["href"], "2.html#details")
            self.assertFalse(page.select_one("#next").has_attr("ping"))
            self.assertFalse(page.select_one("#external").has_attr("href"))
            self.assertFalse(page.select_one("#missing-page").has_attr("href"))
            self.assertEqual(len(page.find_all("script")), 1)
            self.assertEqual(page.find("script")["data-forensic-sitesaver-controller"], "links")
            self.assertIn(LINK_SCRIPT_HASH, page.find("meta", attrs={"http-equiv": "Content-Security-Policy"})["content"])
            self.assertIsNone(page.find("base"))
            self.assertIsNone(page.find("link", rel="dns-prefetch"))
            self.assertTrue(page.find("input").has_attr("disabled"))
            self.assertEqual((root / visited[0]["raw_dom_relative"]).read_bytes(), raw)
            self.assertEqual((root / "01_har/segment_0001.har.zip").read_bytes(), archive)
            index = BeautifulSoup((website / "index.html").read_text(), "html.parser")
            self.assertIsNone(index.find("img"))
            self.assertEqual(index.find("a").get_text(), visited[0]["title"])
            diagnostics = json.loads((website / "fehlende_referenzen.json").read_text())["references"]
            self.assertTrue(any(row["url"].endswith("/uncaptured") for row in diagnostics))
            self.assertTrue(any(row["url"].endswith("/missing.png") for row in diagnostics))
            self.assertTrue(any(row["kind"] == "css-url" and row["url"].endswith("/missing-css.png") for row in diagnostics))

    def test_browser_selected_picture_survives_without_raw_dom_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = make_case(root, selected=True)
            build_local_mirror(root, visited)
            soup = BeautifulSoup((root / "02_website/seiten/1.html").read_text(), "html.parser")
            self.assertIsNone(soup.select_one("picture source"))
            self.assertTrue(soup.select_one("#picture")["src"].endswith("photo.png"))
            self.assertIn("<source", (root / visited[0]["raw_dom_relative"]).read_text())

    def test_css_imports_use_derived_files_and_original_bytes_remain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = make_case(root)
            build_local_mirror(root, visited)
            website = root / "02_website"
            soup = BeautifulSoup((website / "seiten/1.html").read_text(), "html.parser")
            main = website / "seiten" / soup.find("link", rel="stylesheet")["href"]
            css = main.read_text()
            self.assertIn('@import url("', css)
            self.assertNotIn("theme.css", css)
            self.assertNotIn("data:,", css)
            self.assertIn("../ressourcen/example.test/assets/photo.png", css)
            self.assertIn("../_runtime_css/", soup.find("style").get_text())
            original = website / "ressourcen/example.test/assets/main.css"
            self.assertEqual(original.read_bytes(), b'@import url("theme.css"); #background {background-image:url(photo.png)}')

    def test_image_source_collection_falls_back_when_browser_evaluation_fails(self):
        page = Mock()
        page.evaluate.return_value = ["https://example.test/photo.png", ""]
        self.assertEqual(_image_sources(page), ["https://example.test/photo.png", ""])
        page.evaluate.side_effect = RuntimeError("page closed")
        self.assertEqual(_image_sources(page), [])

    def test_rebuild_reads_original_case_and_writes_separate_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp) / "original"
            case.mkdir()
            visited = make_case(case)
            metadata = case / "04_metadaten"
            metadata.mkdir()
            (metadata / "visited_pages.json").write_text(json.dumps(visited))
            original = {p.relative_to(case): p.read_bytes() for p in case.rglob("*") if p.is_file()}
            output = Path(tmp) / "new-view"
            self.assertEqual(rebuild_local_mirror(case, output)["pages"], 2)
            self.assertTrue((output / "index.html").is_file())
            self.assertTrue((output / "QUELLE.txt").is_file())
            self.assertEqual(original, {p.relative_to(case): p.read_bytes() for p in case.rglob("*") if p.is_file()})
            with self.assertRaises(ValueError):
                rebuild_local_mirror(case, case / "new-view")
            with self.assertRaises(ValueError):
                rebuild_local_mirror(case, output)

    def test_rebuild_rejects_paths_outside_evidence_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp) / "original"
            case.mkdir()
            visited = make_case(case)
            metadata = case / "04_metadaten"
            metadata.mkdir()
            visited[0]["raw_dom_relative"] = "../outside.txt"
            (Path(tmp) / "outside.txt").write_text("outside")
            (metadata / "visited_pages.json").write_text(json.dumps(visited))
            output = Path(tmp) / "new-view"
            with self.assertRaises(ValueError):
                rebuild_local_mirror(case, output)
            self.assertFalse(output.exists())


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class BrowserTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manager = sync_playwright().start()
        executable = os.environ.get("SITESAVER_TEST_CHROMIUM")
        if not executable and not Path(cls.manager.chromium.executable_path).is_file():
            cls.manager.stop()
            raise unittest.SkipTest("Chromium is unavailable; set SITESAVER_TEST_CHROMIUM for browser checks")
        try:
            cls.browser = cls.manager.chromium.launch(executable_path=executable)
        except Exception:
            cls.manager.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.manager.stop()


class LocalMirrorBrowserTests(BrowserTestCase):
    def test_file_and_http_images_css_links_and_no_external_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = make_case(root, selected=True)
            build_local_mirror(root, visited)
            website = root / "02_website"
            server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(website)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for entry in [(website / "seiten/1.html").as_uri(), f"http://127.0.0.1:{server.server_port}/seiten/1.html"]:
                    with self.subTest(entry=entry):
                        context = self.browser.new_context(service_workers="block")
                        attempted_external = []

                        def guard(route):
                            parsed = urlparse(route.request.url)
                            if parsed.scheme in {"http", "https"} and parsed.hostname != "127.0.0.1":
                                attempted_external.append(route.request.url)
                                route.abort()
                            else:
                                route.continue_()

                        context.route("**/*", guard)
                        page = context.new_page()
                        page.goto(entry)
                        for selector in ["#data", "#svg", "#redirect", "#responsive", "#picture", "#lazy", "#data-srcset"]:
                            self.assertGreater(page.locator(selector).evaluate("image => image.naturalWidth"), 0,
                                               page.locator(selector).evaluate("image => image.outerHTML"))
                        self.assertEqual(page.evaluate("getComputedStyle(document.body).color"), "rgb(1, 2, 3)")
                        self.assertIn("ressourcen", page.evaluate("getComputedStyle(document.querySelector('#background')).backgroundImage"))
                        self.assertIsNone(page.evaluate("window.untrustedRan"))
                        page.locator("#jump").click()
                        self.assertTrue(page.url.endswith("#section"))
                        page.locator("#next").click()
                        page.wait_for_url("**/2.html#details")
                        self.assertEqual(page.locator("h1").inner_text(), "Next page")
                        self.assertEqual(attempted_external, [])
                        context.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    unittest.main()
