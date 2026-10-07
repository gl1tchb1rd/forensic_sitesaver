# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inactive destinations remain inspectable without executing or opening URLs."""
from __future__ import annotations

import base64
import functools
import hashlib
import html
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import expect

from capture import build_local_mirror
from offline_links import LINK_SCRIPT_HASH, PREFIX
from test_local_mirror import BrowserTestCase, DATA_IMAGE, QuietHandler
from test_offline_menu import menu_case


DESTINATION = "https://external.invalid/path?order=7&search=%C3%A4#details"
HOSTILE_DESTINATION = "https://external.invalid/?q=<img src=x onerror=window.injectedRan=true>#frag"


def link_case(root: Path):
    visited = menu_case(root)
    raw = root / visited[0]["raw_dom_relative"]
    markup = raw.read_text().replace("</head>", '<meta charset="windows-1252"></head>')
    markup = markup.replace("</body>", f"""
    <a id="external-info" href="{html.escape(DESTINATION, quote=True)}">Partner website</a>
    <a id="hostile-info" href="{html.escape(HOSTILE_DESTINATION, quote=True)}">Untrusted URL text</a>
    <a id="email-info" href="mailto:test@example.test?subject=Hello#mail">Email</a>
    <a id="phone-info" href="tel:+4930123456">Phone</a>
    <a id="action-info" href="javascript:window.actionRan=true">Script action</a>
    <a id="missing-info" href="../uncaptured?filter=2#section">Uncaptured</a>
    <a id="forged-info" href="../next" data-original-url="https://fake.invalid" data-forensic-sitesaver-link-target="external">Local</a>
    <img id="map-image" src="{DATA_IMAGE}" width="24" height="24" usemap="#external-map">
    <map name="external-map"><area alt="Map destination" shape="rect" coords="0,0,24,24" href="{html.escape(DESTINATION, quote=True)}"></map>
    </body>""")
    markup = markup.replace("</nav>", f'<a id="menu-external-info" href="{html.escape(DESTINATION, quote=True)}">Menu partner</a></nav>', 1)
    raw.write_text(markup, encoding="utf-8")
    return visited


class OfflineLinkTests(unittest.TestCase):
    def test_full_destinations_markers_and_hashes_preserve_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = link_case(root)
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            build_local_mirror(root, visited)
            soup = BeautifulSoup((root / "02_website/seiten/1.html").read_text(), "html.parser")
            external = soup.select_one("#external-info")
            self.assertFalse(external.has_attr("href"))
            self.assertEqual(external["data-original-url"], DESTINATION)
            self.assertIn(DESTINATION, external["title"])
            self.assertEqual(external["role"], "button")
            self.assertEqual(external["tabindex"], "0")
            self.assertEqual(external.find("span").get_text(), "extern · deaktiviert")
            self.assertEqual(soup.select_one("#hostile-info")["data-original-url"], HOSTILE_DESTINATION)
            self.assertEqual(soup.select_one("#email-info")[PREFIX + "target"], "email")
            self.assertEqual(soup.select_one("#phone-info")[PREFIX + "target"], "phone")
            self.assertEqual(soup.select_one("#action-info")[PREFIX + "target"], "action")
            self.assertFalse(soup.select_one("#action-info").has_attr("href"))
            missing = soup.select_one("#missing-info")
            self.assertEqual(missing[PREFIX + "target"], "uncaptured")
            self.assertEqual(missing["data-original-url"], "https://example.test/uncaptured?filter=2#section")
            local = soup.select_one("#forged-info")
            self.assertEqual(local["href"], "2.html")
            self.assertFalse(local.has_attr(PREFIX + "target"))
            self.assertFalse(local.has_attr("data-original-url"))
            script = soup.find("script", attrs={"data-forensic-sitesaver-controller": "links"})
            digest = "sha256-" + base64.b64encode(hashlib.sha256(script.string.encode()).digest()).decode()
            self.assertEqual(digest, LINK_SCRIPT_HASH)
            csp = soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"})["content"]
            self.assertIn(digest, csp)
            self.assertIn("connect-src 'none'", csp)
            self.assertEqual(soup.find("meta", charset=True)["charset"], "utf-8")
            map_button = soup.select_one(f'#map-image + button[{PREFIX}target]')
            self.assertEqual(map_button["type"], "button")
            self.assertEqual(map_button["data-original-url"], DESTINATION)
            manifest = json.loads((root / "02_website/linkziele_manifest.json").read_text())
            self.assertTrue(any(link["url"] == DESTINATION for link in manifest["pages"][0]["links"]))
            for path, body in before.items():
                self.assertEqual((root / path).read_bytes(), body, str(path))


class OfflineLinkBrowserTests(BrowserTestCase):
    def test_file_and_http_tooltip_dialog_copy_keyboard_and_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_local_mirror(root, link_case(root))
            website = root / "02_website"
            server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(website)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for entry in [(website / "seiten/1.html").as_uri(), f"http://127.0.0.1:{server.server_port}/seiten/1.html"]:
                    with self.subTest(entry=entry):
                        context = self.browser.new_context(viewport={"width": 480, "height": 900}, service_workers="block")
                        # Simulate only the operating-system clipboard boundary;
                        # the real UI, script, CSP and browser events all run.
                        context.add_init_script("""window.copiedURLs = [];
                            Object.defineProperty(navigator, 'clipboard', {configurable:true,
                                value:{writeText:async value => {window.copiedURLs.push(value)}}});""")
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
                        page.set_default_timeout(5000)
                        page.goto(entry)
                        self.assertEqual(page.evaluate("document.characterSet"), "UTF-8")
                        link = page.locator("#external-info")
                        tooltip = page.locator(f'[{PREFIX}ui="tooltip"]')
                        dialog = page.get_by_role("dialog")
                        link.hover()
                        expect(tooltip).to_have_text(DESTINATION)
                        expect(tooltip).to_be_visible()
                        link.focus()
                        expect(tooltip).to_be_visible()
                        link.press("Enter")
                        expect(dialog).to_be_visible()
                        expect(dialog).to_contain_text("Externe Links und Verbindungen sind gesperrt.")
                        expect(dialog.locator("textarea")).to_have_value(DESTINATION)
                        self.assertTrue(dialog.locator("textarea").evaluate("field => field.readOnly"))
                        dialog.get_by_role("button", name="URL kopieren").click()
                        expect(dialog.get_by_role("status")).to_have_text("URL kopiert.")
                        self.assertEqual(page.evaluate("window.copiedURLs"), [DESTINATION])
                        dialog.press("Escape")
                        expect(dialog).not_to_be_visible()
                        self.assertTrue(link.evaluate("element => element === document.activeElement"))
                        self.assertEqual(page.url, entry)
                        # Space and pointer clicks both open only this dialog.
                        link.press(" ")
                        expect(dialog).to_be_visible()
                        dialog.get_by_role("button", name="Schließen").click()
                        page.locator("#hostile-info").click()
                        expect(dialog.locator("textarea")).to_have_value(HOSTILE_DESTINATION)
                        self.assertEqual(dialog.locator("img").count(), 0)
                        self.assertIsNone(page.evaluate("window.injectedRan"))
                        # If clipboard APIs are blocked, select for manual copy.
                        page.evaluate("""() => {navigator.clipboard.writeText=async () => {throw new Error('blocked')};
                            document.execCommand=() => false;}""")
                        dialog.get_by_role("button", name="URL kopieren").click()
                        expect(dialog.get_by_role("status")).to_contain_text("Strg+C")
                        self.assertEqual(dialog.locator("textarea").evaluate("field => [field.selectionStart, field.selectionEnd]"),
                                         [0, len(HOSTILE_DESTINATION)])
                        dialog.get_by_role("button", name="Schließen").click()
                        page.locator("#action-info").click()
                        expect(dialog.locator("textarea")).to_have_value("javascript:window.actionRan=true")
                        self.assertIsNone(page.evaluate("window.actionRan"))
                        # Clipboard denial can also fall back to the legacy
                        # local copy command when the browser permits it.
                        page.evaluate("""() => {window.copyCommands=[];
                            document.execCommand=command => {window.copyCommands.push(command);return true;};}""")
                        dialog.get_by_role("button", name="URL kopieren").click()
                        expect(dialog.get_by_role("status")).to_have_text("URL kopiert.")
                        self.assertEqual(page.evaluate("window.copyCommands"), ["copy"])
                        dialog.get_by_role("button", name="Schließen").click()
                        page.locator("#hamburger").click()
                        page.locator("#menu-external-info").click()
                        expect(dialog).to_be_visible()
                        dialog.press("Escape")
                        expect(page.locator("#mobile-nav")).to_be_visible()
                        page.locator("#hamburger").click()
                        page.locator(f'#map-image + button[{PREFIX}target]').click()
                        expect(dialog.locator("textarea")).to_have_value(DESTINATION)
                        dialog.get_by_role("button", name="Schließen").click()
                        self.assertEqual(page.url, entry)
                        self.assertEqual(len(context.pages), 1)
                        self.assertEqual(attempted_external, [])
                        page.locator("#forged-info").click()
                        page.wait_for_url("**/2.html")
                        self.assertEqual(page.locator("h1").inner_text(), "Next page")
                        context.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_tampered_link_controller_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_local_mirror(root, link_case(root))
            target = root / "02_website/seiten/1.html"
            soup = BeautifulSoup(target.read_text(), "html.parser")
            script = soup.find("script", attrs={"data-forensic-sitesaver-controller": "links"})
            script.string.replace_with(script.string + "\nwindow.linkTamperedRan=true;")
            target.write_text(str(soup))
            context = self.browser.new_context(viewport={"width": 480, "height": 900})
            page = context.new_page()
            page.goto(target.as_uri())
            page.locator("#external-info").click()
            self.assertEqual(page.locator("dialog").count(), 0)
            self.assertIsNone(page.evaluate("window.linkTamperedRan"))
            self.assertIn(DESTINATION, page.locator("#external-info").get_attribute("title"))
            context.close()
