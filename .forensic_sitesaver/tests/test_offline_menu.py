# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real DOM-menu interaction, including CSP and unchanged evidence checks."""
from __future__ import annotations

import base64
import functools
import hashlib
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from capture import build_local_mirror, rebuild_local_mirror
from offline_menu import MENU_SCRIPT_HASH, PREFIX
from offline_links import LINK_SCRIPT_HASH
from test_local_mirror import BrowserTestCase, QuietHandler, make_case


MENU_HTML = """
<style>
 .dropdown-menu, #keyboard-menu, .navbar-collapse {display:none}
 #mobile-nav {display:none; visibility:hidden; transform:translateX(-100%);opacity:0;max-height:0}
 @media (min-width:768px) { #hamburger {display:none} #mobile-nav {display:block;visibility:visible;transform:none;opacity:1;max-height:none} }
</style>
<button id="hamburger" aria-expanded="false" aria-controls="mobile-nav">Menu</button>
<nav id="mobile-nav">
 <a id="nav-link" href="../next#details">Next</a>
 <div class="dropdown">
  <a id="products" href="../next" data-bs-toggle="dropdown">Products</a>
  <ul class="dropdown-menu" id="products-menu">
   <li><a href="../next#details">Product page</a></li>
   <li><button id="nested-toggle" aria-controls="nested-menu" aria-expanded="false">More</button>
    <ul id="nested-menu" class="sub-menu"><li><a href="../next">More products</a></li></ul>
   </li>
  </ul>
 </div>
</nav>
<div class="dropdown">
 <button id="independent" data-bs-toggle="dropdown" aria-expanded="false">Other menu</button>
 <ul id="independent-menu" class="dropdown-menu"><li><a href="../next">Other page</a></li></ul>
</div>
<span id="keyboard-toggle" role="button" aria-expanded="false" aria-controls="keyboard-menu">Keyboard menu</span>
<ul id="keyboard-menu"><li><a href="../next">Keyboard page</a></li></ul>
<button id="collapse-toggle" data-bs-toggle="collapse" data-bs-target=".navbar-collapse" aria-expanded="false">Collapse menu</button>
<div id="collapse-menu" class="navbar-collapse"><a href="../next">Collapsed link</a></div>
<ul><li class="menu-item-has-children">
 <a id="wordpress-link" href="../next">Pages</a>
 <ul class="sub-menu"><li><a href="../next">WordPress-style submenu</a></li></ul>
</li></ul>
<button id="missing-toggle" aria-controls="missing-navigation">Missing</button>
<button id="accordion-toggle" aria-controls="ordinary-content">Not a menu</button>
<div id="ordinary-content"><a href="../next">Article link</a></div>
<button id="forged" data-forensic-sitesaver-menu-controls="1">Forged annotation</button>
<form action="https://external.invalid/submit">
 <button id="form-toggle" aria-controls="form-menu">Submit</button>
 <nav id="form-menu"><a href="../next">Form link</a></nav>
</form>
<button id="already-disabled" disabled aria-controls="keyboard-menu">Disabled original</button>
<a id="foreign-fragment" href="https://external.invalid/start#keyboard-menu" role="button" aria-expanded="false">Foreign target</a>
<div id="outside">Outside all menus</div>
"""


def menu_case(root: Path) -> list[dict]:
    visited = make_case(root)
    raw = root / visited[0]["raw_dom_relative"]
    raw.write_text(raw.read_text().replace("</body>", MENU_HTML + "</body>"), encoding="utf-8")
    return visited


class OfflineMenuTests(unittest.TestCase):
    def test_only_fixed_hash_script_and_identified_controls_are_authorized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = menu_case(root)
            raw = (root / visited[0]["raw_dom_relative"]).read_bytes()
            build_local_mirror(root, visited)
            soup = BeautifulSoup((root / "02_website/seiten/1.html").read_text(), "html.parser")
            scripts = soup.find_all("script")
            self.assertEqual(len(scripts), 2)
            menu_script = soup.find("script", attrs={"data-forensic-sitesaver-controller": "menu"})
            actual_hash = "sha256-" + base64.b64encode(hashlib.sha256(menu_script.string.encode()).digest()).decode()
            self.assertEqual(actual_hash, MENU_SCRIPT_HASH)
            csp = soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"})["content"]
            self.assertIn(f"script-src '{actual_hash}'", csp)
            self.assertIn(LINK_SCRIPT_HASH, csp)
            self.assertIn("script-src-attr 'none'", csp)
            self.assertIn("connect-src 'none'", csp)
            self.assertNotIn("'unsafe-inline'", csp.split("script-src ")[1].split(";")[0])
            self.assertFalse(soup.select_one("#hamburger").has_attr("disabled"))
            for selector in ["#forged", "#form-toggle", "#already-disabled", "#accordion-toggle", "#missing-toggle"]:
                self.assertTrue(soup.select_one(selector).has_attr("disabled"), selector)
                self.assertFalse(soup.select_one(selector).has_attr(PREFIX + "controls"), selector)
            self.assertFalse(soup.select_one("#foreign-fragment").has_attr(PREFIX + "controls"))
            self.assertEqual(soup.select_one("#products")["href"], "2.html")
            button = soup.select_one(f'button[{PREFIX}controls][aria-controls="products-menu"]')
            self.assertIsNotNone(button)
            self.assertEqual(button["type"], "button")
            self.assertIsNone(soup.find(attrs={"onclick": True}))
            manifest = json.loads((root / "02_website/menue_manifest.json").read_text())
            self.assertEqual(len(manifest["pages"][0]["menus"]), 7)
            wp_button = soup.select_one(f'#wordpress-link + button[{PREFIX}controls]')
            self.assertIsNotNone(wp_button)
            self.assertTrue(wp_button["aria-controls"].startswith("forensic-sitesaver-menu-"))
            self.assertEqual((root / visited[0]["raw_dom_relative"]).read_bytes(), raw)
            # Pages with no recognized menus still forbid all script execution.
            plain = BeautifulSoup((root / "02_website/seiten/2.html").read_text(), "html.parser")
            self.assertIsNone(plain.find("script"))
            self.assertIn("script-src 'none'", plain.find("meta", attrs={"http-equiv": "Content-Security-Policy"})["content"])

    def test_rebuild_adds_menu_support_without_altering_original_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "original"
            source.mkdir()
            visited = menu_case(source)
            metadata = source / "04_metadaten"
            metadata.mkdir()
            (metadata / "visited_pages.json").write_text(json.dumps(visited))
            before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
            destination = Path(tmp) / "new-view"
            rebuild_local_mirror(source, destination)
            self.assertTrue((destination / "menue_manifest.json").is_file())
            self.assertEqual(before, {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()})


class OfflineMenuBrowserTests(BrowserTestCase):
    def test_file_and_http_menus_keyboard_resize_navigation_and_csp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = menu_case(root)
            build_local_mirror(root, visited)
            website = root / "02_website"
            html_path = website / "seiten/1.html"
            # Simulate scripts/event handlers injected after mirror generation:
            # CSP must reject them independently of the sanitizer.
            html = html_path.read_text().replace("</body>", """
            <script>window.injectedRan=true;fetch('https://external.invalid/injected')</script>
            <script src="data:text/javascript,window.externalScriptRan=true"></script>
            <button id="evil-handler" onclick="window.handlerRan=true">Injected handler</button>
            </body>""")
            html_path.write_text(html)
            server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(website)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for entry in [html_path.as_uri(), f"http://127.0.0.1:{server.server_port}/seiten/1.html"]:
                    with self.subTest(entry=entry):
                        context = self.browser.new_context(viewport={"width": 480, "height": 900}, service_workers="block")
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
                        self.assertFalse(page.locator("#mobile-nav").is_visible())
                        page.locator("#hamburger").click()
                        self.assertTrue(page.locator("#mobile-nav").is_visible())
                        self.assertEqual(page.locator("#hamburger").get_attribute("aria-expanded"), "true")
                        self.assertEqual(page.locator("#mobile-nav").evaluate("panel => getComputedStyle(panel).transform"), "none")
                        products = page.locator(f'button[{PREFIX}controls][aria-controls="products-menu"]')
                        products.click()
                        self.assertTrue(page.locator("#products-menu").is_visible())
                        page.locator("#nested-toggle").click()
                        self.assertTrue(page.locator("#nested-menu").is_visible())
                        self.assertTrue(page.locator("#mobile-nav").is_visible())
                        page.locator("#nested-toggle").press("Escape")
                        self.assertFalse(page.locator("#nested-menu").is_visible())
                        self.assertTrue(page.locator("#products-menu").is_visible())
                        page.locator("#nested-toggle").press("Escape")
                        self.assertFalse(page.locator("#products-menu").is_visible())
                        self.assertTrue(products.evaluate("control => control === document.activeElement"))
                        products.press("Escape")
                        self.assertFalse(page.locator("#mobile-nav").is_visible())
                        self.assertTrue(page.locator("#hamburger").evaluate("control => control === document.activeElement"))
                        page.locator("#keyboard-toggle").focus()
                        page.locator("#keyboard-toggle").press("Enter")
                        self.assertTrue(page.locator("#keyboard-menu").is_visible())
                        page.locator("#keyboard-toggle").press(" ")
                        self.assertFalse(page.locator("#keyboard-menu").is_visible())
                        wordpress = page.locator(f'#wordpress-link + button[{PREFIX}controls]')
                        wordpress.click()
                        wp_panel = page.locator('[id="' + wordpress.get_attribute("aria-controls") + '"]')
                        self.assertTrue(wp_panel.is_visible())
                        wordpress.press("Escape")
                        self.assertFalse(wp_panel.is_visible())
                        page.locator("#collapse-toggle").click()
                        self.assertTrue(page.locator("#collapse-menu").is_visible())
                        page.locator("#outside").click()
                        self.assertFalse(page.locator("#collapse-menu").is_visible())
                        page.locator("#independent").click()
                        self.assertTrue(page.locator("#independent-menu").is_visible())
                        page.locator("#hamburger").click()
                        self.assertFalse(page.locator("#independent-menu").is_visible())
                        page.locator("#hamburger").click()
                        page.set_viewport_size({"width": 1100, "height": 900})
                        page.wait_for_function("() => getComputedStyle(document.querySelector('#mobile-nav')).display !== 'none'")
                        self.assertTrue(page.locator("#mobile-nav").is_visible())
                        self.assertFalse(page.locator("#hamburger").is_visible())
                        page.set_viewport_size({"width": 480, "height": 900})
                        page.wait_for_function("() => getComputedStyle(document.querySelector('#mobile-nav')).display === 'none'")
                        self.assertFalse(page.locator("#mobile-nav").is_visible())
                        page.locator("#evil-handler").click()
                        for variable in ["injectedRan", "externalScriptRan", "handlerRan", "untrustedRan"]:
                            self.assertIsNone(page.evaluate(f"window.{variable}"))
                        # DevTools executes this test expression; connect-src
                        # must still block fetch, even to the local origin.
                        self.assertFalse(page.evaluate("url => fetch(url).then(() => true).catch(() => false)",
                                                       f"http://127.0.0.1:{server.server_port}/index.html"))
                        page.locator("#hamburger").click()
                        products.click()
                        page.locator("#products").click()
                        page.wait_for_url("**/2.html")
                        self.assertEqual(page.locator("h1").inner_text(), "Next page")
                        self.assertEqual(attempted_external, [])
                        context.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_modified_controller_is_blocked_by_its_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_local_mirror(root, menu_case(root))
            target = root / "02_website/seiten/1.html"
            soup = BeautifulSoup(target.read_text(), "html.parser")
            script = soup.find("script")
            script.string.replace_with(script.string + "\nwindow.tamperedRan = true;\n")
            target.write_text(str(soup))
            context = self.browser.new_context(viewport={"width": 480, "height": 900})
            page = context.new_page()
            page.goto(target.as_uri())
            page.locator("#hamburger").click()
            self.assertFalse(page.locator("#mobile-nav").is_visible())
            self.assertIsNone(page.evaluate("window.tamperedRan"))
            context.close()
