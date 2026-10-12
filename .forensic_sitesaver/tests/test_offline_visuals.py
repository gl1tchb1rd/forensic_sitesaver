# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser regressions for scroll reveals and script-drawn charts."""
import functools
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from bs4 import BeautifulSoup

from capture import _load_lazy_images, capture_canvases, rebuild_local_mirror
from offline_visuals import canvas_sources
from test_local_mirror import BrowserTestCase, PNG, QuietHandler


class CanvasPathTests(unittest.TestCase):
    def test_snapshot_cannot_read_outside_case_or_wrong_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'case'
            root.mkdir()
            (root.parent / 'outside.png').write_bytes(PNG)
            (root / 'inside.png').write_bytes(PNG)
            self.assertEqual(canvas_sources(root, [
                {'index': 0, 'path': '../outside.png'},
                {'index': 1, 'path': 'inside.png', 'sha256': 'wrong'},
            ]), {})


class OfflineVisualBrowserTests(BrowserTestCase):
    def test_unavailable_or_oversized_canvas_is_diagnosed(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = self.browser.new_context()
            try:
                page = context.new_page()
                page.set_content('<canvas width="0" height="0"></canvas><canvas width="4001" height="4000"></canvas>')
                rows = capture_canvases(page, Path(tmp), 1)
                self.assertEqual(rows[0]['error'], 'canvas_pixels_unavailable')
                self.assertEqual(rows[1]['error'], 'capture_limit')
                self.assertFalse(list(Path(tmp).rglob('*.png')))
            finally:
                context.close()

    def test_revealed_products_and_canvas_survive_file_and_http_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'site'
            source.mkdir()
            (source / 'photo.jpg').write_bytes(PNG)
            # A filter exists above invisible product cards, as in the report.
            (source / 'index.html').write_text('''<!doctype html><html><head><style>
                .reveal {opacity:0;transform:translateY(30px);transition:opacity 2s}
                .reveal.visible {opacity:1;transform:none}
                body {margin:0} canvas {width:120px;height:60px}
                </style></head><body><div style="height:12000px">Filter</div>
                <article class="reveal" id="product"><img loading="lazy" src="photo.jpg" width="100" height="100"><h2>Goldbarren</h2></article>
                <section class="reveal" id="mission"><canvas id="chart" width="240" height="120" aria-label="Goldkurs"></canvas><h2>Unsere Mission</h2></section>
                <nav class="reveal" hidden id="hidden-menu">Hidden menu</nav>
                <script>window.originalRan = true;
                const observer = new IntersectionObserver(entries => {
                    for (const entry of entries) if (entry.isIntersecting) {
                        entry.target.classList.add('visible');
                        if (entry.target.id === 'mission') {
                            const ctx = document.getElementById('chart').getContext('2d');
                            ctx.fillStyle = '#d4af37';ctx.fillRect(0, 0, 240, 120);
                        }
                    }
                });
                document.querySelectorAll('.reveal').forEach(element => observer.observe(element));
                </script></body></html>''')
            server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(root)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                case = root / 'case'
                har = case / '01_har/capture.har.zip'
                har.parent.mkdir(parents=True)
                context = self.browser.new_context(record_har_path=str(har), record_har_content='attach', service_workers='block')
                page = context.new_page()
                url = f'http://127.0.0.1:{server.server_port}/site/index.html'
                page.goto(url)
                loading = _load_lazy_images(page, 4000)
                self.assertGreater(loading['loaded_images'], 0)
                self.assertEqual(page.evaluate('scrollY'), 0)
                self.assertEqual(page.locator('#chart').evaluate("c => c.getContext('2d').getImageData(0,0,1,1).data[3]"), 255)
                snapshots = capture_canvases(page, case, 1)
                self.assertIn('path', snapshots[0])
                raw = case / '02_website/_dom_roh/1.txt'
                raw.parent.mkdir(parents=True)
                # Old DOMs can retain the initial invisible reveal state.
                raw.write_text(page.content().replace('reveal visible', 'reveal'))
                context.close()
                metadata = case / '04_metadaten/visited_pages.json'
                metadata.parent.mkdir()
                metadata.write_text(json.dumps([{'index': 1, 'final_url': url, 'raw_dom_relative': raw.relative_to(case).as_posix(),
                                                'canvas_snapshots': snapshots}]))
                original = {p: p.read_bytes() for p in case.rglob('*') if p.is_file()}
                output = root / 'view'
                rebuild_local_mirror(case, output)
                page_path = next((output / 'seiten').glob('*.html'))
                manifest = json.loads((output / 'website_manifest.json').read_text())
                self.assertEqual(manifest['network_safety_verification'], 'PASS')
                self.assertEqual(manifest['pages'][0]['static_visuals']['canvases_restored'], 1)
                for p, body in original.items():
                    self.assertEqual(p.read_bytes(), body)
                for offline_url in [page_path.as_uri(), f'http://127.0.0.1:{server.server_port}/view/seiten/{page_path.name}']:
                    with self.subTest(url=offline_url):
                        context = self.browser.new_context(service_workers='block')
                        page = context.new_page()
                        page.goto(offline_url)
                        for selector in ['#product', '#mission']:
                            self.assertEqual(page.locator(selector).evaluate('e => getComputedStyle(e).opacity'), '1')
                        self.assertTrue(page.locator('#hidden-menu').is_hidden())
                        self.assertGreater(page.locator('#product img').evaluate('i => i.naturalWidth'), 0)
                        self.assertEqual(page.locator('#chart').evaluate('i => i.naturalWidth'), 240)
                        self.assertEqual(page.locator('#chart').bounding_box()['width'], 120)
                        self.assertEqual(page.locator('#chart').bounding_box()['height'], 60)
                        self.assertIsNone(page.evaluate('window.originalRan'))
                        context.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_reveal_without_images_is_scrolled_and_dom_not_artificially_changed(self):
        context = self.browser.new_context()
        try:
            page = context.new_page()
            page.set_content('<html><body><div style="height:12000px"></div><section class="reveal">Mission</section></body></html>')
            before = page.content()
            result = _load_lazy_images(page, 1000)
            self.assertEqual(result['candidate_images'], 0)
            self.assertGreater(result['positions_visited'], 0)
            self.assertEqual(page.evaluate('scrollY'), 0)
            self.assertEqual(page.content(), before)
        finally:
            context.close()
