# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""K25 pipeline: cached JPEG bodies, archive selection and native srcset."""
from __future__ import annotations

import base64
import functools
import json
import tempfile
import threading
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from website_mirror import build_local_mirror, _verify_local_html
from test_local_mirror import BrowserTestCase, QuietHandler, PNG

# Genuine, locally generated JPEG bytes (2x3 pixels), without an image-library
# dependency in the test runner. PNG bytes under a .jpg name would miss bugs.
JPEG = base64.b64decode(
    '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/'
    '2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/'
    'wAARCAADAAIDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/'
    '8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/'
    '8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/'
    '8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/'
    '9oADAMBAAIRAxEAPwCGiiivkT9LP//Z'
)
SITE = 'https://www.feuerwehr-vestenberg.de/'
PHOTO = 'wp-content/uploads/2024/07/11-Freiwillige-Feuerwehr-Vestenberg_Jubilaeum-125-Jahre_10.06.24-11-683x1024.jpg'
LARGE = PHOTO.replace('-683x1024.jpg', '-scaled.jpg')


def k25_case(root: Path):
    har_dir = root / '01_har'
    har_dir.mkdir()
    raw_dir = root / '02_website/_dom_roh'
    raw_dir.mkdir(parents=True)
    raw = f'''<!doctype html><html><head><meta charset="windows-1252">
    <style>.dropdown-menu{{display:none}} .dropdown:hover > .dropdown-menu{{display:block}}</style>
    <script>fetch('https://external.invalid/original')</script></head><body>
    <img id="png" src="poster.png">
    <img id="jpeg" loading="lazy" src="{PHOTO}">
    <img id="responsive" src="{PHOTO}" srcset="{PHOTO} 683w, {LARGE} 1709w" sizes="100vw">
    <img id="absent" src="empty-cache.jpg">
    <nav><ul><li class="menu-item-has-children dropdown">
      <a id="about" href="aktive-feuerwehr/" aria-haspopup="true" aria-controls="about-menu" aria-expanded="false">Über uns</a>
      <ul id="about-menu" class="dropdown-menu"><li><a id="about-child" href="aktive-feuerwehr/">Aktive Feuerwehr</a></li></ul>
    </li></ul></nav>
    <a id="image-link" href="{PHOTO}">Bild öffnen</a>
    <a id="external" href="https://external.invalid/?query=1#details">External</a>
    </body></html>'''
    (raw_dir / '1.dom.txt').write_text(raw, encoding='utf-8')
    (raw_dir / '2.dom.txt').write_text('<html><head></head><body><h1>Feuerwehr</h1></body></html>')
    entries = []
    with zipfile.ZipFile(har_dir / 'segment_0001.har.zip', 'w') as archive:
        # K25 tries subsequent candidates when a preceding .har isn't valid.
        archive.writestr('metadata.har', 'not a HAR document')
        for name, mime, status, body in [
            ('poster.png', 'image/png', 200, PNG),
            (PHOTO, 'image/jpeg', 304, JPEG),
            (LARGE, 'image/jpeg', 200, JPEG),
            ('empty-cache.jpg', 'image/jpeg', 304, None),
        ]:
            content = {'mimeType': mime}
            if body:
                attachment = 'resources/' + str(len(entries))
                content['_sha1'] = str(len(entries))
                archive.writestr(attachment, body)
            entries.append({'request': {'url': SITE + name}, 'response': {'status': status, 'content': content}})
        archive.writestr('capture.har', json.dumps({'log': {'entries': entries}}))
    return [
        {'index': 1, 'final_url': SITE, 'html_name': '1.html', 'raw_dom_relative': '02_website/_dom_roh/1.dom.txt',
         'title': 'Start', 'image_sources': ['', '', SITE + PHOTO]},
        {'index': 2, 'final_url': SITE + 'aktive-feuerwehr/', 'html_name': '2.html',
         'raw_dom_relative': '02_website/_dom_roh/2.dom.txt', 'title': 'Feuerwehr'},
    ]


class K25EngineTests(unittest.TestCase):
    def test_cached_jpeg_multi_document_archive_and_old_resource_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = k25_case(root)
            original = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            result = build_local_mirror(root, visited)
            self.assertEqual(result, {'pages': 2, 'resources': 3})
            website = root / '02_website'
            soup = BeautifulSoup((website / 'seiten/1.html').read_text(), 'html.parser')
            self.assertEqual((website / 'seiten' / soup.select_one('#jpeg')['src']).read_bytes(), JPEG)
            self.assertTrue(soup.select_one('#image-link')['href'].endswith('.jpg'))
            self.assertIn('1709w', soup.select_one('#responsive')['srcset'])
            diagnostics = json.loads((website / 'fehlende_referenzen.json').read_text())['references']
            missing = next(row for row in diagnostics if row['url'].endswith('empty-cache.jpg'))
            self.assertEqual(missing['reason'], 'response_body_missing')
            self.assertEqual(missing['http_status'], 304)
            manifest = json.loads((website / 'website_manifest.json').read_text())
            self.assertEqual(manifest['engine'], 'k25-derived')
            self.assertEqual(manifest['network_safety_verification'], 'PASS')
            self.assertEqual(manifest['issues'], [])
            for name, body in original.items():
                self.assertEqual((root / name).read_bytes(), body)
            self.assertNotIn('website_html', visited[0])

    def test_k25_verifier_rejects_tampered_local_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_local_mirror(root, k25_case(root))
            target = root / '02_website/seiten/1.html'
            self.assertEqual(_verify_local_html(target), [])
            soup = BeautifulSoup(target.read_text(), 'html.parser')
            script = soup.find('script')
            script.string.replace_with(script.string + '\nwindow.tampered = true;')
            target.write_text(str(soup))
            self.assertIn('Nicht freigegebenes script-Element', _verify_local_html(target))


class K25EngineBrowserTests(BrowserTestCase):
    def test_jpeg_png_responsive_images_menu_and_resource_navigation_file_and_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_local_mirror(root, k25_case(root))
            website = root / '02_website'
            server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(website)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                entries = [(website / 'seiten/1.html').as_uri(), f'http://127.0.0.1:{server.server_port}/seiten/1.html']
                for entry, width in [(entry, width) for entry in entries for width in (1100, 480)]:
                    with self.subTest(entry=entry, width=width):
                        context = self.browser.new_context(viewport={'width': width, 'height': 900}, service_workers='block')
                        external = []
                        page = context.new_page()
                        page.on('request', lambda request: external.append(request.url)
                                if urlparse(request.url).scheme in {'http', 'https'} and urlparse(request.url).hostname != '127.0.0.1' else None)
                        page.goto(entry)
                        for selector in ['#jpeg', '#png', '#responsive']:
                            self.assertTrue(page.locator(selector).evaluate('image => image.complete && image.naturalWidth > 0'))
                        self.assertEqual(page.locator('#jpeg').evaluate('image => [image.naturalWidth, image.naturalHeight]'), [2, 3])
                        expected = '-scaled.jpg' if width == 1100 else '-683x1024.jpg'
                        self.assertTrue(page.locator('#responsive').evaluate('image => image.currentSrc').endswith(expected))
                        page.locator('#about').hover()
                        self.assertTrue(page.locator('#about-menu').is_visible())
                        page.locator('#about-child').click()
                        page.wait_for_url('**/2.html')
                        page.goto(entry)
                        page.locator('#image-link').click()
                        self.assertTrue(page.url.endswith('.jpg'))
                        self.assertEqual(external, [])
                        context.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
