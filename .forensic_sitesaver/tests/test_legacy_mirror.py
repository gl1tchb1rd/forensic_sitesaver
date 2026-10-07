# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Archive layouts supported by K25-SiteSaver and full browser capture checks."""
import base64
import contextlib
import functools
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup

from capture import _har_body, build_local_mirror, capture_website, rebuild_local_mirror
from test_local_mirror import BrowserTestCase, PNG, QuietHandler

LONG_IMAGE = '11-Freiwillige-Feuerwehr-Vestenberg_Jubilaeum-125-Jahre_10.06.24-11-683x1024.jpg'

def archive_case(root):
    raw = root / '02_website/_dom_roh/1.txt'
    raw.parent.mkdir(parents=True)
    raw.write_text(f'''<html><head><link rel="stylesheet" href="https://example.test/theme.css"></head><body>
      <img id="sha" src="https://example.test/sha.jpg">
      <img id="nested" src="https://example.test/{LONG_IMAGE}">
      <img id="latest" src="https://example.test/latest.php">
      <div id="background"></div>
      </body></html>''')
    har = root / '01_har/segment_0001.har.zip'
    har.parent.mkdir()
    entries = []
    with zipfile.ZipFile(har, 'w') as z:
        for url, mime, body, content, name in [
            ('sha.jpg', 'image/png', PNG, {'_sha1': 'sha-body.png'}, 'resources/sha-body.png'),
            (LONG_IMAGE, 'image/png', PNG, {'_file': 'nested-body.png'}, 'attachments/nested-body.png'),
            ('latest.php', 'image/png', b'old-invalid-image', {'_file': 'old.png'}, 'old.png'),
            ('latest.php', 'image/png', PNG, {'_file': 'latest.png'}, 'latest.png'),
            ('photo-%C3%A4.png', 'image/png', PNG, {'_file': 'accent.png'}, 'accent.png'),
            ('theme.css', 'text/css', '#background {background-image:url("photo-ä.png")}'.encode('latin-1'), {'_file': 'theme.css'}, 'theme.css'),
        ]:
            z.writestr(name, body)
            entries.append({'request': {'url': 'https://example.test/' + url},
                            'response': {'status': 200, 'content': {'mimeType': mime, **content}}})
        z.writestr('har.har', json.dumps({'log': {'entries': entries}}))
    return [{'index': 1, 'final_url': 'https://example.test/', 'html_name': '1.html',
             'raw_dom_relative': '02_website/_dom_roh/1.txt', 'title': 'Legacy resources'}]


class LegacyMirrorTests(unittest.TestCase):
    def test_long_windows_style_output_root_uses_short_resource_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ('application_folder_' * 8)
            build_local_mirror(root, archive_case(root))
            page = root / '02_website/seiten/1.html'
            soup = BeautifulSoup(page.read_text(), 'html.parser')
            local = page.parent / unquote(soup.select_one('#nested')['src'])
            self.assertEqual(local.read_bytes(), PNG)
            self.assertIn('_kurz', str(local))
            manifest = json.loads((root / '02_website/ressourcen_manifest.json').read_text())['resources']
            self.assertTrue(any(row.get('path_shortened') for row in manifest))
            for row in manifest:
                self.assertLess(len(str(root / '02_website' / row['local_relative'])), 260)

    def test_legacy_attachment_layouts_css_encoding_and_latest_resource_preserve_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = archive_case(root)
            original = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            build_local_mirror(root, visited)
            page = root / '02_website/seiten/1.html'
            soup = BeautifulSoup(page.read_text(), 'html.parser')
            for selector in ['#sha', '#nested', '#latest']:
                image = soup.select_one(selector)
                self.assertEqual((page.parent / unquote(image['src'])).read_bytes(), PNG, selector)
                self.assertTrue(image['src'].endswith('.png'))
            manifest = json.loads((root / '02_website/ressourcen_manifest.json').read_text())['resources']
            versions = [row for row in manifest if row['original_url'].endswith('/latest.php')]
            self.assertEqual(len(versions), 2)
            self.assertEqual({(root / '02_website' / row['local_relative']).read_bytes() for row in versions}, {PNG, b'old-invalid-image'})
            diagnostics = json.loads((root / '02_website/fehlende_referenzen.json').read_text())['references']
            self.assertEqual(diagnostics, [])
            css = (page.parent / unquote(soup.find('link')['href'])).read_text()
            self.assertIn('../ressourcen/', css)
            for path, body in original.items():
                self.assertEqual((root / path).read_bytes(), body)

    def test_inline_base64_and_attached_sidecars_are_read_but_outside_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            har = root / 'har/archive.har'
            har.parent.mkdir()
            har.write_text('{}')
            (har.parent / 'photo.png').write_bytes(PNG)
            self.assertEqual(_har_body(har, {'_sha1': 'photo.png'}), PNG)
            self.assertEqual(_har_body(har, {'_file': 'photo.png', 'text': ''}), PNG)
            self.assertEqual(_har_body(har, {'_file': 'absent.png', 'text': base64.b64encode(PNG).decode(), 'encoding': 'BASE64'}), PNG)
            (root / 'outside.png').write_bytes(PNG)
            self.assertIsNone(_har_body(har, {'_file': '../outside.png'}))
            self.assertIsNone(_har_body(har, {'_file': str(root / 'outside.png')}))

    def test_ambiguous_zip_basenames_are_not_matched_to_the_wrong_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'archive.har.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('one/photo.png', PNG)
                z.writestr('two/photo.png', b'other')
            self.assertIsNone(_har_body(archive, {'_file': 'photo.png'}))

    def test_k25_page_metadata_with_windows_paths_rebuilds_without_changing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'case'
            visited = archive_case(root)
            item = visited[0]
            item['dom_raw'] = item.pop('raw_dom_relative').replace('/', '\\')
            item.pop('html_name')
            metadata = root / '04_metadaten/visited_pages.json'
            metadata.parent.mkdir()
            metadata.write_text(json.dumps(visited))
            original = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            output = Path(tmp) / 'view'
            self.assertEqual(rebuild_local_mirror(root, output)['pages'], 1)
            self.assertTrue((output / 'index.html').is_file())
            for path, body in original.items():
                self.assertEqual((root / path).read_bytes(), body)


class LegacyMirrorBrowserTests(BrowserTestCase):
    def test_full_capture_to_har_to_offline_picture_in_file_and_http_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ('windows_path_' * 8)
            source = root / 'source'
            source.mkdir(parents=True)
            (source / 'first.png').write_bytes(PNG)
            (source / LONG_IMAGE).write_bytes(PNG)
            (source / 'small.jpg').write_bytes(PNG)
            (source / 'index.html').write_text(f'''<html><head><title>WordPress-like fixture</title></head><body>
              <img src="first.png" width="1024" height="1024">
              <div style="height:10000px"></div>
              <img id="poster" loading="lazy" width="683" height="1024" src="{LONG_IMAGE}"
                srcset="{LONG_IMAGE} 683w, small.jpg 200w" sizes="auto, (max-width: 683px) 100vw, 683px">
              <script>fetch('/blocked', {{method:'POST'}});</script></body></html>''')
            server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(source)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                # Use the real segmented HAR API and all capture/mirror code.
                # Only select the installed browser executable and stub unrelated external analyses.
                @contextlib.contextmanager
                def playwright_for_capture():
                    yield SimpleNamespace(chromium=SimpleNamespace(launch=lambda **kwargs: self.manager.chromium.launch(
                        executable_path=os.environ.get('SITESAVER_TEST_CHROMIUM'), **kwargs)))
                with patch('capture.sync_playwright', playwright_for_capture), \
                     patch('capture.analyze_domain', return_value={'external_calls': []}), \
                     patch('capture.capture_tls', return_value={'hosts_attempted': []}), \
                     contextlib.redirect_stdout(io.StringIO()):
                    case = capture_website(f'http://127.0.0.1:{server.server_port}/index.html', root / 'cases',
                                           headless=True, max_pages=1, segment_pages=1, delay_ms=0, timeout_ms=5000)
                visited = json.loads((case / '04_metadaten/visited_pages.json').read_text())
                self.assertEqual(visited[0]['lazy_image_loading']['loaded_images'], 1)
                self.assertTrue(visited[0]['image_sources'][1].endswith('/' + LONG_IMAGE))
                blocked = json.loads((case / '04_metadaten/blocked_network_requests.json').read_text())
                self.assertTrue(any(row['method'] == 'POST' for row in blocked))
                website = case / '02_website'
                html = website / 'seiten' / visited[0]['html_name']
                view_server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(website)))
                view_thread = threading.Thread(target=view_server.serve_forever, daemon=True)
                view_thread.start()
                try:
                    for url in [html.as_uri(), f'http://127.0.0.1:{view_server.server_port}/seiten/{html.name}']:
                        with self.subTest(url=url):
                            context = self.browser.new_context(service_workers='block')
                            attempted = []
                            def guard(route):
                                address = urlparse(route.request.url)
                                if address.scheme in {'http', 'https'} and not (
                                    address.hostname == '127.0.0.1' and address.port == view_server.server_port):
                                    attempted.append(route.request.url)
                                    route.abort()
                                else:
                                    route.continue_()
                            context.route('**/*', guard)
                            page = context.new_page()
                            page.goto(url)
                            self.assertGreater(page.locator('#poster').evaluate('image => image.naturalWidth'), 0)
                            self.assertTrue(page.locator('#poster').get_attribute('src').endswith('.jpg'))
                            self.assertIn('_kurz', page.locator('#poster').get_attribute('src'))
                            self.assertEqual(page.locator('script').count(), 0)
                            self.assertEqual(attempted, [])
                            context.close()
                finally:
                    view_server.shutdown()
                    view_server.server_close()
                    view_thread.join()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == '__main__':
    unittest.main()
