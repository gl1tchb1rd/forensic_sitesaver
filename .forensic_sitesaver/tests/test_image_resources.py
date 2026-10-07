# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression cases for archived images with browser/CSS URL syntax."""
import base64
import functools
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup

from capture import _load_lazy_images, _rewrite_css, build_local_mirror
from test_local_mirror import BrowserTestCase, PNG, QuietHandler


def image_case(root):
    raw = root / '02_website/_dom_roh/page.txt'
    raw.parent.mkdir(parents=True)
    raw.write_text('''<!doctype html><html><head>
      <link rel="stylesheet" href="/old/theme.css">
      <style>
        #escaped { background-image:url("/assets/photo\\2e png"); }
        #variants { background-image:image-set("/assets/Größe 1.png" 1x, url("/assets/photo.png") 2x); }
        #content::before { content:'url(/keep-this-text.png)'; }
      </style></head><body>
      <img id="unicode" src="/assets/Größe 1.png">
      <img id="lazy" src="/assets/not-recorded-placeholder.gif" data-src="/assets/photo.png">
      <img id="binary" src="/image?id=1">
      <picture><source media="(min-width: 1px)" srcset="/assets/missing.png 1x"><img id="picture" src="/assets/photo.png"></picture>
      <div id="redirected"></div><div id="escaped"></div><div id="variants"></div><div id="content"></div>
      </body></html>''', encoding='utf-8')
    entries = []
    for url, mime, body, header in [
        ('/assets/Gr%C3%B6%C3%9Fe%201.png', 'image/png', PNG, 'image/png'),
        ('/assets/photo.png', 'image/png', PNG, 'image/png'),
        ('/image?id=1', 'application/octet-stream', PNG, 'image/png'),
        ('/assets/theme.css', 'text/css', b'#redirected {background-image:url(photo.png)}', 'text/css'),
    ]:
        entries.append({'request': {'url': 'https://example.test' + url},
                        'response': {'status': 200, 'headers': [{'name': 'Content-Type', 'value': header}],
                                     'content': {'mimeType': mime, 'encoding': 'base64', 'text': base64.b64encode(body).decode()}}})
    entries.append({'request': {'url': 'https://example.test/old/theme.css'},
                    'response': {'status': 302, 'redirectURL': '/assets/theme.css'}})
    har = root / '01_har/images.har'
    har.parent.mkdir()
    har.write_text(json.dumps({'log': {'entries': entries}}))
    return [{'index': 1, 'final_url': 'https://example.test/page', 'html_name': '1.html',
             'raw_dom_relative': '02_website/_dom_roh/page.txt', 'title': 'Images'}]


class ImageResourceTests(unittest.TestCase):
    def test_css_strings_comments_parentheses_and_escaped_schemes(self):
        missing = []
        embedded = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><path fill='rgb(1,2,3)'/></svg>"
        css = f'''/* url(https://keep-text.invalid) */ .x {{content:'url(keep-text.png)';background:url("{embedded}")}}
          .y {{background:image-set("photo.png" 1x type("image/png"), url(photo.png) 2x)}}
          .z {{background:url("https\\3a //blocked.invalid/image.png")}}'''
        result = _rewrite_css(css, 'https://example.test/assets/main.css', Path('/view/main.css'),
                              {'https://example.test/assets/photo.png': {'local_path': Path('/view/photo.png')}}, {}, missing)
        self.assertIn('/* url(https://keep-text.invalid) */', result)
        self.assertIn("content:'url(keep-text.png)'", result)
        self.assertIn(embedded, result)
        self.assertIn('image-set("photo.png" 1x type("image/png"), url("photo.png") 2x)', result)
        self.assertIn('url("data:,")', result)
        self.assertEqual([row['url'] for row in missing], ['https://blocked.invalid/image.png'])

    def test_missing_images_distinguish_http_failures_absent_bodies_and_no_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = image_case(root)
            raw = root / visited[0]['raw_dom_relative']
            raw.write_text(raw.read_text().replace('</body>', '<img src="/no-body.jpg"><img src="/error.jpg"><img src="/never.jpg"></body>'))
            har = root / '01_har/images.har'
            document = json.loads(har.read_text())
            document['log']['entries'].extend([
                {'request': {'url': 'https://example.test/no-body.jpg'}, 'response': {'status': 200, 'content': {'mimeType': 'image/jpeg'}}},
                {'request': {'url': 'https://example.test/error.jpg'}, 'response': {'status': 404, 'content': {'mimeType': 'image/jpeg'}}},
            ])
            har.write_text(json.dumps(document))
            build_local_mirror(root, visited)
            rows = json.loads((root / '02_website/fehlende_referenzen.json').read_text())['references']
            reasons = {urlparse(row['url']).path: row['reason'] for row in rows}
            self.assertEqual(reasons['/no-body.jpg'], 'response_body_missing')
            self.assertEqual(reasons['/error.jpg'], 'http_error')
            self.assertEqual(reasons['/never.jpg'], 'not_in_har')

    def test_archived_image_variants_are_resolved_without_changing_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            visited = image_case(root)
            original = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            build_local_mirror(root, visited)
            page_file = root / '02_website/seiten/1.html'
            soup = BeautifulSoup(page_file.read_text(), 'html.parser')
            for selector in ['#unicode', '#lazy', '#binary', '#picture']:
                path = page_file.parent / unquote(soup.select_one(selector)['src'])
                self.assertTrue(path.is_file(), selector)
                self.assertEqual(path.read_bytes(), PNG)
            self.assertIsNone(soup.select_one('picture source'))
            css = (page_file.parent / unquote(soup.find('link')['href'])).read_text()
            self.assertIn('../ressourcen/', css)
            self.assertNotIn('data:,', css)
            self.assertIn("content:'url(/keep-this-text.png)'", soup.find('style').get_text())
            diagnostics = json.loads((root / '02_website/fehlende_referenzen.json').read_text())['references']
            self.assertFalse(any('Größe' in row['url'] or '/old/photo.png' in row['url'] for row in diagnostics))
            for path, body in original.items():
                self.assertEqual((root / path).read_bytes(), body)


class ImageResourceBrowserTests(BrowserTestCase):
    def test_below_fold_native_lazy_image_is_recorded_before_offline_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'
            source.mkdir()
            (source / 'photo.jpg').write_bytes(PNG)
            markup = '<html><body><div style="height:12000px"></div><img loading="lazy" width="100" height="100" src="photo.jpg"></body></html>'
            (source / 'index.html').write_text(markup)
            server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(source)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                har = root / '01_har/lazy.har.zip'
                har.parent.mkdir()
                context = self.browser.new_context(service_workers='block', record_har_path=str(har), record_har_content='attach')
                page = context.new_page()
                url = f'http://127.0.0.1:{server.server_port}/index.html'
                page.goto(url)
                self.assertEqual(page.locator('img').evaluate('image => image.naturalWidth'), 0)
                before = page.content()
                limited = _load_lazy_images(page, 0)
                self.assertEqual(limited['positions_visited'], 0)
                self.assertTrue(limited['limited'])
                self.assertEqual(page.locator('img').evaluate('image => image.naturalWidth'), 0)
                result = _load_lazy_images(page, 3000)
                self.assertEqual(result['loaded_images'], 1)
                self.assertEqual(page.evaluate('scrollY'), 0)
                self.assertEqual(page.content(), before)
                raw = root / '02_website/_dom_roh/1.txt'
                raw.parent.mkdir(parents=True)
                raw.write_text(page.content())
                context.close()
                build_local_mirror(root, [{'index': 1, 'final_url': url, 'title': 'Lazy', 'html_name': '1.html',
                                           'raw_dom_relative': str(raw.relative_to(root))}])
                context = self.browser.new_context(service_workers='block')
                page = context.new_page()
                page.goto((root / '02_website/seiten/1.html').as_uri())
                self.assertGreater(page.locator('img').evaluate('image => image.naturalWidth'), 0)
                context.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_file_and_http_display_legacy_images_and_css_variants_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_local_mirror(root, image_case(root))
            website = root / '02_website'
            server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(website)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for url in [(website / 'seiten/1.html').as_uri(), f'http://127.0.0.1:{server.server_port}/seiten/1.html']:
                    with self.subTest(url=url):
                        context = self.browser.new_context(service_workers='block')
                        attempted = []
                        def guard(route):
                            parsed = urlparse(route.request.url)
                            if parsed.scheme in {'http', 'https'} and parsed.hostname != '127.0.0.1':
                                attempted.append(route.request.url)
                                route.abort()
                            else:
                                route.continue_()
                        context.route('**/*', guard)
                        page = context.new_page()
                        page.goto(url)
                        for selector in ['#unicode', '#lazy', '#binary', '#picture']:
                            self.assertGreater(page.locator(selector).evaluate('image => image.naturalWidth'), 0, selector)
                        for selector in ['#redirected', '#escaped', '#variants']:
                            self.assertTrue(page.locator(selector).evaluate(r'''async element => {
                                const css = getComputedStyle(element).backgroundImage;
                                const urls = Array.from(css.matchAll(/(?:url\(|image-set\()"([^"]+)"/g), m => m[1]);
                                return urls.length > 0 && (await Promise.all(urls.map(url => new Promise(resolve => {
                                    const img = new Image(); img.onload = () => resolve(img.naturalWidth > 0);
                                    img.onerror = () => resolve(false); img.src = url;
                                })))).every(Boolean);
                            }'''), selector)
                        self.assertEqual(attempted, [])
                        context.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == '__main__':
    unittest.main()
