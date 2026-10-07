# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib
import html
import json
import mimetypes
import os
import re
import shutil
import sys
import time
import zipfile
from collections import deque
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from common import (
    APP_NAME, APP_VERSION, REPOSITORY_URL, ensure_dir, folder_size, hash_tree, hostname_from_value,
    human_size, is_first_party, is_stateful_get, iso_now, normalize_url, registrable_domain,
    relative_to_case, safe_exception, sanitize_component, sanitize_url, sha256_bytes, sha256_file,
    timestamp_slug, write_csv, write_json, write_text,
)
from domain_analysis import analyze_domain
from har_analysis import analyze_har, discover_har_files, read_har_document
from tls_capture import capture_tls
from reports import export_reports, write_capture_report
from offline_menu import MENU_SCRIPT_HASH, PREFIX as MENU_PREFIX, append_menu_script, prepare_offline_menus
from offline_links import (
    LINK_SCRIPT_HASH, add_image_map_info_buttons, annotate_inactive_link,
    append_link_inspector, clear_link_annotations,
)

ACTIVE_TAGS = {"script", "iframe", "frame", "object", "embed", "applet", "portal", "base",
               "animate", "animatemotion", "animatetransform", "set"}
RESOURCE_MIME_PREFIXES = ("image/", "font/", "audio/", "video/", "text/css")
CSS_STRING = r'"(?:\\[\s\S]|[^"\\])*"' + r"|'(?:\\[\s\S]|[^'\\])*'"
CSS_TOKEN_RE = re.compile(
    rf"(?P<comment>/\*.*?\*/)|(?P<string>{CSS_STRING})|"
    r"(?P<function>[-\w]+)\(|(?P<open>\()|(?P<close>\))|(?P<import>@import\b)", re.I | re.S)
CSS_URL_ARGUMENT_RE = re.compile(rf"\s*(?P<value>{CSS_STRING}|(?:\\[\s\S]|[^)\"'])*?)\s*\)", re.S)


def _url_without_fragment(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


def _resource_key(url: str) -> str:
    """Match browser-encoded URLs without discarding query strings or decoding slashes."""
    p = urlparse(_url_without_fragment(url))
    def encoded(value: str, safe: str) -> str:
        return re.sub(r"%[0-9a-fA-F]{2}", lambda m: m[0].upper(), quote(value, safe=safe))
    return urlunparse((p.scheme, p.netloc, encoded(p.path, "/:@!$&'()*+,;=-._~%"),
                       encoded(p.params, ":@!$&'()*+,;=-._~%"),
                       encoded(p.query, "/?:@!$&'()*+,;=-._~%"), ""))


def _css_unescape(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match[1]
        if re.match(r"[0-9a-fA-F]", token):
            codepoint = int(token.strip(), 16)
            return chr(codepoint) if 0 < codepoint <= 0x10FFFF and not 0xD800 <= codepoint <= 0xDFFF else "\ufffd"
        return "" if token in {"\n", "\r", "\r\n", "\f"} else token
    return re.sub(r"\\([0-9a-fA-F]{1,6}[ \t\r\n\f]?|\r\n|[\s\S])", replace, value)


def _css_quoted(value: str) -> str:
    value = value.replace("\\", "\\\\").replace('"', '\\"')
    for character, escaped in (("\n", r"\a "), ("\r", r"\d "), ("\f", r"\c ")):
        value = value.replace(character, escaped)
    return '"' + value + '"'


def _page_slug(url: str, index: int) -> str:
    p = urlparse(url)
    tail = Path(p.path.rstrip("/")).name or "index"
    tail = sanitize_component(tail, 60)
    if p.query:
        tail += "__q_" + hashlib.sha256(p.query.encode()).hexdigest()[:8]
    return f"{index:04d}_{tail}.html"


def _resource_relpath(url: str, mime: str, body: bytes) -> Path:
    p = urlparse(url)
    host = sanitize_component(p.hostname or "unknown-host", 160)
    raw_path = p.path or "/resource"
    parts = [sanitize_component(x, 100) for x in raw_path.split("/") if x]
    if not parts:
        parts = ["index"]
    name = parts[-1]
    if "." not in name:
        ext = mimetypes.guess_extension((mime or "").split(";", 1)[0].strip()) or ""
        name += ext
    if p.query:
        stem, ext = os.path.splitext(name)
        name = f"{stem}__q_{hashlib.sha256(p.query.encode()).hexdigest()[:8]}{ext}"
    parts[-1] = name
    return Path(host, *parts)


def _har_body(segment: Path, content: dict[str, Any]) -> bytes | None:
    if not content:
        return None
    file_ref = content.get("_file")
    if file_ref and zipfile.is_zipfile(segment):
        try:
            with zipfile.ZipFile(segment, "r") as z:
                return z.read(str(file_ref))
        except Exception:
            return None
    text = content.get("text")
    if text is None:
        return None
    try:
        if content.get("encoding") == "base64":
            return base64.b64decode(text)
        return str(text).encode("utf-8")
    except Exception:
        return None


def _safe_resource_mime(mime: str) -> bool:
    mime = (mime or "").lower().split(";", 1)[0].strip()
    return any(mime.startswith(prefix) for prefix in RESOURCE_MIME_PREFIXES)


def _rel_link(from_file: Path, to_file: Path) -> str:
    return quote(os.path.relpath(to_file, from_file.parent).replace(os.sep, "/"), safe="/")


def _srcset_candidates(value: str) -> list[tuple[str, str]]:
    """Read candidate URLs without splitting the commas inside data URLs."""
    candidates = []
    position = 0
    while position < len(value):
        while position < len(value) and (value[position].isspace() or value[position] == ","):
            position += 1
        start = position
        while position < len(value) and not value[position].isspace():
            position += 1
        url = value[start:position]
        if not url:
            break
        if url.endswith(","):
            candidates.append((url.rstrip(","), ""))
            continue
        start = position
        while position < len(value) and value[position] != ",":
            position += 1
        descriptor = value[start:position].strip()
        # Invalid descriptors cannot be selected by the browser.
        if not descriptor or re.fullmatch(r"(?:[1-9]\d*w|(?:\d+(?:\.\d+)?|\.\d+)x)", descriptor):
            candidates.append((url, descriptor))
        position += 1
    return candidates


def _image_sources(page: Any) -> list[str]:
    """Record selected image URLs separately, without modifying the raw DOM."""
    try:
        sources = page.evaluate("""() => Array.from(document.images, image =>
            image.complete && image.naturalWidth ? image.currentSrc : '')""")
        if isinstance(sources, list) and all(isinstance(source, str) for source in sources):
            return sources
    except Exception:
        pass
    return []


def _load_lazy_images(page: Any, timeout_ms: int) -> dict[str, Any]:
    """Visit image positions while HAR is active; restore the original viewport."""
    try:
        result = page.evaluate(r'''async budget => {
            const deadline = performance.now() + Math.max(0, budget - 120);
            const original = {x: scrollX, y: scrollY};
            const candidates = Array.from(document.images).filter(image =>
                (image.loading === 'lazy' && !image.naturalWidth) ||
                ['data-src', 'data-lazy-src', 'data-original', 'data-srcset'].some(name => image.hasAttribute(name)));
            const initiallyLoaded = new Set(candidates.filter(image => image.naturalWidth > 0));
            const positions = [...new Set(candidates.filter(image => image.getClientRects().length)
                .map(image => Math.max(0, image.getBoundingClientRect().top + scrollY - innerHeight / 2)))];
            let visited = 0;
            const pause = () => new Promise(resolve => setTimeout(resolve, Math.min(120, Math.max(0, deadline - performance.now()))));
            try {
                for (const top of positions.slice(0, 40)) {
                    if (performance.now() >= deadline) break;
                    window.scrollTo({left: original.x, top, behavior: 'instant'});
                    visited++;
                    await pause();
                }
                while (visited && candidates.some(image => !image.complete) && performance.now() < deadline) await pause();
            } finally {
                if (visited) {
                    window.scrollTo({left: original.x, top: original.y, behavior: 'instant'});
                    // Give IntersectionObserver/scroll handlers time to restore the initial view.
                    await new Promise(resolve => setTimeout(resolve, 120));
                }
            }
            return {candidate_images: candidates.length, positions_visited: visited,
                loaded_images: candidates.filter(image => image.naturalWidth > 0 && !initiallyLoaded.has(image)).length,
                limited: visited < positions.length || candidates.some(image => !image.complete)};
        }''', max(0, min(timeout_ms, 8000)))
        if isinstance(result, dict):
            return result
    except Exception as exc:
        return {"error": safe_exception(exc)}
    return {}


def _rewrite_css(css_text: str, css_url: str, css_runtime_file: Path,
                 url_map: dict[str, dict[str, Any]], runtime_css_map: dict[str, Path],
                 missing_references: list[dict[str, str]] | None = None) -> str:
    def missing(url: str, kind: str) -> None:
        if missing_references is not None:
            missing_references.append({"page": css_runtime_file.name, "kind": kind, "url": url})

    def resolve_resource(raw: str, kind: str = "css-url") -> str:
        raw = raw.strip()
        if not raw or raw.lower().startswith("data:") or raw.startswith("#"):
            return raw
        resolved = urljoin(css_url, raw)
        absolute = _resource_key(resolved)
        rec = url_map.get(absolute)
        if not rec or (kind == "css-import" and absolute not in runtime_css_map):
            missing(resolved, kind)
            return "data:,"
        target = runtime_css_map.get(absolute) or rec.get("local_path")
        if not target:
            return "data:,"
        fragment = urlparse(resolved).fragment
        return _rel_link(css_runtime_file, target) + ("#" + fragment if fragment else "")

    # Tokenize strings/comments first so content:"url(...)" stays text and
    # quoted URLs may contain parentheses. image-set permits bare strings.
    output: list[str] = []
    functions: list[str] = []
    position = 0
    expect_import = False
    while match := CSS_TOKEN_RE.search(css_text, position):
        gap = css_text[position:match.start()]
        output.append(gap)
        if gap.strip():
            expect_import = False
        token = match[0]
        position = match.end()
        if match.lastgroup == "import":
            expect_import = True
        elif match.lastgroup == "function":
            name = match["function"].lower()
            if name == "url" and (argument := CSS_URL_ARGUMENT_RE.match(css_text, position)):
                raw = argument["value"].strip()
                if raw[:1] in {'"', "'"}:
                    raw = raw[1:-1]
                token = 'url(' + _css_quoted(resolve_resource(_css_unescape(raw),
                    "css-import" if expect_import else "css-url")) + ')'
                position = argument.end()
            else:
                functions.append(name)
            expect_import = False
        elif match.lastgroup == "string":
            if expect_import or (functions and functions[-1] in {"image-set", "-webkit-image-set"}):
                token = _css_quoted(resolve_resource(_css_unescape(token[1:-1]),
                    "css-import" if expect_import else "css-image-set"))
            expect_import = False
        elif match.lastgroup == "open":
            functions.append("")
        elif match.lastgroup == "close" and functions:
            functions.pop()
        output.append(token)
    output.append(css_text[position:])
    return "".join(output)


def build_local_mirror(case_root: Path, visited: list[dict[str, Any]], *,
                       output_dir: Path | None = None) -> dict[str, Any]:
    website = ensure_dir(output_dir if output_dir is not None else case_root / "02_website")
    pages_dir = ensure_dir(website / "seiten")
    resources_dir = ensure_dir(website / "ressourcen")
    runtime_css_dir = ensure_dir(website / "_runtime_css")
    har_files = discover_har_files(case_root / "01_har")

    url_map: dict[str, dict[str, Any]] = {}
    manifest_rows: list[dict[str, Any]] = []
    redirects: dict[str, str] = {}
    resource_issues: dict[str, dict[str, Any]] = {}
    missing_references: list[dict[str, str]] = []

    # Extract safe-to-view resources byte-identically. HAR remains the source for everything else.
    for segment in har_files:
        try:
            doc = read_har_document(segment)
        except Exception:
            continue
        for entry in ((doc.get("log") or {}).get("entries") or []):
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            raw_url = str(req.get("url") or "")
            if urlparse(raw_url).scheme not in {"http", "https"}:
                continue
            url = _resource_key(raw_url)
            if url in url_map:
                continue
            status = int(resp.get("status") or 0)
            if 300 <= status < 400 and resp.get("redirectURL"):
                redirects[url] = _resource_key(urljoin(raw_url, resp["redirectURL"]))
                resource_issues[url] = {"reason": "redirect_target_not_archived", "http_status": status}
                continue
            if not 200 <= status < 300:
                resource_issues[url] = {"reason": "http_error" if status else "no_response", "http_status": status}
                continue
            content = resp.get("content") or {}
            headers = {str(h.get("name") or "").lower(): str(h.get("value") or "")
                       for h in resp.get("headers") or []}
            mime = str(content.get("mimeType") or headers.get("content-type") or "").split(";", 1)[0].lower().strip()
            if mime in {"", "application/octet-stream"}:
                header_mime = headers.get("content-type", "").split(";", 1)[0].lower().strip()
                mime = header_mime if _safe_resource_mime(header_mime) else mimetypes.guess_type(urlparse(url).path)[0] or mime
            if not _safe_resource_mime(mime):
                resource_issues[url] = {"reason": "unsupported_mime", "http_status": status, "mime": mime}
                continue
            body = _har_body(segment, content)
            if body is None:
                resource_issues[url] = {"reason": "response_body_missing", "http_status": status, "mime": mime}
                continue
            rel = _resource_relpath(url, mime, body)
            out = resources_dir / rel
            if out.exists() and out.read_bytes() != body:
                out = out.with_name(out.stem + "__" + sha256_bytes(body)[:8] + out.suffix)
            ensure_dir(out.parent)
            if not out.exists():
                out.write_bytes(body)
            rec = {
                "original_url": _url_without_fragment(raw_url), "mime": mime, "http_status": resp.get("status"),
                "size": len(body), "sha256": sha256_bytes(body),
                "local_path": out, "local_relative": out.relative_to(website).as_posix(),
                "har_segment": segment.name, "byte_preserved": True,
            }
            url_map[url] = rec
            manifest_rows.append({k: v for k, v in rec.items() if k != "local_path"})

    # The DOM often retains the pre-redirect image URL; HAR stores the body at
    # the final URL. Resolve aliases only to an actually archived resource.
    for original, target in redirects.items():
        seen_redirects = {original}
        while target in redirects and target not in seen_redirects:
            seen_redirects.add(target)
            target = redirects[target]
        if target in url_map:
            url_map[original] = url_map[target]

    # Runtime CSS copies – original CSS above remains byte-identical.
    runtime_css_map: dict[str, Path] = {}
    for url, rec in url_map.items():
        if rec.get("mime") == "text/css":
            target = runtime_css_dir / (hashlib.sha256(rec["original_url"].encode()).hexdigest()[:16] + ".css")
            runtime_css_map[url] = target
    for url, target in runtime_css_map.items():
        rec = url_map[url]
        try:
            original = rec["local_path"].read_text(encoding="utf-8", errors="replace")
            rewritten = _rewrite_css(original, rec["original_url"], target, url_map, runtime_css_map, missing_references)
            write_text(target, rewritten)
        except Exception:
            write_text(target, "/* CSS konnte nicht für die sichere Laufzeitfassung verarbeitet werden. */")

    # Map archived page URLs.
    page_map: dict[str, Path] = {}
    for item in visited:
        page_map[_url_without_fragment(item["final_url"])] = pages_dir / item["html_name"]
        if item.get("requested_url"):
            page_map[_url_without_fragment(item["requested_url"])] = pages_dir / item["html_name"]

    page_results: list[dict[str, Any]] = []
    menu_results: list[dict[str, Any]] = []
    link_results: list[dict[str, Any]] = []
    for item in visited:
        html_file = pages_dir / item["html_name"]
        raw_source = case_root / item["raw_dom_relative"]
        if not raw_source.exists():
            continue
        raw_html = raw_source.read_text(encoding="utf-8", errors="replace")
        soup = BeautifulSoup(raw_html, "html.parser")
        base_url = item["final_url"]
        base = soup.find("base", href=True)
        if base:
            base_url = urljoin(base_url, str(base["href"]))

        for img, selected in zip(soup.find_all("img"), item.get("image_sources") or []):
            if selected and (selected.lower().startswith("data:") or _resource_key(selected) in url_map):
                img["src"] = selected
                img.attrs.pop("srcset", None)
                img.attrs.pop("data-srcset", None)
                picture = img.find_parent("picture")
                if picture:
                    for source in list(picture.find_all("source")):
                        source.decompose()

        for tag in list(soup.find_all(ACTIVE_TAGS)):
            tag.decompose()
        for meta in list(soup.find_all("meta")):
            if str(meta.get("http-equiv") or "").lower() in {"refresh", "content-security-policy"}:
                meta.decompose()

        # Event handlers / active attributes.
        for tag in soup.find_all(True):
            for attr in list(tag.attrs):
                low = attr.lower()
                if low.startswith("on") or low in {"nonce", "integrity", "crossorigin", "ping", "target", "download"}:
                    del tag.attrs[attr]

        clear_link_annotations(soup)
        menu_result = prepare_offline_menus(soup, item["final_url"], base_url)
        has_menus = bool(menu_result["menus"])
        menu_results.append({"page": item["html_name"], **menu_result})

        # Forms become inert; controls stay visible but disabled.
        for form in soup.find_all("form"):
            form.attrs.pop("action", None)
            form.attrs.pop("method", None)
            form["data-forensic-sitesaver-form-disabled"] = "true"
        for control in soup.find_all(["input", "button", "select", "textarea"]):
            if not (control.name == "button" and control.has_attr(MENU_PREFIX + "controls")):
                control["disabled"] = "disabled"

        # Links: archived internal pages remain clickable, everything else becomes inert text/link marker.
        inactive_links: list[dict[str, str]] = []
        for a in soup.find_all(["a", "area"]):
            href = str(a.get("href") or a.get("xlink:href") or "").strip()
            if not href:
                continue
            original_url = urljoin(base_url, href)
            target = page_map.get(_url_without_fragment(original_url))
            if target:
                fragment = urlparse(original_url).fragment
                local = _rel_link(html_file, target) + ("#" + fragment if fragment else "")
                for attr in ("href", "xlink:href"):
                    if a.has_attr(attr):
                        a[attr] = local
            else:
                inactive_links.append(annotate_inactive_link(soup, a, original_url, item["final_url"]))
                missing_references.append({"page": item["html_name"], "kind": "navigation", "url": original_url})
        has_inactive_links = bool(inactive_links)
        if has_inactive_links:
            add_image_map_info_buttons(soup, item["final_url"])
        link_results.append({"page": item["html_name"], "links": inactive_links})

        def local_resource(raw: str, kind: str) -> str | None:
            raw = raw.strip()
            if raw.lower().startswith("data:") or raw.startswith("#"):
                return raw
            absolute_url = urljoin(base_url, raw)
            rec = url_map.get(_resource_key(absolute_url))
            if rec:
                fragment = urlparse(absolute_url).fragment
                return _rel_link(html_file, rec["local_path"]) + ("#" + fragment if fragment else "")
            missing_references.append({"page": item["html_name"], "kind": kind, "url": absolute_url})
            return None

        def rewrite_attr(tag: Any, attr: str) -> None:
            raw = str(tag.get(attr) or "").strip()
            if not raw:
                return
            local = local_resource(raw, attr)
            if local is not None:
                tag[attr] = local
            else:
                tag[f"data-original-{attr}"] = urljoin(base_url, raw)
                tag[attr] = "data:,"

        for img in soup.find_all("img"):
            # Lazy attributes are only useful when their body already exists in
            # HAR. Do not make additional requests while building the mirror.
            src = str(img.get("src") or "")
            if not src or src.lower().startswith("data:") or _resource_key(urljoin(base_url, src)) not in url_map:
                for lazy_attr in ("data-src", "data-lazy-src", "data-original"):
                    candidate = str(img.get(lazy_attr) or "")
                    if candidate and _resource_key(urljoin(base_url, candidate)) in url_map:
                        img["src"] = candidate
                        break
            rewrite_attr(img, "src")
            img["loading"] = "eager"
        for tag in soup.find_all(["img", "source"]):
            srcset = str(tag.get("srcset") or tag.get("data-srcset") or "")
            if srcset:
                candidates = []
                fallback = None
                for raw, descriptor in _srcset_candidates(srcset):
                    local = local_resource(raw, "srcset")
                    if local is not None:
                        if fallback is None:
                            fallback = local
                        candidates.append(local + (" " + descriptor if descriptor else ""))
                if candidates:
                    tag["srcset"] = ", ".join(candidates)
                    if tag.name == "img" and (not tag.get("src") or tag.has_attr("data-original-src")):
                        # A blocked src otherwise becomes a broken 1x candidate
                        # and can win over the only archived (e.g. 2x) variant.
                        tag["src"] = fallback
                else:
                    tag.attrs.pop("srcset", None)
                    # An empty picture source can hide the archived img fallback.
                    if tag.name == "source" and tag.find_parent("picture"):
                        tag.decompose()
        for media in soup.find_all(["audio", "video", "source"]):
            rewrite_attr(media, "src")
        # SVG images are inert in an <img>/CSS image context. External SVG use
        # references are neutralized; local fragment references stay intact.
        for image in soup.find_all("image"):
            for attr in ("href", "xlink:href"):
                rewrite_attr(image, attr)
        for use in soup.find_all("use"):
            for attr in ("href", "xlink:href"):
                if use.has_attr(attr) and not str(use[attr]).startswith("#"):
                    use.attrs.pop(attr, None)
        for video in soup.find_all("video"):
            rewrite_attr(video, "poster")
        for tag in soup.find_all(attrs={"background": True}):
            rewrite_attr(tag, "background")

        # Stylesheets use rewritten runtime CSS copies.
        for link in list(soup.find_all("link")):
            rels = [str(x).lower() for x in (link.get("rel") or [])]
            href = str(link.get("href") or "")
            if "stylesheet" in rels and href:
                absolute = _resource_key(urljoin(base_url, href))
                target = runtime_css_map.get(absolute)
                if target:
                    link["href"] = _rel_link(html_file, target)
                    link.attrs.pop("integrity", None)
                    link.attrs.pop("crossorigin", None)
                else:
                    missing_references.append({"page": item["html_name"], "kind": "stylesheet", "url": absolute})
                    link.decompose()
            elif "icon" in rels and href:
                rewrite_attr(link, "href")
            else:
                # Preconnect, DNS-prefetch and preload are unnecessary offline.
                link.decompose()

        for tag in soup.find_all(style=True):
            tag["style"] = _rewrite_css(str(tag.get("style") or ""), base_url, html_file, url_map, runtime_css_map, missing_references)
        for style_tag in soup.find_all("style"):
            if style_tag.string:
                style_tag.string.replace_with(_rewrite_css(style_tag.string, base_url, html_file, url_map, runtime_css_map, missing_references))

        # Only our fixed menu controller may execute; original code remains
        # removed. file: supports opening the viewing copy directly.
        if soup.head is None:
            head = soup.new_tag("head")
            if soup.html:
                soup.html.insert(0, head)
            else:
                soup.insert(0, head)
        csp = soup.new_tag("meta")
        csp["http-equiv"] = "Content-Security-Policy"
        script_hashes = ([MENU_SCRIPT_HASH] if has_menus else []) + ([LINK_SCRIPT_HASH] if has_inactive_links else [])
        script_source = " ".join(f"'{digest}'" for digest in script_hashes) or "'none'"
        csp["content"] = (
            f"default-src 'none'; script-src {script_source}; script-src-attr 'none'; connect-src 'none'; frame-src 'none'; "
            "child-src 'none'; object-src 'none'; worker-src 'none'; manifest-src 'none'; "
            "form-action 'none'; base-uri 'none'; img-src 'self' data: file:; style-src 'self' 'unsafe-inline' file:; "
            "font-src 'self' data: file:; media-src 'self' data: file:"
        )
        soup.head.insert(0, csp)
        marker = soup.new_tag("meta")
        marker["name"] = "generator"
        marker["content"] = f"{APP_NAME} {APP_VERSION} – sichere lokale Auswertungsfassung"
        soup.head.insert(1, marker)

        # page.content() and all derived files are UTF-8, regardless of the
        # original response's encoding. CSP hashes must use that same text.
        charset = soup.find("meta", charset=True)
        if charset is None:
            charset = soup.new_tag("meta", charset="utf-8")
            soup.head.insert(2, charset)
        else:
            charset["charset"] = "utf-8"
            charset.extract()
            soup.head.insert(2, charset)
        for meta in soup.find_all("meta"):
            if str(meta.get("http-equiv") or "").lower() == "content-type":
                meta["content"] = "text/html; charset=utf-8"

        if has_menus:
            append_menu_script(soup)
        if has_inactive_links:
            append_link_inspector(soup)

        write_text(html_file, str(soup))
        page_results.append({
            "index": item["index"], "title": item.get("title"), "original_url": item["final_url"],
            "local_file": html_file.relative_to(website).as_posix(),
        })

    # Website index.
    index_lines = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline';\">",
        f"<title>{APP_NAME} – lokaler Website-Spiegel</title>",
        "<style>body{font-family:sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}li{margin:.45rem 0}code{word-break:break-all}</style>",
        "</head><body>", f"<h1>{APP_NAME} – lokaler Website-Spiegel</h1>",
        "<p>Originalskripte und externe Netzwerkzugriffe sind deaktiviert. Menüs und die Anzeige ursprünglicher Linkziele verwenden ausschließlich lokalen Bediencode. Die HAR-Dateien sind die technische Primärquelle.</p><ol>",
    ]
    for p in page_results:
        index_lines.append(f"<li><a href='{html.escape(p['local_file'], quote=True)}'>{html.escape(p.get('title') or '(ohne Titel)')}</a><br><code>{html.escape(p['original_url'])}</code></li>")
    index_lines += ["</ol></body></html>"]
    write_text(website / "index.html", "\n".join(index_lines))
    write_text(website / "NETZWERKSICHERHEIT.txt",
               f"{APP_NAME} {APP_VERSION}\n\nDiese lokale Auswertungsfassung entfernt/neutralisiert aktive Inhalte und externe Netzwerkverweise.\n"
               "Originale Netzwerkkommunikation und Response-Inhalte bleiben in 01_har erhalten.\n"
               "Originale extrahierte Ressourcen unter ressourcen/ werden byteidentisch gespeichert; CSS wird für die sichere Darstellung zusätzlich als Laufzeitkopie erzeugt.\n"
               "SVG-Dateien werden nur als passive Bilder verwendet; externe SVG-use-Verweise und SVG-Animationen werden entfernt.\n"
               "Nicht gesicherte Ressourcen und Navigationsziele stehen in fehlende_referenzen.json.\n"
               "Erkannte vorhandene Navigationsmenüs werden ausschließlich durch eigenen lokalen Menücode bedient, der per CSP-Hash freigegeben ist.\n"
               "Originalskripte, Inline-Eventhandler, Netzwerkanfragen und Formulare bleiben deaktiviert.\n"
               "Deaktivierte Links zeigen ihre ursprüngliche vollständige Adresse als Text in einem lokalen Dialog; Kopieren baut keine Verbindung zum Ziel auf.\n"
               "Die Menüerkennung ist in menue_manifest.json dokumentiert; nachzuladende oder nicht erkannte Menüs können nicht bedient werden.\n")
    write_json(website / "website_manifest.json", {"created_at": iso_now(), "pages": page_results})
    write_json(website / "menue_manifest.json", {"controller_csp_hash": MENU_SCRIPT_HASH, "pages": menu_results})
    write_json(website / "linkziele_manifest.json", {"controller_csp_hash": LINK_SCRIPT_HASH, "pages": link_results})
    for reference in missing_references:
        if reference["kind"] == "navigation":
            reference["reason"] = "page_not_archived"
        else:
            reference.update(resource_issues.get(_resource_key(reference["url"]), {"reason": "not_in_har"}))
    write_json(website / "fehlende_referenzen.json", {"references": missing_references})
    write_json(website / "ressourcen_manifest.json", {"created_at": iso_now(), "resources": manifest_rows})
    write_csv(website / "ressourcen_manifest.csv", manifest_rows,
              ["original_url", "mime", "http_status", "size", "sha256", "local_relative", "har_segment", "byte_preserved"])
    return {"pages": len(page_results), "resources": len(manifest_rows)}


def rebuild_local_mirror(source: Path, output: Path) -> dict[str, Any]:
    """Build a new viewing copy outside the original evidence directory."""
    source = source.expanduser().resolve()
    output = output.expanduser().resolve()
    if output == source or source in output.parents:
        raise ValueError("Die neue Ansicht muss außerhalb des ursprünglichen Sicherungsordners liegen.")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Der Ausgabeordner muss neu oder leer sein.")
    visited = json.loads((source / "04_metadaten/visited_pages.json").read_text(encoding="utf-8"))
    if not isinstance(visited, list) or not visited:
        raise ValueError("Die Sicherung enthält keine gespeicherte Seitenliste.")
    if not (source / "01_har").is_dir():
        raise ValueError("Der HAR-Ordner der Sicherung fehlt.")
    for item in visited:
        raw = (source / item["raw_dom_relative"]).resolve()
        if source not in raw.parents or not raw.is_file():
            raise ValueError("Eine gespeicherte DOM-Datei fehlt oder liegt außerhalb der Sicherung.")
        if Path(item["html_name"]).name != item["html_name"] or "\\" in item["html_name"]:
            raise ValueError("Ungültiger Dateiname in der gespeicherten Seitenliste.")
    result = build_local_mirror(source, visited, output_dir=output)
    write_text(output / "QUELLE.txt", f"Abgeleitete Ansicht aus: {source}\nErstellt: {iso_now()}\n"
               "Die ursprüngliche Sicherung wurde ausschließlich gelesen.\n")
    return result


def _write_size_report(case_root: Path) -> None:
    rows: list[tuple[str, int]] = []
    total = 0
    for p in sorted(case_root.iterdir()):
        if p.is_dir():
            size = folder_size(p)
            rows.append((p.name, size))
            total += size
        elif p.is_file() and p.name != "ASSERVIERUNGS_GROESSENBERICHT.txt":
            total += p.stat().st_size
    gb = total / 1_000_000_000
    status = "PASS" if gb <= 4.50 else "WARNUNG" if gb <= 4.70 else "ZU_GROSS"
    lines = [
        f"{APP_NAME} – Asservierungs-Größenbericht", "", f"Projekt / Quellcode: {REPOSITORY_URL}", f"Gesamtgröße: {human_size(total)} ({gb:.3f} GB dezimal)",
        "Nominelle DVD-Kapazität: 4,70 GB", "Empfohlener Zielwert mit Reserve: 4,50 GB", f"Status DVD 4,7 GB: {status}", "",
        "Verteilung:",
    ]
    for name, size in rows:
        lines.append(f"- {name}: {human_size(size)}")
    write_text(case_root / "ASSERVIERUNGS_GROESSENBERICHT.txt", "\n".join(lines))


def capture_website(start_url: str, output_root: Path, *, browser_name: str = "chromium", headless: bool = False,
                    max_pages: int = 1000, segment_pages: int = 20, delay_ms: int = 500,
                    timeout_ms: int = 30000, allow_hosts: list[str] | None = None) -> Path:
    start_url = normalize_url(start_url)
    start_host = hostname_from_value(start_url)
    root_domain = registrable_domain(start_host)
    allow_hosts = [x.lower().strip(".") for x in (allow_hosts or []) if x.strip()]
    started_at = iso_now()
    started_monotonic = time.monotonic()
    case_root = ensure_dir(Path(output_root).expanduser().resolve() / f"{timestamp_slug()}_{sanitize_component(start_host)}")
    dirs = {name: ensure_dir(case_root / name) for name in (
        "00_tool", "01_har", "02_website", "03_screenshots", "04_metadaten", "05_infrastruktur",
        "06_har_analyse", "07_domain_analyse", "08_tls_zertifikate",
    )}
    tool_info = {
        "tool": APP_NAME, "version": APP_VERSION, "repository": REPOSITORY_URL, "started_at": started_at,
        "start_url": sanitize_url(start_url), "browser": browser_name,
        "max_pages": max_pages, "segment_pages": segment_pages,
        "headless": headless, "delay_ms": delay_ms, "timeout_ms": timeout_ms, "allow_hosts": allow_hosts,
        "python_version": sys.version.split()[0], "playwright_version": version("playwright"),
    }
    write_json(dirs["00_tool"] / "tool_info.json", tool_info)

    visited: list[dict[str, Any]] = []
    blocked_network: list[dict[str, Any]] = []
    blocked_navigation: list[dict[str, Any]] = []
    external_not_followed: list[str] = []
    crawl_remaining: list[str] = []
    queue: deque[str] = deque([start_url])
    seen: set[str] = {start_url}
    first_party_hosts: set[str] = {start_host}
    har_index: list[dict[str, Any]] = []
    active_segment: Path | None = None
    active_start_page = 1
    segment_no = 0
    page_capture_errors = 0
    screenshot_errors = 0
    screenshots_captured = 0

    def navigation_allowed(url: str) -> bool:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        return p.scheme in {"http", "https"} and (is_first_party(host, root_domain) or host in allow_hosts)

    with sync_playwright() as pw:
        browser_type = getattr(pw, browser_name)
        browser = browser_type.launch(headless=headless)
        tool_info["browser_version"] = browser.version
        context = browser.new_context(service_workers="block", ignore_https_errors=True)

        def route_guard(route, request):
            try:
                method = request.method.upper()
                url = request.url
                if method not in {"GET", "HEAD", "OPTIONS"}:
                    blocked_network.append({"timestamp": iso_now(), "method": method, "url": sanitize_url(url), "reason": "HTTP-Methode blockiert"})
                    route.abort()
                    return
                if method == "GET" and is_stateful_get(url):
                    blocked_network.append({"timestamp": iso_now(), "method": method, "url": sanitize_url(url), "reason": "bekanntes zustandsveränderndes GET-Muster blockiert"})
                    route.abort()
                    return
                route.continue_()
            except Exception:
                return

        context.route("**/*", route_guard)
        page = context.new_page()
        page.set_default_navigation_timeout(timeout_ms)

        def start_segment(next_page_no: int) -> None:
            nonlocal active_segment, active_start_page, segment_no
            segment_no += 1
            active_start_page = next_page_no
            active_segment = dirs["01_har"] / f"segment_{segment_no:04d}.har.zip"
            context.tracing.start_har(str(active_segment), content="attach", mode="full")

        def stop_segment(last_page_no: int) -> None:
            nonlocal active_segment
            if active_segment is None:
                return
            try:
                context.tracing.stop_har()
            finally:
                if active_segment.exists():
                    digest = sha256_file(active_segment)
                    write_text(active_segment.with_suffix(active_segment.suffix + ".sha256"), f"{digest}  {active_segment.name}")
                    har_index.append({
                        "segment": active_segment.name, "first_page": active_start_page, "last_page": last_page_no,
                        "sha256": digest, "size": active_segment.stat().st_size,
                    })
                active_segment = None

        browser_started_at = iso_now()
        start_segment(1)
        try:
            while queue and (max_pages == 0 or len(visited) < max_pages):
                requested = queue.popleft()
                if not navigation_allowed(requested):
                    if requested not in external_not_followed:
                        external_not_followed.append(requested)
                    continue
                if is_stateful_get(requested):
                    blocked_navigation.append({"url": sanitize_url(requested), "reason": "bekanntes zustandsveränderndes GET-Muster"})
                    continue
                try:
                    response = page.goto(requested, wait_until="domcontentloaded")
                    try:
                        page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 8000))
                    except Exception:
                        pass
                    lazy_image_loading = _load_lazy_images(page, timeout_ms)
                    final_url = _url_without_fragment(page.url)
                    final_host = (urlparse(final_url).hostname or "").lower()
                    if final_host and is_first_party(final_host, root_domain):
                        first_party_hosts.add(final_host)
                    index = len(visited) + 1
                    title = page.title()
                    status = response.status if response else None
                    html_name = _page_slug(final_url, index)
                    raw_dom = dirs["02_website"] / "_dom_roh" / f"{index:04d}.dom.txt"
                    ensure_dir(raw_dom.parent)
                    raw_dom.write_text(page.content(), encoding="utf-8", newline="\n")
                    image_sources = _image_sources(page)
                    screenshot_name = f"{Path(html_name).stem}.png"
                    screenshot_file = dirs["03_screenshots"] / screenshot_name
                    try:
                        page.screenshot(path=str(screenshot_file), full_page=True)
                        screenshots_captured += 1
                    except Exception as exc:
                        screenshot_errors += 1
                        write_text(dirs["03_screenshots"] / f"{index:04d}_SCREENSHOT_FEHLER.txt", safe_exception(exc))
                    item = {
                        "index": index, "requested_url": requested, "final_url": final_url, "status": status,
                        "title": title, "html_name": html_name,
                        "raw_dom_relative": raw_dom.relative_to(case_root).as_posix(),
                        "image_sources": image_sources,
                        "lazy_image_loading": lazy_image_loading,
                        "screenshot": f"03_screenshots/{screenshot_name}",
                    }
                    visited.append(item)
                    print(f"[Seite {index}] {status if status is not None else '-'} | {title or '(ohne Titel)'} | {sanitize_url(final_url)}", flush=True)

                    # Passive discovery from rendered DOM. No link is clicked.
                    soup = BeautifulSoup(page.content(), "html.parser")
                    base = soup.find("base", href=True)
                    discovery_base = urljoin(final_url, str(base["href"])) if base else final_url
                    for a in soup.find_all(["a", "area"], href=True):
                        raw = str(a.get("href") or "").strip()
                        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                            continue
                        target = _url_without_fragment(urljoin(discovery_base, raw))
                        p = urlparse(target)
                        if p.scheme not in {"http", "https"}:
                            continue
                        host = (p.hostname or "").lower()
                        if is_stateful_get(target):
                            blocked_navigation.append({"url": sanitize_url(target), "reason": "bekanntes zustandsveränderndes GET-Muster"})
                            continue
                        if not (is_first_party(host, root_domain) or host in allow_hosts):
                            if target not in external_not_followed:
                                external_not_followed.append(target)
                            continue
                        if target not in seen:
                            seen.add(target)
                            queue.append(target)

                    if segment_pages > 0 and len(visited) % segment_pages == 0:
                        stop_segment(len(visited))
                        if queue and (max_pages == 0 or len(visited) < max_pages):
                            start_segment(len(visited) + 1)
                    if delay_ms:
                        page.wait_for_timeout(delay_ms)
                except Exception as exc:
                    page_capture_errors += 1
                    print(f"[Fehler] {sanitize_url(requested)} | {safe_exception(exc)}", flush=True)
                    write_text(dirs["04_metadaten"] / f"seitenfehler_{len(visited)+1:04d}.txt",
                               f"URL: {sanitize_url(requested)}\nFehler: {safe_exception(exc)}")
            crawl_remaining = list(queue)
        finally:
            try:
                stop_segment(len(visited))
            except Exception:
                pass
            try:
                context.close()
            finally:
                browser.close()

    browser_finished_at = iso_now()
    write_json(dirs["01_har"] / "HAR_Index.json", {"segments": har_index})
    idx_lines = [f"{APP_NAME} – HAR-Index", "", f"Projekt / Quellcode: {REPOSITORY_URL}", f"Segmente: {len(har_index)}", ""]
    for seg in har_index:
        idx_lines.append(f"{seg['segment']} | Seiten {seg['first_page']}–{seg['last_page']} | SHA-256 {seg['sha256']}")
    write_text(dirs["01_har"] / "HAR_Index.txt", "\n".join(idx_lines))
    write_json(dirs["04_metadaten"] / "blocked_network_requests.json", blocked_network)
    write_json(dirs["04_metadaten"] / "blocked_navigation_links.json", blocked_navigation)
    write_json(dirs["04_metadaten"] / "external_links_not_followed.json", external_not_followed)
    write_json(dirs["04_metadaten"] / "crawl_remaining.json", crawl_remaining)
    write_json(dirs["04_metadaten"] / "visited_pages.json", visited)

    har_result = analyze_har(dirs["01_har"], dirs["06_har_analyse"], base_url=start_url)
    har_server_ips: list[str] = []
    for row in har_result.get("hosts", []):
        if is_first_party(str(row.get("host") or ""), root_domain):
            for ip in str(row.get("server_ips") or "").split(","):
                ip = ip.strip()
                if ip and ip not in har_server_ips:
                    har_server_ips.append(ip)
    domain_result = analyze_domain(start_host, dirs["07_domain_analyse"], har_server_ips=har_server_ips)
    tls_result = capture_tls(sorted(first_party_hosts), dirs["08_tls_zertifikate"])
    mirror_result = build_local_mirror(case_root, visited)

    write_json(dirs["05_infrastruktur"] / "infrastructure_summary.json", {
        "start_host": start_host, "first_party_hosts": sorted(first_party_hosts),
        "har_server_ips": har_server_ips, "domain_analysis": "../07_domain_analyse/domain_analysis.json",
        "tls_analysis": "../08_tls_zertifikate/tls_certificates.json",
    })
    capture_transparency = {
        "tool": APP_NAME, "version": APP_VERSION, "repository": REPOSITORY_URL, "created_at": iso_now(),
        "website": sanitize_url(start_url),
        "browser_note": "Normale Browser-GET/HEAD/OPTIONS-Anfragen; POST/PUT/PATCH/DELETE und bekannte zustandsverändernde GET-Muster werden blockiert.",
        "external_hosts_from_har": [x.get("host") for x in har_result.get("external_connections", [])],
        "domain_analysis_sources": domain_result.get("external_calls", []),
        "tls": {"source": "direkter TLS-Handshake", "hosts": tls_result.get("hosts_attempted", [])},
        "ai_cloud_analysis": "nicht verwendet",
    }
    write_json(dirs["04_metadaten"] / "EXTERNE_DIENSTE_UND_DATEN.json", capture_transparency)
    lines = [
        f"{APP_NAME} – Externe Dienste/Datenquellen", "", f"Projekt / Quellcode: {REPOSITORY_URL}",
        "Keine KI-/Cloud-Analyse; Sicherungsdateien werden nicht zu einem Analysedienst hochgeladen.",
        f"Untersuchte Website: {sanitize_url(start_url)}", "Browserkommunikation: Details sind unverändert in den HAR-Segmenten dokumentiert.", "",
        "Externe Hosts, die von der untersuchten Website selbst geladen wurden:",
    ]
    for host in capture_transparency["external_hosts_from_har"]:
        lines.append(f"- {host}")
    lines += ["", "Domain-/Infrastrukturabfragen:"]
    for rec in domain_result.get("external_calls", []):
        lines.append(f"- {rec.get('service')} | {rec.get('protocol')} | übertragen: {rec.get('transmitted_data')} | Zweck: {rec.get('purpose')}")
    write_text(dirs["04_metadaten"] / "EXTERNE_DIENSTE_UND_DATEN.txt", "\n".join(lines))

    tool_info.update({
        "browser_started_at": browser_started_at, "browser_finished_at": browser_finished_at,
        "finished_at": iso_now(), "duration_seconds": round(time.monotonic() - started_monotonic, 3),
    })
    write_json(dirs["00_tool"] / "tool_info.json", tool_info)
    write_capture_report(case_root, {
        **tool_info,
        "pages_captured": len(visited), "page_capture_errors": page_capture_errors,
        "http_error_pages": sum(1 for item in visited if isinstance(item.get("status"), int) and item["status"] >= 400),
        "screenshots_captured": screenshots_captured, "screenshot_errors": screenshot_errors,
        "har_segments": len(har_index), "har_entries": har_result["entries_total"],
        "har_bytes": sum(segment["size"] for segment in har_index),
        "mirror_pages": mirror_result["pages"], "mirror_resources": mirror_result["resources"],
        "blocked_network_requests": len(blocked_network), "blocked_navigation_links": len(blocked_navigation),
        "external_links_not_followed": len(external_not_followed), "remaining_pages": len(crawl_remaining),
    })

    # Automatische Aktenausfertigungen. PDF-Berichte sind abgeleitete Dateien
    # mit eigenem Exportmanifest und werden nicht in den primären Hashbestand
    # aufgenommen, damit sie nach späteren dokumentierten Ergänzungen (z. B.
    # Origin-IP) regeneriert werden können, ohne die Primärsicherung zu verändern.
    export_reports(case_root, case_root / "PDF-Berichte", combined=True)
    _write_size_report(case_root)
    hash_tree(case_root, exclude_dirs={"PDF-Berichte"})
    print(f"Sicherung abgeschlossen: {case_root}", flush=True)
    return case_root
