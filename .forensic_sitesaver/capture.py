# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import re
import shutil
import time
import zipfile
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from common import (
    APP_NAME, APP_VERSION, DISCLAIMER, REPOSITORY_URL, ensure_dir, folder_size, hash_tree, hostname_from_value,
    human_size, is_first_party, is_stateful_get, iso_now, normalize_url, registrable_domain,
    relative_to_case, safe_exception, sanitize_component, sanitize_url, sha256_bytes, sha256_file,
    timestamp_slug, write_csv, write_json, write_text,
)
from domain_analysis import analyze_domain
from har_analysis import analyze_har, discover_har_files, read_har_document
from tls_capture import capture_tls
from reports import export_reports

ACTIVE_TAGS = {"script", "iframe", "frame", "object", "embed", "applet", "portal", "base"}
RESOURCE_MIME_PREFIXES = ("image/", "font/", "audio/", "video/", "text/css")
CSS_URL_RE = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)", re.I)
CSS_IMPORT_RE = re.compile(r"@import\s+(?:url\()?\s*(['\"]?)([^'\")\s;]+)\1\s*\)?", re.I)


def _url_without_fragment(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


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
    return os.path.relpath(to_file, from_file.parent).replace(os.sep, "/")


def _rewrite_css(css_text: str, css_url: str, css_runtime_file: Path,
                 url_map: dict[str, dict[str, Any]], runtime_css_map: dict[str, Path]) -> str:
    def resolve_resource(raw: str) -> str:
        raw = raw.strip().strip('"\'')
        if not raw or raw.startswith(("data:", "#")):
            return raw
        absolute = _url_without_fragment(urljoin(css_url, raw))
        rec = url_map.get(absolute)
        if not rec:
            return "data:,"
        if rec.get("mime", "").lower().startswith("image/svg"):
            return "data:,"
        target = rec.get("local_path")
        if not target:
            return "data:,"
        return _rel_link(css_runtime_file, target)

    def repl_url(m: re.Match[str]) -> str:
        return f'url("{resolve_resource(m.group(2))}")'

    text = CSS_URL_RE.sub(repl_url, css_text)

    def repl_import(m: re.Match[str]) -> str:
        raw = m.group(2).strip()
        absolute = _url_without_fragment(urljoin(css_url, raw))
        target = runtime_css_map.get(absolute)
        if not target:
            return "/* Forensic SiteSaver: externer/fehlender @import blockiert */"
        return f'@import url("{_rel_link(css_runtime_file, target)}")'

    return CSS_IMPORT_RE.sub(repl_import, text)


def build_local_mirror(case_root: Path, visited: list[dict[str, Any]]) -> dict[str, Any]:
    website = ensure_dir(case_root / "02_website")
    pages_dir = ensure_dir(website / "seiten")
    resources_dir = ensure_dir(website / "ressourcen")
    runtime_css_dir = ensure_dir(website / "_runtime_css")
    raw_dom_dir = ensure_dir(website / "_dom_roh")
    har_files = discover_har_files(case_root / "01_har")

    url_map: dict[str, dict[str, Any]] = {}
    manifest_rows: list[dict[str, Any]] = []

    # Extract safe-to-view resources byte-identically. HAR remains the source for everything else.
    for segment in har_files:
        try:
            doc = read_har_document(segment)
        except Exception:
            continue
        for entry in ((doc.get("log") or {}).get("entries") or []):
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            url = _url_without_fragment(str(req.get("url") or ""))
            if not url or url in url_map:
                continue
            content = resp.get("content") or {}
            mime = str(content.get("mimeType") or "").split(";", 1)[0].lower()
            if not _safe_resource_mime(mime):
                continue
            body = _har_body(segment, content)
            if body is None:
                continue
            rel = _resource_relpath(url, mime, body)
            out = resources_dir / rel
            if out.exists() and out.read_bytes() != body:
                out = out.with_name(out.stem + "__" + sha256_bytes(body)[:8] + out.suffix)
            ensure_dir(out.parent)
            if not out.exists():
                out.write_bytes(body)
            rec = {
                "original_url": url, "mime": mime, "http_status": resp.get("status"),
                "size": len(body), "sha256": sha256_bytes(body),
                "local_path": out, "local_relative": out.relative_to(website).as_posix(),
                "har_segment": segment.name, "byte_preserved": True,
            }
            url_map[url] = rec
            manifest_rows.append({k: v for k, v in rec.items() if k != "local_path"})

    # Runtime CSS copies – original CSS above remains byte-identical.
    runtime_css_map: dict[str, Path] = {}
    for url, rec in url_map.items():
        if rec.get("mime") == "text/css":
            target = runtime_css_dir / (hashlib.sha256(url.encode()).hexdigest()[:16] + ".css")
            runtime_css_map[url] = target
    for url, target in runtime_css_map.items():
        rec = url_map[url]
        try:
            original = rec["local_path"].read_text(encoding="utf-8", errors="replace")
            rewritten = _rewrite_css(original, url, target, url_map, runtime_css_map)
            write_text(target, rewritten)
        except Exception:
            write_text(target, "/* CSS konnte nicht für die sichere Laufzeitfassung verarbeitet werden. */")

    # Map archived page URLs.
    page_map: dict[str, Path] = {}
    for item in visited:
        page_map[_url_without_fragment(item["final_url"])] = pages_dir / item["html_name"]
        if item.get("requested_url"):
            page_map[_url_without_fragment(item["requested_url"])] = pages_dir / item["html_name"]

    def rewrite_inline_css(value: str, base_url: str, html_file: Path) -> str:
        def repl(m: re.Match[str]) -> str:
            raw = m.group(2).strip()
            if raw.startswith(("data:", "#")):
                return m.group(0)
            absolute = _url_without_fragment(urljoin(base_url, raw))
            rec = url_map.get(absolute)
            if not rec or rec.get("mime", "").startswith("image/svg"):
                return 'url("data:,")'
            return f'url("{_rel_link(html_file, rec["local_path"])}")'
        return CSS_URL_RE.sub(repl, value)

    page_results: list[dict[str, Any]] = []
    for item in visited:
        html_file = pages_dir / item["html_name"]
        raw_source = case_root / item["raw_dom_relative"]
        if not raw_source.exists():
            continue
        raw_html = raw_source.read_text(encoding="utf-8", errors="replace")
        soup = BeautifulSoup(raw_html, "html.parser")
        base_url = item["final_url"]

        for tag in list(soup.find_all(ACTIVE_TAGS)):
            tag.decompose()
        for meta in list(soup.find_all("meta")):
            if str(meta.get("http-equiv") or "").lower() in {"refresh", "content-security-policy"}:
                meta.decompose()

        # Event handlers / active attributes.
        for tag in soup.find_all(True):
            for attr in list(tag.attrs):
                low = attr.lower()
                if low.startswith("on") or low in {"nonce", "integrity", "crossorigin"}:
                    del tag.attrs[attr]

        # Forms become inert; controls stay visible but disabled.
        for form in soup.find_all("form"):
            form.attrs.pop("action", None)
            form.attrs.pop("method", None)
            form["data-forensic-sitesaver-form-disabled"] = "true"
        for control in soup.find_all(["input", "button", "select", "textarea"]):
            control["disabled"] = "disabled"

        # Links: archived internal pages remain clickable, everything else becomes inert text/link marker.
        for a in soup.find_all("a"):
            href = str(a.get("href") or "")
            if not href:
                continue
            absolute = _url_without_fragment(urljoin(base_url, href))
            target = page_map.get(absolute)
            if target:
                a["href"] = _rel_link(html_file, target)
            else:
                a["data-original-url"] = absolute
                a["href"] = "#"

        def rewrite_attr(tag: Any, attr: str, allow_svg: bool = False) -> None:
            raw = str(tag.get(attr) or "")
            if not raw:
                return
            absolute = _url_without_fragment(urljoin(base_url, raw))
            rec = url_map.get(absolute)
            if rec and (allow_svg or not rec.get("mime", "").startswith("image/svg")):
                tag[attr] = _rel_link(html_file, rec["local_path"])
            else:
                tag[f"data-original-{attr}"] = absolute
                tag[attr] = "data:,"

        for img in soup.find_all("img"):
            rewrite_attr(img, "src")
            if img.get("srcset"):
                del img["srcset"]
        for media in soup.find_all(["audio", "video", "source"]):
            rewrite_attr(media, "src")
        for video in soup.find_all("video"):
            rewrite_attr(video, "poster")
        for tag in soup.find_all(attrs={"background": True}):
            rewrite_attr(tag, "background")

        # Stylesheets use rewritten runtime CSS copies.
        for link in list(soup.find_all("link")):
            rels = [str(x).lower() for x in (link.get("rel") or [])]
            href = str(link.get("href") or "")
            if "stylesheet" in rels and href:
                absolute = _url_without_fragment(urljoin(base_url, href))
                target = runtime_css_map.get(absolute)
                if target:
                    link["href"] = _rel_link(html_file, target)
                    link.attrs.pop("integrity", None)
                    link.attrs.pop("crossorigin", None)
                else:
                    link.decompose()
            elif href and urlparse(urljoin(base_url, href)).scheme in {"http", "https"}:
                # favicon/preload/etc. only if captured local resource exists.
                absolute = _url_without_fragment(urljoin(base_url, href))
                rec = url_map.get(absolute)
                if rec and not rec.get("mime", "").startswith("image/svg"):
                    link["href"] = _rel_link(html_file, rec["local_path"])
                else:
                    link.decompose()

        for tag in soup.find_all(style=True):
            tag["style"] = rewrite_inline_css(str(tag.get("style") or ""), base_url, html_file)
        for style_tag in soup.find_all("style"):
            if style_tag.string:
                style_tag.string.replace_with(rewrite_inline_css(style_tag.string, base_url, html_file))

        # CSP blocks every network-capable/active category. file: is required when pages are opened directly.
        if soup.head is None:
            head = soup.new_tag("head")
            if soup.html:
                soup.html.insert(0, head)
            else:
                soup.insert(0, head)
        csp = soup.new_tag("meta")
        csp["http-equiv"] = "Content-Security-Policy"
        csp["content"] = (
            "default-src 'none'; script-src 'none'; connect-src 'none'; frame-src 'none'; "
            "child-src 'none'; object-src 'none'; worker-src 'none'; manifest-src 'none'; "
            "form-action 'none'; base-uri 'none'; img-src data: file:; style-src 'unsafe-inline' file:; "
            "font-src data: file:; media-src data: file:"
        )
        soup.head.insert(0, csp)
        marker = soup.new_tag("meta")
        marker["name"] = "generator"
        marker["content"] = f"{APP_NAME} {APP_VERSION} – sichere lokale Auswertungsfassung"
        soup.head.insert(1, marker)

        write_text(html_file, str(soup))
        page_results.append({
            "index": item["index"], "title": item.get("title"), "original_url": base_url,
            "local_file": html_file.relative_to(website).as_posix(),
        })

    # Website index.
    index_lines = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline';\">",
        f"<title>{APP_NAME} – lokaler Website-Spiegel</title>",
        "<style>body{font-family:sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}li{margin:.45rem 0}code{word-break:break-all}</style>",
        "</head><body>", f"<h1>{APP_NAME} – lokaler Website-Spiegel</h1>",
        "<p>Aktive Inhalte und externe Netzwerkzugriffe sind deaktiviert. Die HAR-Dateien sind die technische Primärquelle.</p><ol>",
    ]
    for p in page_results:
        index_lines.append(f"<li><a href='{p['local_file']}'>{p.get('title') or '(ohne Titel)'}</a><br><code>{p['original_url']}</code></li>")
    index_lines += ["</ol></body></html>"]
    write_text(website / "index.html", "\n".join(index_lines))
    write_text(website / "NETZWERKSICHERHEIT.txt",
               f"{APP_NAME} {APP_VERSION}\n\nDiese lokale Auswertungsfassung entfernt/neutralisiert aktive Inhalte und externe Netzwerkverweise.\n"
               "Originale Netzwerkkommunikation und Response-Inhalte bleiben in 01_har erhalten.\n"
               "Originale extrahierte Ressourcen unter ressourcen/ werden byteidentisch gespeichert; CSS wird für die sichere Darstellung zusätzlich als Laufzeitkopie erzeugt.\n")
    write_json(website / "website_manifest.json", {"created_at": iso_now(), "pages": page_results})
    write_json(website / "ressourcen_manifest.json", {"created_at": iso_now(), "resources": manifest_rows})
    write_csv(website / "ressourcen_manifest.csv", manifest_rows,
              ["original_url", "mime", "http_status", "size", "sha256", "local_relative", "har_segment", "byte_preserved"])
    return {"pages": len(page_results), "resources": len(manifest_rows)}


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
    case_root = ensure_dir(Path(output_root).expanduser().resolve() / f"{timestamp_slug()}_{sanitize_component(start_host)}")
    dirs = {name: ensure_dir(case_root / name) for name in (
        "00_tool", "01_har", "02_website", "03_screenshots", "04_metadaten", "05_infrastruktur",
        "06_har_analyse", "07_domain_analyse", "08_tls_zertifikate",
    )}
    write_json(dirs["00_tool"] / "tool_info.json", {
        "tool": APP_NAME, "version": APP_VERSION, "repository": REPOSITORY_URL, "started_at": iso_now(),
        "start_url": sanitize_url(start_url), "browser": browser_name,
        "max_pages": max_pages, "segment_pages": segment_pages,
    })

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

    def navigation_allowed(url: str) -> bool:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        return p.scheme in {"http", "https"} and (is_first_party(host, root_domain) or host in allow_hosts)

    with sync_playwright() as pw:
        browser_type = getattr(pw, browser_name)
        browser = browser_type.launch(headless=headless)
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
                    screenshot_name = f"{Path(html_name).stem}.png"
                    screenshot_file = dirs["03_screenshots"] / screenshot_name
                    try:
                        page.screenshot(path=str(screenshot_file), full_page=True)
                    except Exception as exc:
                        write_text(dirs["03_screenshots"] / f"{index:04d}_SCREENSHOT_FEHLER.txt", safe_exception(exc))
                    item = {
                        "index": index, "requested_url": requested, "final_url": final_url, "status": status,
                        "title": title, "html_name": html_name,
                        "raw_dom_relative": raw_dom.relative_to(case_root).as_posix(),
                        "screenshot": f"03_screenshots/{screenshot_name}",
                    }
                    visited.append(item)
                    print(f"[Seite {index}] {status if status is not None else '-'} | {title or '(ohne Titel)'} | {sanitize_url(final_url)}", flush=True)

                    # Passive discovery from rendered DOM. No link is clicked.
                    soup = BeautifulSoup(page.content(), "html.parser")
                    for a in soup.find_all("a", href=True):
                        raw = str(a.get("href") or "").strip()
                        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                            continue
                        target = _url_without_fragment(urljoin(final_url, raw))
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

    remark = [
        f"{APP_NAME} – Sicherungsvermerk", "=" * 72, "", f"Projekt / Quellcode: {REPOSITORY_URL}",
        f"Programmversion: {APP_VERSION}", f"Beginn/Erstellung: {iso_now()}", f"Ausgangs-URL: {sanitize_url(start_url)}",
        f"Browser: {browser_name}", f"Gesicherte Seiten: {len(visited)}", f"HAR-Segmente: {len(har_index)}", "",
        "Sicherungsumfang:",
        "- segmentierte HAR-Aufzeichnung im Modus full mit Response-Inhalten",
        "- Full-Page-Screenshots",
        "- lokaler netzwerkgesperrter Website-Spiegel mit lokalisierten Ressourcen",
        "- HAR-, Domain-/Hosting-/MX- und TLS-Auswertung",
        "- SHA-256-Prüfsummen", "",
        "Sicherheitsprinzip:",
        "Es werden keine Links angeklickt und keine Formulare abgesendet. Aktive Navigation erfolgt ausschließlich per HTTP(S)-GET zu zulässigen First-Party-Zielen. POST/PUT/PATCH/DELETE sowie bekannte Warenkorb-/Bestell-/Zahlungs-GET-Muster werden blockiert.",
        "Eine absolute Nebenwirkungsfreiheit kann bei fremden Servern nicht garantiert werden, wenn ein Server entgegen HTTP-Konventionen bereits auf einen gewöhnlichen GET-Aufruf Zustandsänderungen ausführt.", "",
        "Lokaler Website-Spiegel:",
        "Die HTML-Dateien sind eine sichere Auswertungsfassung aus dem gerenderten DOM. Aktive Inhalte und externe Netzwerkverbindungen werden deaktiviert. Die ursprüngliche Netzwerkkommunikation und Response-Inhalte bleiben in den HAR-Dateien dokumentiert.", "",
        "DISCLAIMER", "-" * 72, DISCLAIMER,
    ]
    write_text(case_root / "Sicherungsvermerk.txt", "\n".join(remark))

    # Automatische Aktenausfertigungen. PDF-Berichte sind abgeleitete Dateien
    # mit eigenem Exportmanifest und werden nicht in den primären Hashbestand
    # aufgenommen, damit sie nach späteren dokumentierten Ergänzungen (z. B.
    # Origin-IP) regeneriert werden können, ohne die Primärsicherung zu verändern.
    export_reports(case_root, case_root / "PDF-Berichte", combined=True)
    _write_size_report(case_root)
    hash_tree(case_root, exclude_dirs={"PDF-Berichte"})
    print(f"Sicherung abgeschlossen: {case_root}", flush=True)
    return case_root
