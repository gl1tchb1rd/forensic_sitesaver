# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import time
from collections import deque
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from common import (
    APP_NAME, APP_VERSION, REPOSITORY_URL, ensure_dir, folder_size, hash_tree, hostname_from_value,
    human_size, is_first_party, is_stateful_get, iso_now, normalize_url, registrable_domain,
    relative_to_case, safe_exception, sanitize_component, sanitize_url, sha256_file,
    timestamp_slug, write_json, write_text,
)
from domain_analysis import analyze_domain
from har_analysis import analyze_har
from tls_capture import capture_tls
from reports import export_reports, write_capture_report
from website_mirror import build_local_mirror
# Keep the old imports available for existing callers and regression tests.
from mirror_support import _har_body, _rewrite_css, _url_without_fragment


def _page_slug(url: str, index: int) -> str:
    p = urlparse(url)
    tail = Path(p.path.rstrip("/")).name or "index"
    tail = sanitize_component(tail, 60)
    if p.query:
        tail += "__q_" + hashlib.sha256(p.query.encode()).hexdigest()[:8]
    return f"{index:04d}_{tail}.html"

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
    normalized = []
    for index, saved_item in enumerate(visited, 1):
        item = dict(saved_item)
        # K25 stored dom_raw and Windows separators, without html_name.
        raw_relative = str(item.get("raw_dom_relative") or item.get("dom_raw") or "").replace("\\", "/")
        if not raw_relative or re.match(r"^[a-zA-Z]:", raw_relative):
            raise ValueError("Ungültiger Pfad zur gespeicherten DOM-Datei.")
        raw = (source / raw_relative).resolve()
        if source not in raw.parents or not raw.is_file():
            raise ValueError("Eine gespeicherte DOM-Datei fehlt oder liegt außerhalb der Sicherung.")
        item["raw_dom_relative"] = raw.relative_to(source).as_posix()
        item["final_url"] = item.get("final_url") or item["requested_url"]
        item["index"] = int(item.get("index") or index)
        item["html_name"] = item.get("html_name") or _page_slug(item["final_url"], item["index"])
        if Path(item["html_name"]).name != item["html_name"] or "\\" in item["html_name"]:
            raise ValueError("Ungültiger Dateiname in der gespeicherten Seitenliste.")
        normalized.append(item)
    result = build_local_mirror(source, normalized, output_dir=output)
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
