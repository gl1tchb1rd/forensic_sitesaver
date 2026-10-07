# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Complete offline mirror pipeline ported from the supplied K25-SiteSaver.

Resource extraction, localization, verification and index generation originate
in K25's mirror section (lines 2046–2708). v1.1 adapters preserve existing menu
and link helpers, diagnostics, robust URL/CSS handling and passive SVG images.
No original script or online resource fallback is executed.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import html as html_lib
import json
import mimetypes
import posixpath
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urljoin, urlparse

from bs4 import BeautifulSoup

from common import (APP_NAME as TOOL_NAME, APP_VERSION as TOOL_VERSION, iso_now,
                    sanitize_component as safe_slug, sanitize_url as sanitized_url,
                    sha256_file, write_json)
from har_analysis import discover_har_files
from mirror_support import (_resource_key, _har_body, _safe_resource_mime,
                            _decode_css, _rewrite_css, _srcset_candidates, _url_without_fragment)
from offline_menu import MENU_SCRIPT_HASH, PREFIX as MENU_PREFIX, prepare_offline_menus, append_menu_script
from offline_links import (LINK_SCRIPT_HASH, clear_link_annotations, annotate_inactive_link,
                           add_image_map_info_buttons, append_link_inspector)

WEBSITE_CSP = (
    "default-src 'none'; "
    "script-src 'none'; script-src-attr 'none'; connect-src 'none'; frame-src 'none'; child-src 'none'; "
    "object-src 'none'; worker-src 'none'; manifest-src 'none'; form-action 'none'; "
    "base-uri 'none'; img-src 'self' data: file:; style-src 'self' 'unsafe-inline' file:; "
    "font-src 'self' data: file:; media-src 'self' data: file:"
)

SAFE_DATA_URI_PREFIXES = (
    "data:image/png", "data:image/jpeg", "data:image/gif", "data:image/webp",
    "data:image/svg+xml", "data:,",
    "data:image/avif", "data:image/bmp", "data:image/x-icon",
    "data:font/", "data:application/font-woff", "data:application/x-font-woff",
    "data:audio/", "data:video/"
)
NETWORK_SCHEMES_RE = re.compile(r"^(?:https?:)?//", re.I)
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def _canon_resource_url(value: str) -> str:
    return _resource_key(value)


def _safe_data_uri(value: str) -> bool:
    low = value.strip().lower()
    return any(low.startswith(prefix) for prefix in SAFE_DATA_URI_PREFIXES)


def _har_body_bytes(entry: dict[str, Any], source_path: Path | None = None) -> bytes | None:
    return _har_body(source_path, (entry.get("response") or {}).get("content") or {}) if source_path else None


def _mime_of_entry(entry: dict[str, Any]) -> str:
    response = entry.get("response") or {}
    headers = {str(h.get("name") or "").lower(): str(h.get("value") or "") for h in response.get("headers") or []}
    mime = str((response.get("content") or {}).get("mimeType") or headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if mime in {"", "application/octet-stream"}:
        header_mime = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        mime = header_mime if _safe_resource_mime(header_mime) else mimetypes.guess_type(urlparse((entry.get("request") or {}).get("url") or "").path)[0] or mime
    return mime


def _decode_text_bytes(data: bytes, charset: str = "") -> str:
    return _decode_css(data, charset)


def _materialize_resource(mime: str) -> bool:
    return _safe_resource_mime(mime)


def _renderable_resource(mime: str) -> bool:
    # SVG is used only in passive image contexts; never as an active document.
    return _materialize_resource(mime)


def _preferred_extension(mime: str, url: str) -> str:
    special = {
        "text/css": ".css",
        "image/svg+xml": ".svg",
        "image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif",
        "image/webp": ".webp", "image/avif": ".avif", "image/bmp": ".bmp",
        "image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico",
        "font/woff": ".woff", "font/woff2": ".woff2", "font/ttf": ".ttf", "font/otf": ".otf",
        "application/font-woff": ".woff", "application/x-font-woff": ".woff",
        "application/vnd.ms-fontobject": ".eot",
    }
    if mime in special:
        return special[mime]
    if mime.startswith("audio/") or mime.startswith("video/"):
        return mimetypes.guess_extension(mime) or ".bin"
    try:
        suffix = Path(urlparse(url).path).suffix.lower()
        if re.fullmatch(r"\.[a-z0-9]{1,8}", suffix):
            return suffix
    except Exception:
        pass
    return mimetypes.guess_extension(mime) or ".bin"


def _safe_fs_component(value: str, fallback: str = "datei") -> str:
    try:
        value = unquote(value)
    except Exception:
        pass
    value = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", value)
    value = re.sub(r"\s+", " ", value).strip(" .")
    if not value:
        value = fallback
    stem = value.split(".", 1)[0].lower()
    if stem in WINDOWS_RESERVED_NAMES:
        value = "_" + value
    if len(value) > 120:
        suffix = Path(value).suffix[:12]
        base = Path(value).stem[:95]
        value = base + "__" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10] + suffix
    return value


def _resource_local_rel(url: str, mime: str, body_hash: str, used_paths: dict[str, str]) -> str:
    p = urlparse(url)
    host = _safe_fs_component((p.hostname or "unbekannter-host").lower(), "unbekannter-host")
    raw_parts = [part for part in p.path.split("/") if part]
    parts = [_safe_fs_component(part, "segment") for part in raw_parts]
    ext = _preferred_extension(mime, url)

    if p.path.endswith("/") or not parts:
        parts.append("index" + ext)
    else:
        last = parts[-1]
        old_suffix = Path(last).suffix.lower()
        # Für passive Ressourcen erzwingen wir eine zum MIME passende, ungefährliche Endung.
        if ext and old_suffix != ext:
            if old_suffix:
                last = Path(last).stem + ext
            else:
                last = last + ext
        parts[-1] = last

    if p.query:
        name = parts[-1]
        suffix = Path(name).suffix
        stem = name[:-len(suffix)] if suffix else name
        parts[-1] = f"{stem}__q_{hashlib.sha256(p.query.encode('utf-8', errors='replace')).hexdigest()[:10]}{suffix}"

    rel = posixpath.join("ressourcen", host, *parts)
    prior = used_paths.get(rel)
    if prior is not None and prior != body_hash:
        name = posixpath.basename(rel)
        parent = posixpath.dirname(rel)
        suffix = Path(name).suffix
        stem = name[:-len(suffix)] if suffix else name
        rel = posixpath.join(parent, f"{stem}__v_{body_hash[:10]}{suffix}")
    used_paths[rel] = body_hash
    return rel


def _relative_site_ref(from_dir: str, target_rel: str) -> str:
    return quote(posixpath.relpath(target_rel, start=from_dir or "."), safe="/")


def _local_resource_reference(
    ref: str, base_url: str, resource_map: dict[str, dict[str, Any]], from_dir: str,
    *, prefer_runtime_css: bool = False, kind: str = "src", page: str = "",
) -> str | None:
    ref = (ref or "").strip()
    if not ref:
        return None
    if ref.startswith("#"):
        return ref
    if ref.lower().startswith("data:"):
        return ref if _safe_data_uri(ref) else None
    absolute = urljoin(base_url, ref)
    rec = resource_map.get(_canon_resource_url(absolute))
    if not rec or not rec.get("renderable"):
        if isinstance(resource_map, ResourceMap):
            resource_map.missing.append({"page": page, "kind": kind, "url": absolute})
        return None
    target = rec.get("runtime_css_path") if prefer_runtime_css and rec.get("mime") == "text/css" else rec.get("local_path")
    if not target:
        return None
    fragment = urlparse(absolute).fragment
    return _relative_site_ref(from_dir, str(target)) + ("#" + fragment if fragment else "")


def _rewrite_css_text(css: str, base_url: str, resource_map: ResourceMap, from_dir: str, filename: str = "runtime.css") -> str:
    # Preserve K25's separate CSS runtime pass, using v1.1's lexer for escaped
    # URLs, data URLs, comments, image-set and nested imports.
    if resource_map.files is None:
        resource_map.files = {url: {**rec, "local_path": resource_map.website / rec["local_path"]}
                              for url, rec in resource_map.items() if rec.get("renderable")}
        resource_map.runtime = {url: resource_map.website / rec["runtime_css_path"]
                                for url, rec in resource_map.items() if rec.get("runtime_css_path")}
    return _rewrite_css(css, base_url, resource_map.website / from_dir / filename,
                        resource_map.files, resource_map.runtime, resource_map.missing)


def _extract_site_resources(
    har_sources: Path | list[Path] | tuple[Path, ...], website_dir: Path, case_root: Path,
) -> tuple[ResourceMap, list[dict[str, Any]]]:
    """K25 extraction pass: byte copies, all content versions, then runtime CSS."""
    resource_map = ResourceMap(website_dir)
    manifest_records: list[dict[str, Any]] = []
    used_paths: dict[str, str] = {}
    seen_versions: dict[tuple[str, str], dict[str, Any]] = {}
    redirects: dict[str, str] = {}
    for entry, source_path in iter_har_entry_sources(har_sources):
        request, response = entry.get("request") or {}, entry.get("response") or {}
        url = str(request.get("url") or "")
        if not url or urlparse(url).scheme not in {"http", "https"}:
            continue
        canonical = _canon_resource_url(url)
        status = int(response.get("status") or 0)
        if 300 <= status < 400 and status != 304 and response.get("redirectURL"):
            redirects[canonical] = _canon_resource_url(urljoin(url, response["redirectURL"]))
            resource_map.issues[canonical] = {"reason": "redirect_target_not_archived", "http_status": status}
            continue
        if not (200 <= status < 300 or status == 304):
            resource_map.issues[canonical] = {"reason": "http_error" if status else "no_response", "http_status": status}
            continue
        mime = _mime_of_entry(entry)
        if not _materialize_resource(mime):
            resource_map.issues[canonical] = {"reason": "unsupported_mime", "http_status": status, "mime": mime}
            continue
        body = _har_body_bytes(entry, source_path)
        if not body:
            resource_map.issues[canonical] = {"reason": "response_body_missing", "http_status": status, "mime": mime}
            continue
        body_hash = hashlib.sha256(body).hexdigest()
        version_key = (canonical, body_hash)
        if version_key in seen_versions:
            resource_map[canonical] = seen_versions[version_key]
            continue
        local_rel = _resource_local_rel(url, mime, body_hash, used_paths)
        shortened = len(str(website_dir / local_rel)) > 230
        if shortened:
            local_rel = posixpath.join("ressourcen", "_kurz", hashlib.sha256(canonical.encode()).hexdigest()[:20] + _preferred_extension(mime, url))
            previous = used_paths.get(local_rel)
            if previous is not None and previous != body_hash:
                name = Path(local_rel)
                local_rel = str(name.with_name(name.stem + "__v_" + body_hash[:10] + name.suffix)).replace("\\", "/")
            used_paths[local_rel] = body_hash
        local_abs = website_dir / local_rel
        local_abs.parent.mkdir(parents=True, exist_ok=True)
        if not local_abs.exists():
            local_abs.write_bytes(body)
        rec = {
            "source_url": sanitized_url(url),
            "source_url_sha256": hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest(),
            "original_url": _url_without_fragment(url), "mime": mime,
            "status": response.get("status"), "http_status": response.get("status"),
            "sha256": body_hash, "size": len(body), "local_path": local_rel,
            "local_relative": local_rel, "renderable": _renderable_resource(mime),
            "source_har": relative_ref(source_path, case_root), "har_segment": source_path.name,
            "byte_preserved": True,
        }
        if shortened:
            rec["path_shortened"] = True
        if response.get("url"):
            rec["response_url"] = str(response["url"])
        headers = {str(h.get("name") or "").lower(): str(h.get("value") or "") for h in response.get("headers") or []}
        charset = re.search(r"charset\s*=\s*[\"']?([^;\s\"']+)", headers.get("content-type", ""), re.I)
        if charset:
            rec["charset"] = charset[1]
        manifest_records.append(rec)
        seen_versions[version_key] = rec
        resource_map[canonical] = rec

    # v1.1 alias handling, applied before the K25 CSS passes.
    for original, target in redirects.items():
        seen = {original}
        while target in redirects and target not in seen:
            seen.add(target)
            target = redirects[target]
        if target in resource_map:
            resource_map[original] = resource_map[target]
    runtime_css_dir = website_dir / "_runtime_css"
    runtime_css_dir.mkdir(parents=True, exist_ok=True)
    for canonical, rec in resource_map.items():
        if rec.get("mime") == "text/css":
            runtime_name = hashlib.sha256(rec["original_url"].encode()).hexdigest()[:20] + ".css"
            rec["runtime_css_path"] = posixpath.join("_runtime_css", runtime_name)
    processed: set[str] = set()
    for canonical, rec in resource_map.items():
        if rec.get("mime") != "text/css" or rec["runtime_css_path"] in processed:
            continue
        processed.add(rec["runtime_css_path"])
        try:
            css_text = _decode_text_bytes((website_dir / rec["local_path"]).read_bytes(), rec.get("charset", ""))
            runtime_abs = website_dir / rec["runtime_css_path"]
            css_url = rec.get("response_url") or rec["original_url"]
            safe_css = _rewrite_css_text(css_text, css_url, resource_map, "_runtime_css", runtime_abs.name)
            runtime_abs.write_text(safe_css, encoding="utf-8", newline="\n")
            rec["runtime_css_sha256"] = sha256_file(runtime_abs)
        except Exception as exc:
            rec["renderable"] = False
            rec["runtime_css_error"] = safe_exception_text(exc, case_root)
            resource_map.files = None
    manifest_records.sort(key=lambda x: (x.get("source_url", ""), x.get("local_path", "")))
    return resource_map, manifest_records


def _page_filename(item: dict[str, Any]) -> str:
    if item.get("html_name"):
        return str(item["html_name"])
    idx = int(item.get("index") or 0)
    page_url = str(item.get("final_url") or item.get("requested_url") or "")
    path = urlparse(page_url).path or "/"
    slug = safe_slug(path if path != "/" else "startseite", 80)
    return f"{idx:04d}_{slug or 'seite'}.html"


def _localize_html(
    raw_html: str, page_url: str, resource_map: dict[str, dict[str, Any]], page_link_map: dict[str, str], *, page_name: str = "", selected_images: list[str] | None = None,
) -> str:
    soup = BeautifulSoup(raw_html, "html.parser")
    original_page_url = page_url
    base = soup.find("base", href=True)
    if base:
        page_url = urljoin(page_url, str(base["href"]))
    def local_reference(ref, *, prefer_runtime_css=False, kind="src"):
        return _local_resource_reference(ref, page_url, resource_map, "seiten",
                                         prefer_runtime_css=prefer_runtime_css, kind=kind, page=page_name)
    # A saved browser selection is a fallback only when the original src was
    # not archived. Otherwise keep K25's native responsive image selection.
    for img, selected in zip(soup.find_all("img"), selected_images or []):
        current = _canon_resource_url(urljoin(page_url, str(img.get("src") or "")))
        if selected and current not in resource_map and _canon_resource_url(selected) in resource_map:
            img["src"] = selected
            img.attrs.pop("srcset", None)
            img.attrs.pop("data-srcset", None)
            picture = img.find_parent("picture")
            if picture:
                for source in list(picture.find_all("source")):
                    source.decompose()
    for img in soup.find_all("img"):
        src = str(img.get("src") or "")
        if not src or src.lower().startswith("data:") or _canon_resource_url(urljoin(page_url, src)) not in resource_map:
            for attr in ("data-src", "data-lazy-src", "data-original"):
                candidate = str(img.get(attr) or "")
                if candidate and _canon_resource_url(urljoin(page_url, candidate)) in resource_map:
                    img["src"] = candidate
                    break
        img["loading"] = "eager"
    clear_link_annotations(soup)
    menu_result = prepare_offline_menus(soup, original_page_url, page_url)
    inactive_links = []

    for tag in list(soup.find_all(["script", "iframe", "frame", "object", "embed", "applet", "portal", "animate", "animatemotion", "animatetransform", "set"])):
        # Aktive Elemente werden aus der lauffähigen lokalen Fassung vollständig entfernt.
        # Der unveränderte gerenderte DOM bleibt separat als .dom.txt erhalten.
        tag.decompose()

    for tag in list(soup.find_all("base")):
        tag.decompose()
    for tag in list(soup.find_all("meta")):
        if str(tag.get("http-equiv") or "").strip().lower() in {"refresh", "content-security-policy"}:
            tag.decompose()

    if soup.html is None:
        html_tag = soup.new_tag("html")
        for child in list(soup.contents):
            html_tag.append(child.extract())
        soup.append(html_tag)
    if soup.head is None:
        soup.html.insert(0, soup.new_tag("head"))

    csp = soup.new_tag("meta")
    csp["http-equiv"] = "Content-Security-Policy"
    hashes = ([MENU_SCRIPT_HASH] if menu_result["menus"] else [])
    # The link controller hash is filled after localizing all anchors.
    csp["content"] = WEBSITE_CSP
    soup.head.insert(0, csp)
    marker = soup.new_tag("meta")
    marker["name"] = "k25-sitesaver-local"
    marker["content"] = f"{TOOL_NAME} {TOOL_VERSION}; network disabled; local mirror"
    soup.head.insert(1, marker)

    for form in soup.find_all("form"):
        form.name = "div"
        for attr in ("action", "method", "target", "enctype", "accept-charset"):
            form.attrs.pop(attr, None)
        form["data-k25-form-disabled"] = "true"
    for control in soup.find_all(["button", "input", "select", "textarea"]):
        if not (control.name == "button" and control.has_attr(MENU_PREFIX + "controls")):
            control["disabled"] = "disabled"
        for attr in ("formaction", "formmethod", "formenctype", "formtarget"):
            control.attrs.pop(attr, None)

    for tag in soup.find_all(True):
        for attr in list(tag.attrs.keys()):
            low = attr.lower()
            if low.startswith("on") or low in {"ping", "nonce", "integrity", "crossorigin", "manifest", "target", "download"}:
                tag.attrs.pop(attr, None)

    for tag in list(soup.find_all("link")):
        rel_values = {str(x).lower() for x in (tag.get("rel") or [])}
        href = str(tag.get("href") or "")
        if "stylesheet" in rel_values:
            local = local_reference(href, prefer_runtime_css=True, kind="stylesheet")
            if local and local.lower().endswith(".css"):
                tag["href"] = local
                for attr in ("integrity", "crossorigin", "referrerpolicy"):
                    tag.attrs.pop(attr, None)
            else:
                tag.decompose()
        elif rel_values.intersection({"icon", "shortcut", "apple-touch-icon", "mask-icon"}):
            local = local_reference(href, kind="href")
            if local:
                tag["href"] = local
            else:
                tag.decompose()
        else:
            tag.decompose()

    for style_tag in soup.find_all("style"):
        css_text = style_tag.string if style_tag.string is not None else style_tag.get_text()
        style_tag.clear()
        style_tag.append(_rewrite_css_text(css_text or "", page_url, resource_map, "seiten", page_name))
    for tag in soup.find_all(True):
        if tag.has_attr("style"):
            tag["style"] = _rewrite_css_text(str(tag.get("style") or ""), page_url, resource_map, "seiten", page_name)

    for tag in soup.find_all(True):
        for attr in ("src", "poster", "background"):
            if tag.has_attr(attr):
                local = local_reference(str(tag.get(attr) or ""), kind=attr)
                if local:
                    tag[attr] = local
                else:
                    tag["data-original-" + attr] = urljoin(page_url, str(tag.get(attr) or ""))
                    tag.attrs.pop(attr, None)
        if tag.has_attr("srcset") or tag.has_attr("data-srcset"):
            replacements = []
            fallback = None
            for ref, descriptor in _srcset_candidates(str(tag.get("srcset") or tag.get("data-srcset") or "")):
                local = local_reference(ref, kind="srcset")
                if local:
                    fallback = fallback or local
                    replacements.append(local + (" " + descriptor if descriptor else ""))
            if replacements:
                tag["srcset"] = ", ".join(replacements)
                if tag.name == "img" and (not tag.get("src") or tag.has_attr("data-original-src")):
                    tag["src"] = fallback
            else:
                tag.attrs.pop("srcset", None)
                if tag.name == "source" and tag.find_parent("picture"):
                    tag.decompose()

    for tag in soup.find_all(True):
        if tag.has_attr("xlink:href"):
            ref = str(tag.get("xlink:href") or "")
            if not ref.startswith("#"):
                local = local_reference(ref, kind="xlink:href")
                if local:
                    tag["xlink:href"] = local
                else:
                    tag.attrs.pop("xlink:href", None)

    for use in soup.find_all("use"):
        for attr in ("href", "xlink:href"):
            if use.has_attr(attr) and not str(use[attr]).startswith("#"):
                use.attrs.pop(attr, None)

    for a in soup.find_all(["a", "area"]):
        href = str(a.get("href") or "")
        if not href or href.startswith("#"):
            continue
        try:
            absolute = urljoin(page_url, href)
            fragment = urlparse(absolute).fragment
            key = _canon_resource_url(absolute)
        except Exception:
            absolute, fragment, key = href, "", ""
        local_page = page_link_map.get(key)
        if local_page:
            a["href"] = local_page + (f"#{fragment}" if fragment else "")
            a["data-k25-local-archive-link"] = "true"
            continue
        resource = resource_map.get(key)
        local_resource = local_reference(href, kind="href") if resource and resource.get("mime") != "image/svg+xml" else None
        if local_resource:
            a["href"] = local_resource
            a["data-k25-local-resource-link"] = "true"
            continue
        inactive_links.append(annotate_inactive_link(soup, a, absolute, original_page_url))
        resource_map.missing.append({"page": page_name, "kind": "navigation", "url": absolute})


    for tag in soup.find_all(True):
        if tag.name in {"a", "area", "link"} or not tag.has_attr("href"):
            continue
        ref = str(tag.get("href") or "")
        if ref.startswith("#"):
            continue
        local = local_reference(ref, kind="href")
        if local:
            tag["href"] = local
        else:
            tag.attrs.pop("href", None)

    if soup.body is None:
        body = soup.new_tag("body")
        for child in [c for c in list(soup.html.contents) if getattr(c, "name", None) != "head"]:
            body.append(child.extract())
        soup.html.append(body)
    if inactive_links:
        add_image_map_info_buttons(soup, original_page_url)
        hashes.append(LINK_SCRIPT_HASH)
    source = " ".join("'" + digest + "'" for digest in hashes) or "'none'"
    csp["content"] = WEBSITE_CSP.replace("script-src 'none'", "script-src " + source)
    charset = soup.find("meta", charset=True)
    if charset is None:
        charset = soup.new_tag("meta", charset="utf-8")
    else:
        charset["charset"] = "utf-8"
        charset.extract()
    soup.head.insert(1, charset)
    for meta in soup.find_all("meta"):
        if str(meta.get("http-equiv") or "").lower() == "content-type":
            meta["content"] = "text/html; charset=utf-8"
    if menu_result["menus"]:
        append_menu_script(soup)
    if inactive_links:
        append_link_inspector(soup)
    resource_map.menu_pages.append({"page": page_name, **menu_result})
    resource_map.link_pages.append({"page": page_name, "links": inactive_links})
    rendered = str(soup)
    return rendered if re.match(r"^\s*<!doctype", rendered, re.I) else "<!doctype html>\n" + rendered


def _verify_local_html(path: Path) -> list[str]:
    issues: list[str] = []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="replace"), "html.parser")
    csp = soup.find("meta", attrs={"http-equiv": re.compile(r"^Content-Security-Policy$", re.I)})
    csp_text = str(csp.get("content") or "") if csp else ""
    required = ["default-src 'none'", "connect-src 'none'", "form-action 'none'"]
    if not csp or any(part not in csp_text for part in required):
        issues.append("CSP fehlt oder ist unvollständig")
    allowed = {MENU_SCRIPT_HASH, LINK_SCRIPT_HASH}
    match = re.search(r"(?:^|;)\s*script-src\s+([^;]+)", csp_text)
    script_sources = set(match[1].split()) if match else set()
    if not script_sources or not script_sources.issubset({"'none'", *("'" + h + "'" for h in allowed)}):
        issues.append("Nicht freigegebene script-src-Quelle")
    for script in soup.find_all("script"):
        digest = "sha256-" + base64.b64encode(hashlib.sha256(str(script.string or "").encode()).digest()).decode()
        if script.has_attr("src") or digest not in allowed or "'" + digest + "'" not in script_sources:
            issues.append("Nicht freigegebenes script-Element")
    if soup.find(["iframe", "frame", "object", "embed", "applet", "portal"]):
        issues.append("aktives Container-Element vorhanden")
    for meta in soup.find_all("meta"):
        if str(meta.get("http-equiv") or "").strip().lower() == "refresh":
            issues.append("Meta-Refresh vorhanden")
    for tag in soup.find_all(True):
        for attr in ("src", "srcset", "poster", "background", "action", "formaction", "href", "xlink:href"):
            if not tag.has_attr(attr):
                continue
            value = str(tag.get(attr) or "").strip()
            if NETWORK_SCHEMES_RE.match(value) or value.lower().startswith(("http:", "https:", "javascript:", "vbscript:", "blob:")):
                issues.append(f"aktive Netz-/Skript-Referenz: <{tag.name}> {attr}")
        for attr in tag.attrs:
            if attr.lower().startswith("on"):
                issues.append(f"Eventhandler vorhanden: <{tag.name}> {attr}")
        if tag.has_attr("style") and re.search(r"url\(\s*['\"]?(?:https?:)?//", str(tag.get("style") or ""), re.I):
            issues.append(f"externe CSS-URL im style-Attribut: <{tag.name}>")
    for style_tag in soup.find_all("style"):
        style = style_tag.get_text()
        if re.search(r"url\(\s*['\"]?(?:https?:)?//", style, re.I) or re.search(r"@import\s+[^;]*(?:https?:)?//", style, re.I):
            issues.append("externe CSS-URL/@import in style-Element")
    return sorted(set(issues))


def build_website_mirror(
    har_sources: Path | list[Path] | tuple[Path, ...], visited: list[dict[str, Any]], website_dir: Path,
    case_root: Path, logger: Any = None,
) -> dict[str, Any]:
    pages_dir = website_dir / "seiten"
    pages_dir.mkdir(parents=True, exist_ok=True)

    resource_map, manifest = _extract_site_resources(har_sources, website_dir, case_root)
    write_json(website_dir / "ressourcen_manifest.json", {"created_at": iso_now(), "engine": "k25-derived", "resources": manifest})
    with (website_dir / "ressourcen_manifest.csv").open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["source_url", "mime", "status", "size", "sha256", "local_path", "source_har", "byte_preserved"]
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(manifest)

    page_link_map: dict[str, str] = {}
    filenames: dict[int, str] = {}
    for item in visited:
        idx = int(item.get("index") or 0)
        filename = _page_filename(item)
        filenames[idx] = filename
        for key_name in ("requested_url", "final_url"):
            value = str(item.get(key_name) or "")
            if value:
                page_link_map[_canon_resource_url(value)] = filename

    page_records: list[dict[str, Any]] = []
    all_issues: list[dict[str, Any]] = []
    for item in visited:
        idx = int(item.get("index") or 0)
        raw_rel = str(item.get("raw_dom_relative") or item.get("dom_raw") or "").replace("\\", "/")
        raw_path = case_root / raw_rel if raw_rel else Path()
        if not raw_rel or not raw_path.exists():
            all_issues.append({"index": idx, "issues": ["DOM-Rohdatei fehlt"]})
            continue
        page_url = str(item.get("final_url") or item.get("requested_url") or "")
        localized = _localize_html(raw_path.read_text(encoding="utf-8", errors="replace"), page_url, resource_map, page_link_map, page_name=filenames[idx], selected_images=item.get("image_sources"))
        out = pages_dir / filenames[idx]
        out.write_text(localized, encoding="utf-8", newline="\n")
        issues = _verify_local_html(out)
        rec = {
            "index": idx, "title": item.get("title"), "original_url": page_url,
            "local_file": out.relative_to(website_dir).as_posix(),
            "page": relative_ref(out, case_root),
            "dom_raw": raw_rel,
            "source_url": sanitized_url(page_url),
            "sha256": sha256_file(out),
            "verification": "PASS" if not issues else "FAIL",
            "issues": issues,
        }
        page_records.append(rec)
        if issues:
            all_issues.append({"index": idx, "page": relative_ref(out, case_root), "issues": issues})

    rows = []
    for record in page_records:
        title = html_lib.escape(str(record.get("title") or "(ohne Titel)"))
        source = html_lib.escape(sanitized_url(record["original_url"]))
        local_file = html_lib.escape(quote(record["local_file"], safe="/"), quote=True)
        rows.append(f'<li><a href="{local_file}">{title}</a><br><code>{source}</code></li>')

    csp_attr = html_lib.escape(WEBSITE_CSP, quote=True)
    index_html = (
        '<!doctype html>\n<html><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{csp_attr}">'
        '<title>Forensic SiteSaver – lokaler Website-Spiegel</title>'
        '<style>body{font-family:sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}li{margin:.8rem 0}code{word-break:break-all}.ok{padding:.8rem;background:#eee;border:1px solid #999}</style>'
        '</head><body><h1>Forensic SiteSaver – lokaler Website-Spiegel</h1>'
        '<p class="ok">Die Seiten und passiven Ressourcen sind lokal gespeichert. Originalskripte, externe Netzwerkzugriffe, Frames und Formulare sind blockiert. Menüs und die Anzeige gesperrter Linkziele verwenden ausschließlich lokalen Bediencode.</p>'
        '<ol>' + ''.join(rows) + '</ol></body></html>'
    )
    index_path = website_dir / "index.html"
    index_path.write_text(index_html, encoding="utf-8", newline="\n")
    index_issues = _verify_local_html(index_path)
    if index_issues:
        all_issues.append({"page": relative_ref(index_path, case_root), "issues": index_issues})

    result = {
        "generated_at": iso_now(), "engine": "k25-derived",
        "website_index": relative_ref(index_path, case_root),
        "pages": page_records,
        "materialized_resources": len(manifest),
        "network_safety_verification": "PASS" if not all_issues else "FAIL",
        "issues": all_issues,
        "policy": {
            "har": "Primärquelle der ursprünglichen Netzwerkkommunikation und Response-Inhalte",
            "dom_raw": "Gerenderter DOM-Zustand als inerte .dom.txt-Datei",
            "website_html": "lokalisierte Auswertungsfassung; keine Online-Nachladung",
            "resources": "passive Ressourcen aus HAR bytegetreu materialisiert; Host-/Pfadstruktur soweit möglich erhalten",
            "css": "Original-CSS bytegetreu gesichert; separate kleine Laufzeitkopie für lokale URL-Umschreibung",
            "scripts": "Originalskripte entfernt; eigene Menü- und Linkcontroller ausschließlich per CSP-Hash freigegeben",
            "svg": "bytegetreu gesichert und ausschließlich als passive Bilder eingebunden",
        },
    }
    (website_dir / "website_manifest.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    summary = [
        f"{TOOL_NAME} {TOOL_VERSION} – LOKALER WEBSITE-SPIEGEL", "",
        "Vorschauerstellung: vollständiges K25-Spiegelmodul mit Anpassungen für Version 1.1", "",
        f"Ergebnis der Netzwerksicherheitsprüfung: {result['network_safety_verification']}",
        f"Startseite: {result['website_index']}",
        f"Lokalisierte Seiten: {len(page_records)}",
        f"Bytegetreu materialisierte passive Ressourcen: {len(manifest)}", "",
        "Konzept:",
        "- nur eine lauffähige HTML-Auswertungsfassung unter 02_website",
        "- ursprüngliche Netzwerkkommunikation bleibt vollständig in 01_har",
        "- gerenderter DOM bleibt unverändert in der ursprünglichen Sicherung erhalten",
        "- Rasterbilder, Fonts, Audio/Video und Original-CSS werden aus HAR lokal abgelegt",
        "- Bild-/Mediendateien werden nicht konvertiert oder neu komprimiert",
        "- Original-CSS bleibt unverändert; die HTML-Seiten verwenden eine umgeschriebene Laufzeitkopie",
        "- Originalskripte/Frames/Formulare/aktive Objekte sind deaktiviert; eigene Bedienhilfen sind per Hash freigegeben",
        "- Online-Links werden blockiert; lokale Archivseiten und lokale Ressourcen bleiben verlinkt",
        "- CSP sperrt Netzwerkzugriffe zusätzlich auf Browser-Ebene",
        "- SVG wird bytegetreu gesichert und ausschließlich als passives Bild gerendert",
    ]
    if all_issues:
        summary += ["", "Festgestellte Probleme:"]
        for rec in all_issues:
            summary.append("- " + json.dumps(rec, ensure_ascii=False))
    (website_dir / "NETZWERKSICHERHEIT.txt").write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")
    write_json(website_dir / "menue_manifest.json", {"controller_csp_hash": MENU_SCRIPT_HASH, "pages": resource_map.menu_pages})
    write_json(website_dir / "linkziele_manifest.json", {"controller_csp_hash": LINK_SCRIPT_HASH, "pages": resource_map.link_pages})
    for reference in resource_map.missing:
        if reference["kind"] == "navigation":
            reference["reason"] = "page_not_archived"
        else:
            reference.update(resource_map.issues.get(_canon_resource_url(reference["url"]), {"reason": "not_in_har"}))
    write_json(website_dir / "fehlende_referenzen.json", {"references": resource_map.missing})
    if logger is not None:
        logger.write("website_mirror_built", index=relative_ref(index_path, case_root), pages=len(page_records),
                     resources=len(manifest), verification=result["network_safety_verification"])
    return result


def _read_har_document(path: Path) -> dict[str, Any]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path, "r") as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            har_names = [n for n in names if n.lower().endswith(".har")]
            candidates = har_names or [n for n in names if n.lower().endswith((".json", ".txt"))]
            for name in candidates:
                try:
                    raw = json.loads(zf.read(name).decode("utf-8"))
                    if isinstance(raw, dict) and isinstance(raw.get("log"), dict):
                        return raw
                except Exception:
                    continue
        raise ValueError(f"Kein HAR-Dokument im Archiv gefunden: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


class ResourceMap(dict[str, dict[str, Any]]):
    def __init__(self, website: Path):
        super().__init__()
        self.website = website
        self.missing: list[dict[str, Any]] = []
        self.issues: dict[str, dict[str, Any]] = {}
        self.menu_pages: list[dict[str, Any]] = []
        self.link_pages: list[dict[str, Any]] = []
        self.files: dict[str, dict[str, Any]] | None = None
        self.runtime: dict[str, Path] = {}


def relative_ref(path: Path, case_root: Path) -> str:
    try:
        return path.relative_to(case_root).as_posix()
    except ValueError:
        return path.as_posix()


def safe_exception_text(exc: Exception, case_root: Path | None = None) -> str:
    from common import safe_exception
    return safe_exception(exc)


def iter_har_entry_sources(har_sources):
    paths = discover_har_files(har_sources) if isinstance(har_sources, Path) else har_sources
    for source in paths:
        try:
            document = _read_har_document(source)
        except Exception:
            continue
        for entry in (document.get("log") or {}).get("entries") or []:
            yield entry, source


def build_local_mirror(case_root: Path, visited: list[dict[str, Any]], *, output_dir: Path | None = None) -> dict[str, Any]:
    website = output_dir if output_dir is not None else case_root / "02_website"
    website.mkdir(parents=True, exist_ok=True)
    result = build_website_mirror(case_root / "01_har", visited, website, case_root)
    return {"pages": len(result["pages"]), "resources": result["materialized_resources"]}
