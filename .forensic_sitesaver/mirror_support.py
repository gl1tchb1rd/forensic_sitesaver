# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared HAR/URL/CSS handling for the K25-derived offline mirror."""
from __future__ import annotations
import base64
import os
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse, urlunparse
RESOURCE_MIME_PREFIXES = ("image/", "font/", "audio/", "video/", "text/css")


FONT_MIMES = {"application/font-woff", "application/x-font-woff", "application/vnd.ms-fontobject"}


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


def _har_body(segment: Path, content: dict[str, Any]) -> bytes | None:
    """Read K25-compatible inline/attached HAR bodies without changing the archive."""
    if not content:
        return None
    text = content.get("text")
    inline = None
    try:
        if text is not None:
            try:
                inline = base64.b64decode(text) if str(content.get("encoding") or "").lower() == "base64" else str(text).encode("utf-8")
            except (ValueError, TypeError):
                pass
            if inline:
                return inline
        references = [str(content[name]).strip().replace("\\", "/") for name in ("_file", "_sha1") if content.get(name)]
        if not references:
            return inline
        if zipfile.is_zipfile(segment):
            with zipfile.ZipFile(segment, "r") as archive:
                names = [name for name in archive.namelist() if not name.endswith("/")]
                for reference in references:
                    for candidate in (reference, reference.lstrip("/"), "resources/" + reference.lstrip("/")):
                        matches = [name for name in names if name.replace("\\", "/") == candidate]
                        if len(matches) == 1:
                            return archive.read(matches[0])
                    matches = [name for name in names if name.replace("\\", "/").rsplit("/", 1)[-1] == reference.rsplit("/", 1)[-1]]
                    if len(matches) == 1:
                        return archive.read(matches[0])
        else:
            parent = segment.parent.resolve()
            for reference in references:
                if Path(reference).is_absolute() or re.match(r"^[a-zA-Z]:", reference):
                    continue
                attached = (parent / reference).resolve()
                if parent in attached.parents and attached.is_file():
                    return attached.read_bytes()
    except Exception:
        return inline
    return inline


def _safe_resource_mime(mime: str) -> bool:
    mime = (mime or "").lower().split(";", 1)[0].strip()
    return mime in FONT_MIMES or any(mime.startswith(prefix) for prefix in RESOURCE_MIME_PREFIXES)


def _decode_css(body: bytes, charset: str = "") -> str:
    declared = re.match(br'\s*@charset\s+["\']([^"\']+)["\']\s*;', body)
    encodings = ["utf-8-sig", charset, declared[1].decode("ascii", "replace") if declared else "", "cp1252", "latin-1"]
    for encoding in encodings:
        if not encoding:
            continue
        try:
            text = body.decode(encoding)
            return re.sub(r'^\s*@charset\s+["\'][^"\']+["\']\s*;', '@charset "UTF-8";', text, flags=re.I)
        except (LookupError, UnicodeError):
            continue
    return body.decode("utf-8", "replace")


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
