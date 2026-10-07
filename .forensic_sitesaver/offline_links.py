# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Readable original destinations without navigation or executable URL data."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag


PREFIX = "data-forensic-sitesaver-link-"
LINK_SCRIPT = Path(__file__).with_name("offline_links.js").read_text(encoding="utf-8")
LINK_SCRIPT_HASH = "sha256-" + base64.b64encode(hashlib.sha256(LINK_SCRIPT.encode("utf-8")).digest()).decode("ascii")
LINK_STYLE = """
a[data-forensic-sitesaver-link-target] { cursor:help; text-decoration:underline dotted; }
[data-forensic-sitesaver-link-badge] { font-size:.72em; font-weight:normal; margin-inline-start:.35em; white-space:nowrap; }
[data-forensic-sitesaver-link-ui="tooltip"] {
 position:fixed!important; z-index:2147483646!important; pointer-events:none!important;
 box-sizing:border-box!important; max-width:min(40rem,calc(100vw - 16px))!important;
 max-height:min(18rem,calc(100vh - 16px))!important; overflow:auto!important;
 padding:.6rem .8rem!important; border:1px solid #666!important; border-radius:.35rem!important;
 background:#222!important; color:#fff!important; font:14px/1.4 system-ui,sans-serif!important;
 white-space:pre-wrap!important; overflow-wrap:anywhere!important;
}
[data-forensic-sitesaver-link-ui="dialog"] {
 position:fixed!important; inset:0!important; margin:auto!important; box-sizing:border-box!important;
 width:min(38rem,calc(100vw - 2rem))!important; max-height:calc(100vh - 2rem)!important;
 height:fit-content!important; overflow:auto!important; padding:1.2rem!important;
 background:#fff!important; color:#222!important; border:1px solid #888!important; border-radius:.5rem!important;
 font:16px/1.5 system-ui,sans-serif!important; text-align:left!important;
}
[data-forensic-sitesaver-link-ui="dialog"]::backdrop { background:rgba(0,0,0,.5); }
[data-forensic-sitesaver-link-ui="dialog"][open],
[data-forensic-sitesaver-link-ui="tooltip"]:not([hidden]) { display:block!important; }
[data-forensic-sitesaver-link-ui="dialog"] h2 { margin:0 0 .6rem!important; font:bold 1.2rem/1.4 system-ui,sans-serif!important; color:#222!important; }
[data-forensic-sitesaver-link-ui="dialog"] p { margin:.5rem 0!important; color:#222!important; }
[data-forensic-sitesaver-link-ui="dialog"] textarea {
 display:block!important; box-sizing:border-box!important; width:100%!important; height:7rem!important;
 padding:.5rem!important; margin:.5rem 0!important; color:#222!important; background:#f5f5f5!important;
 font:14px/1.4 ui-monospace,monospace!important; white-space:pre-wrap!important; overflow-wrap:anywhere!important;
}
[data-forensic-sitesaver-link-ui="dialog"] button {
 display:inline-block!important; padding:.45rem .7rem!important; margin:.3rem .5rem 0 0!important;
 background:#eee!important; color:#222!important; border:1px solid #888!important; border-radius:.25rem!important;
 font:inherit!important; cursor:pointer!important;
}
[data-forensic-sitesaver-link-ui="dialog"] button:focus-visible,
[data-forensic-sitesaver-link-target]:focus-visible { outline:2px solid #1465c0!important; outline-offset:3px!important; }
[data-forensic-sitesaver-link-ui="tooltip"][hidden],
[data-forensic-sitesaver-link-ui="dialog"]:not([open]) { display:none!important; }
"""


def clear_link_annotations(soup: BeautifulSoup) -> None:
    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            if attr.startswith(PREFIX) or attr == "data-original-url":
                del tag[attr]


def annotate_inactive_link(soup: BeautifulSoup, tag: Tag, original_url: str, page_url: str) -> dict[str, str]:
    target = urlparse(original_url)
    if target.scheme in {"http", "https"}:
        kind = "external" if target.netloc.lower() != urlparse(page_url).netloc.lower() else "uncaptured"
        marker = "extern · deaktiviert" if kind == "external" else "nicht gesichert · deaktiviert"
    elif target.scheme == "mailto":
        kind, marker = "email", "E-Mail · deaktiviert"
    elif target.scheme == "tel":
        kind, marker = "phone", "Telefon · deaktiviert"
    else:
        kind, marker = "action", "Aktion · deaktiviert"
    image = tag.find("img", alt=True)
    label = str(tag.get("aria-label") or tag.get("alt") or tag.get_text(" ", strip=True)
                or (image.get("alt") if image else "") or "Linkziel")
    tag.attrs.pop("href", None)
    tag.attrs.pop("xlink:href", None)
    tag["data-original-url"] = original_url
    tag[PREFIX + "target"] = kind
    tag["title"] = f"{marker}. Ursprüngliches Ziel: {original_url}"
    tag["role"] = "button"
    tag["tabindex"] = "0"
    tag["aria-haspopup"] = "dialog"
    tag["aria-label"] = f"{label} – {marker}; Zieladresse anzeigen"
    # The information button works; only navigation is disabled.
    tag.attrs.pop("aria-disabled", None)
    if tag.name == "a" and tag.find_parent("svg") is None:
        badge = soup.new_tag("span")
        badge[PREFIX + "badge"] = "true"
        badge["aria-hidden"] = "true"
        badge.string = marker
        tag.append(badge)
    return {"url": original_url, "kind": kind, "label": label}


def append_link_inspector(soup: BeautifulSoup) -> None:
    style = soup.new_tag("style")
    style.string = LINK_STYLE
    soup.head.append(style)
    script = soup.new_tag("script")
    script["data-forensic-sitesaver-controller"] = "links"
    script.string = LINK_SCRIPT
    (soup.body if soup.body is not None else soup).append(script)


def add_image_map_info_buttons(soup: BeautifulSoup, page_url: str) -> None:
    # Without href, browsers stop treating image-map areas as click targets.
    # Keep those regions inert and provide explicit information buttons instead.
    for image in soup.find_all("img", usemap=True):
        reference = str(image["usemap"])
        if not reference.startswith("#"):
            continue
        mapping = soup.find("map", attrs={"name": reference[1:]}) or soup.find("map", id=reference[1:])
        if mapping is None:
            continue
        previous = image
        for area in mapping.find_all("area", attrs={PREFIX + "target": True}):
            button = soup.new_tag("button", type="button")
            button.string = "Bildlink: " + str(area.get("alt") or "Zieladresse anzeigen")
            annotate_inactive_link(soup, button, str(area["data-original-url"]), page_url)
            previous.insert_after(button)
            previous = button
