# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Recognize existing navigation panels; authorize only our fixed DOM controller."""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urldefrag

from bs4 import BeautifulSoup, Tag


MENU_SCRIPT = Path(__file__).with_name("offline_menu.js").read_text(encoding="utf-8")
MENU_SCRIPT_HASH = "sha256-" + base64.b64encode(hashlib.sha256(MENU_SCRIPT.encode("utf-8")).digest()).decode("ascii")
PREFIX = "data-forensic-sitesaver-menu-"
MENU_NAME = re.compile(r"menu|navigation|navbar|dropdown|subnav", re.I)
PANEL_SELECTOR = ".dropdown-menu, .sub-menu, .submenu, [role=menu]"


def prepare_offline_menus(soup: BeautifulSoup, page_url: str, base_url: str) -> dict[str, Any]:
    """Annotate only recognized controls and panels, never executable site data.

    Real navigation anchors retain their destination and receive a separate
    submenu button. No form control is promoted to an interactive menu.
    """
    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            if attr.startswith(PREFIX):
                del tag[attr]

    menus: list[dict[str, Any]] = []
    unresolved: list[dict[str, str]] = []
    panel_keys: dict[int, str] = {}

    def menu_panel(panel: Tag | None, control: Tag) -> bool:
        if panel is None or panel is control or control in panel.parents or panel in control.parents:
            return False
        if panel.name not in {"nav", "ul", "ol", "div", "section", "aside"}:
            return False
        if panel.find_parent("form") or not panel.find("a", href=True):
            return False
        names = " ".join([str(panel.get("id") or ""), *panel.get("class", []),
                          str(control.get("id") or ""), *control.get("class", [])])
        return (panel.name == "nav" or panel.get("role") in {"menu", "menubar", "navigation"}
                or bool(MENU_NAME.search(names)) or control.get("aria-haspopup") in {"true", "menu"})

    for control in list(soup.find_all(["button", "a", "div", "span"])):
        if control.find_parent("form") or control.has_attr("disabled"):
            continue
        classes = control.get("class", [])
        parent = control.parent
        parent_menu = (isinstance(parent, Tag)
                       and any(c in {"menu-item-has-children", "has-submenu", "dropdown"} for c in parent.get("class", []))
                       and parent.find(["a", "button"], recursive=False) is control)
        toggle = str(control.get("data-bs-toggle") or control.get("data-toggle") or "").lower()
        is_control = (control.name == "button" or control.get("role") == "button"
                      or control.has_attr("aria-expanded") or control.has_attr("aria-haspopup")
                      or toggle in {"collapse", "dropdown"}
                      or parent_menu
                      or any(c in {"menu-toggle", "dropdown-toggle", "navbar-toggler", "sub-menu-toggle"} for c in classes))
        if not is_control:
            continue
        panel = None
        method = ""
        for identifier in str(control.get("aria-controls") or "").split():
            candidate = soup.find(id=identifier)
            if menu_panel(candidate, control):
                panel, method = candidate, "aria-controls"
                break
        if panel is None:
            selector = str(control.get("data-bs-target") or control.get("data-target") or "")
            if re.fullmatch(r"[#.][\w-]+", selector):
                candidate = soup.find(id=selector[1:]) if selector[0] == "#" else soup.find(class_=selector[1:])
                if menu_panel(candidate, control):
                    panel, method = candidate, "data-target"
        if panel is None:
            href = str(control.get("href") or "")
            resolved = urljoin(base_url, href)
            # Fragment controls may only address the current page, never a
            # different page which happens to share an element ID.
            if href and urldefrag(resolved)[0] == urldefrag(page_url)[0]:
                candidate = soup.find(id=urlparse(resolved).fragment)
                if menu_panel(candidate, control):
                    panel, method = candidate, "fragment"
        if panel is None and (toggle == "dropdown" or "dropdown-toggle" in classes or parent_menu):
            parent = control.parent
            if isinstance(parent, Tag):
                for candidate in parent.select(PANEL_SELECTOR):
                    # Do not accidentally capture a deeper nested dropdown.
                    if candidate.parent is parent and menu_panel(candidate, control):
                        panel, method = candidate, "dropdown"
                        break
        if panel is None:
            if control.has_attr("aria-controls") or toggle in {"collapse", "dropdown"}:
                unresolved.append({"label": control.get_text(" ", strip=True)[:160], "reason": "Kein vorhandenes Navigationsmenü erkannt"})
            continue
        if control.find_parent("a") or control.find_parent("button"):
            continue

        key = panel_keys.get(id(panel))
        if key is None:
            key = str(len(panel_keys) + 1)
            panel_keys[id(panel)] = key
            panel[PREFIX + "panel"] = key
        if not panel.get("id"):
            identifier = f"forensic-sitesaver-menu-{key}"
            while soup.find(id=identifier):
                identifier += "-local"
            panel["id"] = identifier

        label = str(control.get("aria-label") or control.get_text(" ", strip=True) or "Menü")[:160]
        href = str(control.get("href") or "").strip()
        resolved = urljoin(base_url, href)
        local_toggle = (not href or href == "#" or href.lower().startswith("javascript:")
                        or (urldefrag(resolved)[0] == urldefrag(page_url)[0]
                            and urlparse(resolved).fragment == panel["id"]))
        trigger = control
        if control.name == "a" and not local_toggle:
            trigger = soup.new_tag("button", type="button")
            trigger.string = "▾"
            trigger["aria-label"] = f"Untermenü: {label}"
            trigger["style"] = "font:inherit;cursor:pointer;margin-inline-start:.3em"
            trigger["aria-expanded"] = str(control.get("aria-expanded") or "false")
            for attr in ("aria-expanded", "aria-controls", "aria-haspopup"):
                control.attrs.pop(attr, None)
            control.insert_after(trigger)
        else:
            trigger.attrs.pop("href", None)
            trigger.attrs.pop("xlink:href", None)
        trigger[PREFIX + "controls"] = key
        trigger["aria-controls"] = panel["id"]
        if trigger.name == "button":
            trigger["type"] = "button"
            for attr in ("form", "formaction", "formmethod", "formenctype", "formtarget"):
                trigger.attrs.pop(attr, None)
        else:
            trigger["role"] = "button"
            trigger["tabindex"] = "0"
        menus.append({"panel_id": panel["id"], "label": label, "recognition": method,
                      "separate_button": trigger is not control})
    return {"menus": menus, "unresolved": unresolved}


def append_menu_script(soup: BeautifulSoup) -> None:
    script = soup.new_tag("script")
    script["data-forensic-sitesaver-controller"] = "menu"
    script.string = MENU_SCRIPT
    # The document may be a fragment without a body; either location executes
    # after its menu markup has been parsed.
    (soup.body if soup.body is not None else soup).append(script)
