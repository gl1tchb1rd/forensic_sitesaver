# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read public GitHub releases without changing the installed application."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from common import APP_VERSION, REPOSITORY_URL, USER_AGENT

LATEST_RELEASE_API = REPOSITORY_URL.replace(
    "https://github.com/", "https://api.github.com/repos/", 1
) + "/releases/latest"
_SEMVER = re.compile(
    r"[vV]?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def parse_version(value: str) -> tuple[tuple[int, int, int], tuple[str, ...]]:
    """Parse SemVer, allowing GitHub's usual leading v."""
    match = _SEMVER.fullmatch(value.strip())
    if not match:
        raise ValueError(f"Ungültige Versionsnummer: {value!r}. Erwartet wird z. B. v1.2.3.")
    prerelease = tuple(match[4].split(".")) if match[4] else ()
    if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease):
        raise ValueError(f"Ungültige Vorabversionsnummer: {value!r}.")
    return (int(match[1]), int(match[2]), int(match[3])), prerelease


def is_newer_version(candidate: str, installed: str) -> bool:
    new_core, new_pre = parse_version(candidate)
    old_core, old_pre = parse_version(installed)
    if new_core != old_core:
        return new_core > old_core
    if not new_pre or not old_pre:
        return bool(old_pre) and not new_pre
    for new, old in zip(new_pre, old_pre):
        if new == old:
            continue
        if new.isdigit() and old.isdigit():
            return int(new) > int(old)
        if new.isdigit() != old.isdigit():
            return not new.isdigit()
        return new > old
    return len(new_pre) > len(old_pre)


@dataclass(frozen=True)
class ReleaseInfo:
    tag: str
    notes: str
    update_available: bool

    @property
    def release_url(self) -> str:
        return f"{REPOSITORY_URL}/releases/tag/{quote(self.tag, safe='')}"

    @property
    def download_url(self) -> str:
        return f"{REPOSITORY_URL}/archive/refs/tags/{quote(self.tag, safe='')}.zip"


def check_latest_release(installed_version: str = APP_VERSION) -> ReleaseInfo | None:
    """Return the latest stable release, or None when none has been published."""
    request = Request(LATEST_RELEASE_API, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    })
    try:
        with urlopen(request, timeout=10) as response:
            data = json.load(response)
    except HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in {403, 429}:
            raise RuntimeError("GitHub hat die Anfrage begrenzt. Bitte später erneut prüfen.") from exc
        raise RuntimeError(f"GitHub-Abfrage fehlgeschlagen (HTTP {exc.code}).") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("GitHub ist nicht erreichbar. Bitte die Internetverbindung prüfen.") from exc
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("GitHub hat keine gültigen Release-Daten geliefert.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("tag_name"), str):
        raise RuntimeError("In der GitHub-Antwort fehlt eine gültige Release-Versionsnummer.")
    tag = data["tag_name"].strip()
    _, prerelease = parse_version(tag)
    if data.get("draft") or data.get("prerelease") or prerelease:
        return None
    notes = data.get("body") or "Keine Release Notes hinterlegt."
    if not isinstance(notes, str):
        raise RuntimeError("GitHub hat ungültige Release Notes geliefert.")
    return ReleaseInfo(tag, notes, is_newer_version(tag, installed_version))
