# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Static display aids; the observed DOM and HAR are never rewritten."""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from common import safe_exception, sha256_file

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def capture_canvases(page: Any, case_root: Path, page_index: int) -> list[dict[str, Any]]:
    """Save canvas pixels separately: canvas bitmap content is absent from HTML/HAR."""
    try:
        rows = page.evaluate("""() => {
          let pixels = 0;
          return Array.from(document.querySelectorAll('canvas'), (canvas, index) => {
            const style = getComputedStyle(canvas);
            const row = {index, width: canvas.width, height: canvas.height,
                display_width: parseFloat(style.width), display_height: parseFloat(style.height)};
            pixels += canvas.width * canvas.height;
            if (index >= 40 || pixels > 16000000) {
                return {...row, error: 'capture_limit'};
            }
            try { return {...row, data: canvas.toDataURL('image/png')}; }
            catch (_) { return {...row, error: 'canvas_pixels_unavailable'}; }
          });
        }""")
        if not isinstance(rows, list):
            return []
    except Exception as exc:
        return [{"error": safe_exception(exc)}]
    records = []
    for row in rows:
        record = {key: row[key] for key in ("index", "width", "height", "display_width", "display_height", "error") if key in row}
        data = str(row.get("data") or "")
        if data.startswith("data:image/png;base64,"):
            try:
                body = base64.b64decode(data.split(",", 1)[1], validate=True)
                if body.startswith(PNG_SIGNATURE):
                    path = case_root / "02_website/_canvas_roh" / f"{page_index:04d}_{row['index']:04d}.png"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
                    record.update(path=path.relative_to(case_root).as_posix(), sha256=sha256_file(path))
            except Exception as exc:
                record["error"] = safe_exception(exc)
        if "path" not in record and "error" not in record:
            record["error"] = "canvas_pixels_unavailable"
        records.append(record)
    return records


def canvas_sources(case_root: Path, records: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """Read only PNG snapshots within the evidence root, including during rebuild."""
    sources = {}
    root = case_root.resolve()
    for row in records:
        relative = str(row.get("path") or "").replace("\\", "/")
        if not relative or not isinstance(row.get("index"), int):
            continue
        path = (root / relative).resolve()
        if root not in path.parents or not path.is_file():
            continue
        body = path.read_bytes()
        if body.startswith(PNG_SIGNATURE) and (not row.get("sha256") or sha256_file(path) == row["sha256"]):
            sources[row["index"]] = {**row, "src": "data:image/png;base64," + base64.b64encode(body).decode("ascii")}
    return sources


def prepare_static_visuals(soup: Any, sources: dict[int, dict[str, Any]]) -> dict[str, int]:
    """Expose scroll reveals without exposing explicitly hidden menus/dialogs."""
    reveals = 0
    for tag in soup.select(".reveal"):
        if any(parent.has_attr("hidden") or parent.get("aria-hidden") == "true"
               for parent in [tag, *tag.parents] if getattr(parent, "attrs", None) is not None):
            continue
        # Inline overrides also cover animations that never finish without the
        # removed original IntersectionObserver. Only marked reveal elements change.
        tag["style"] = str(tag.get("style") or "") + (
            ";opacity:1!important;visibility:visible!important;transform:none!important;"
            "animation:none!important;transition:none!important;"
        )
        reveals += 1
    restored = 0
    for index, canvas in enumerate(soup.find_all("canvas")):
        if index not in sources:
            continue
        canvas.name = "img"
        canvas.clear()
        canvas["src"] = sources[index]["src"]
        for dimension in ("width", "height"):
            display = sources[index].get("display_" + dimension)
            if isinstance(display, (int, float)) and display > 0:
                canvas[dimension] = str(round(display))
        canvas["alt"] = str(canvas.get("aria-label") or "Gesicherte Canvas-Grafik")
        canvas["data-sitesaver-canvas"] = "static"
        restored += 1
    return {"reveals_displayed": reveals, "canvases_restored": restored,
            "canvases_unavailable": len(soup.find_all("canvas"))}
