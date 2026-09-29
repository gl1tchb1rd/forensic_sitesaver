# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from common import APP_NAME, APP_VERSION, REPOSITORY_URL, iso_now, registrable_domain, sanitize_url, write_csv, write_json, write_text

PAYMENT_PATTERNS = {
    "Stripe": ("stripe.com", "stripe.network"),
    "PayPal": ("paypal.com", "paypalobjects.com"),
    "Klarna": ("klarna.com", "klarna.net"),
    "Adyen": ("adyen.com", "adyenpayments.com"),
    "Mollie": ("mollie.com",),
    "Checkout.com": ("checkout.com",),
    "Amazon Pay": ("amazonpay.com", "payments-amazon.com"),
    "Apple Pay": ("apple-pay-gateway.apple.com",),
    "Google Pay": ("pay.google.com",),
    "Braintree": ("braintreegateway.com", "braintree-api.com"),
}
SHOP_PATTERNS = {
    "Shopify": ("shopify.com", "shopifycdn.com", "cdn.shopify.com"),
    "WooCommerce": ("woocommerce", "wc-ajax", "/wp-json/wc/"),
    "Magento / Adobe Commerce": ("magento", "/rest/v1/", "mage/"),
    "PrestaShop": ("prestashop",),
    "Shopware": ("shopware", "/store-api/", "/api/_action/"),
    "BigCommerce": ("bigcommerce.com",),
}
INFRA_PATTERNS = {
    "Cloudflare": ("cloudflare.com", "cloudflare.net", "cdnjs.cloudflare.com"),
    "Amazon CloudFront/AWS": ("cloudfront.net", "amazonaws.com"),
    "Fastly": ("fastly.net", "fastly.com"),
    "Akamai": ("akamai.net", "akamaiedge.net", "akamaihd.net"),
    "Bunny CDN": ("b-cdn.net", "bunny.net"),
}
ANALYTICS_PATTERNS = {
    "Google Analytics / Tag Manager": ("google-analytics.com", "googletagmanager.com"),
    "Meta/Facebook": ("facebook.net", "facebook.com/tr"),
    "Matomo": ("matomo",),
    "Hotjar": ("hotjar.com", "hotjar.io"),
}
BACKEND_HINTS = ("/api/", "/graphql", "/wp-json/", "/admin-ajax.php", "/rest/", "/store-api/", "/ajax/")


def discover_har_files(path: Path) -> list[Path]:
    path = path.resolve()
    if path.is_file():
        return [path]
    files: list[Path] = []
    for p in sorted(path.iterdir()):
        if p.is_file() and (p.name.lower().endswith(".har") or p.name.lower().endswith(".har.zip")):
            files.append(p)
    return files


def read_har_document(path: Path) -> dict[str, Any]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()
            candidates = [n for n in names if n.lower().endswith(".har")]
            if not candidates:
                candidates = [n for n in names if n.lower().endswith(".json")]
            if not candidates:
                raise ValueError(f"Keine HAR-Datei im ZIP gefunden: {path.name}")
            return json.loads(z.read(candidates[0]).decode("utf-8", "replace"))
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def iter_har_entries(paths: Iterable[Path]):
    for path in paths:
        try:
            doc = read_har_document(path)
        except Exception:
            continue
        for entry in ((doc.get("log") or {}).get("entries") or []):
            yield path, entry


def _detect(value: str, mapping: dict[str, tuple[str, ...]]) -> list[str]:
    low = value.lower()
    return [name for name, patterns in mapping.items() if any(p.lower() in low for p in patterns)]


def analyze_har(input_path: Path, output_dir: Path, base_url: str | None = None) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    har_files = discover_har_files(input_path)
    if not har_files:
        raise FileNotFoundError("Keine HAR-Datei bzw. kein HAR-Segment im gewählten Pfad gefunden.")

    root_host = (urlparse(base_url).hostname or "").lower() if base_url else ""
    root_domain = registrable_domain(root_host) if root_host else ""
    host_counts: Counter[str] = Counter()
    host_methods: dict[str, Counter[str]] = defaultdict(Counter)
    host_statuses: dict[str, Counter[str]] = defaultdict(Counter)
    host_types: dict[str, Counter[str]] = defaultdict(Counter)
    host_ips: dict[str, set[str]] = defaultdict(set)
    sample_urls: dict[str, list[str]] = defaultdict(list)
    payments: Counter[str] = Counter()
    shops: Counter[str] = Counter()
    infrastructure: Counter[str] = Counter()
    analytics: Counter[str] = Counter()
    backend_candidates: list[dict[str, Any]] = []
    entries_total = 0

    first_host = ""
    for segment, entry in iter_har_entries(har_files):
        entries_total += 1
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = str(req.get("url") or "")
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if not host:
            continue
        if not first_host:
            first_host = host
        host_counts[host] += 1
        host_methods[host][str(req.get("method") or "")] += 1
        host_statuses[host][str(resp.get("status") or "")] += 1
        rtype = str(entry.get("_resourceType") or "")
        if rtype:
            host_types[host][rtype] += 1
        server_ip = str(resp.get("_serverIPAddress") or entry.get("serverIPAddress") or "")
        if server_ip:
            host_ips[host].add(server_ip)
        surl = sanitize_url(url)
        if surl and surl not in sample_urls[host] and len(sample_urls[host]) < 3:
            sample_urls[host].append(surl)

        combined = f"{host} {p.path} {url}"
        for name in _detect(combined, PAYMENT_PATTERNS):
            payments[name] += 1
        for name in _detect(combined, SHOP_PATTERNS):
            shops[name] += 1
        for name in _detect(combined, INFRA_PATTERNS):
            infrastructure[name] += 1
        for name in _detect(combined, ANALYTICS_PATTERNS):
            analytics[name] += 1

        mime = str((resp.get("content") or {}).get("mimeType") or "").lower()
        looks_backend = (
            any(h in p.path.lower() for h in BACKEND_HINTS) or "json" in mime or
            rtype.lower() in {"xhr", "fetch"}
        )
        if looks_backend and len(backend_candidates) < 2000:
            backend_candidates.append({
                "host": host, "method": req.get("method"), "status": resp.get("status"),
                "mime_type": mime, "resource_type": rtype, "url": surl,
                "server_ip": server_ip, "har_segment": segment.name,
            })

    if not root_host:
        root_host = first_host
        root_domain = registrable_domain(root_host) if root_host else ""

    hosts_rows: list[dict[str, Any]] = []
    external_rows: list[dict[str, Any]] = []
    for host, count in host_counts.most_common():
        payment = ", ".join(_detect(host, PAYMENT_PATTERNS))
        shop = ", ".join(_detect(host, SHOP_PATTERNS))
        infra = ", ".join(_detect(host, INFRA_PATTERNS))
        ana = ", ".join(_detect(host, ANALYTICS_PATTERNS))
        row = {
            "host": host, "registered_domain": registrable_domain(host), "requests": count,
            "methods": ", ".join(f"{k}:{v}" for k, v in host_methods[host].items()),
            "status_codes": ", ".join(f"{k}:{v}" for k, v in host_statuses[host].items()),
            "resource_types": ", ".join(f"{k}:{v}" for k, v in host_types[host].items()),
            "server_ips": ", ".join(sorted(host_ips[host])),
            "payment_provider": payment, "ecommerce_platform": shop,
            "infrastructure_provider": infra, "analytics_provider": ana,
            "sample_urls": " | ".join(sample_urls[host]),
        }
        hosts_rows.append(row)
        if root_domain and registrable_domain(host) != root_domain:
            external_rows.append(row.copy())

    result = {
        "tool": APP_NAME, "tool_version": APP_VERSION, "repository": REPOSITORY_URL, "created_at": iso_now(),
        "input": input_path.name, "base_host": root_host, "base_registered_domain": root_domain,
        "har_segment_count": len(har_files), "har_segments": [p.name for p in har_files],
        "entries_total": entries_total, "hosts": hosts_rows, "external_connections": external_rows,
        "backend_candidates": backend_candidates,
        "payment_providers": dict(payments), "ecommerce_platforms": dict(shops),
        "infrastructure_services": dict(infrastructure), "analytics_services": dict(analytics),
    }
    write_json(output_dir / "har_analysis.json", result)
    write_csv(output_dir / "hosts.csv", hosts_rows, list(hosts_rows[0].keys()) if hosts_rows else ["host"])
    write_csv(output_dir / "external_connections.csv", external_rows, list(hosts_rows[0].keys()) if hosts_rows else ["host"])
    write_csv(output_dir / "backend_candidates.csv", backend_candidates,
              ["host", "method", "status", "mime_type", "resource_type", "url", "server_ip", "har_segment"])
    write_csv(output_dir / "payment_providers.csv",
              [{"provider": k, "matches": v} for k, v in payments.most_common()], ["provider", "matches"])
    write_csv(output_dir / "ecommerce_platforms.csv",
              [{"platform": k, "matches": v} for k, v in shops.most_common()], ["platform", "matches"])

    lines = [
        f"{APP_NAME} – HAR-Auswertung", "=" * 72, "",
        f"Version: {APP_VERSION}", f"Projekt / Quellcode: {REPOSITORY_URL}", f"Erstellt: {result['created_at']}",
        f"Requests insgesamt: {entries_total}",
        f"Bezugs-Host: {root_host or '-'}", f"Registrierbare Bezugsdomain: {root_domain or '-'}", "",
        "ERKANNTE ZAHLUNGSDIENSTLEISTER", "-" * 72,
    ]
    if payments:
        lines += [f"- {name}: {count} Treffer" for name, count in payments.most_common()]
    else:
        lines.append("- keine anhand der hinterlegten Indikatoren erkannt")
    lines += ["", "ERKANNTE SHOP-/E-COMMERCE-SYSTEME", "-" * 72]
    if shops:
        lines += [f"- {name}: {count} Treffer" for name, count in shops.most_common()]
    else:
        lines.append("- keine anhand der hinterlegten Indikatoren erkannt")
    lines += ["", "BACKEND-/API-KANDIDATEN", "-" * 72,
              f"Erkannte Kandidaten: {len(backend_candidates)}; Details siehe backend_candidates.csv.", "",
              "EXTERNE VERBINDUNGEN", "-" * 72,
              "Dedupliziert nach Host. Query-Parameter werden in Beispiel-URLs nicht ausgegeben; die unveränderte HAR bleibt Primärquelle."]
    if not external_rows:
        lines.append("- keine externen Hosts gegenüber der Bezugsdomain erkannt")
    for row in external_rows:
        classifications = [x for x in (
            row.get("payment_provider"), row.get("ecommerce_platform"), row.get("infrastructure_provider"), row.get("analytics_provider")
        ) if x]
        lines += [
            "", f"- {row['host']} ({row['requests']} Requests)",
            f"  Registrierbare Domain: {row['registered_domain']}",
            f"  Server-IP(s): {row['server_ips'] or '-'}",
            f"  Einordnung: {', '.join(classifications) if classifications else 'nicht klassifiziert'}",
            f"  Beispiele: {row['sample_urls'] or '-'}",
        ]
    write_text(output_dir / "HAR_Auswertung.txt", "\n".join(lines))
    return result
