# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import ipaddress
import json
import re
import socket
from pathlib import Path
from typing import Any

import dns.resolver
import requests

from common import (
    APP_NAME, APP_VERSION, DISCLAIMER, REPOSITORY_URL, USER_AGENT, ensure_dir, hostname_from_value,
    iso_now, registrable_domain, safe_exception, sanitize_component, sha256_file, write_csv,
    write_json, write_text,
)

DNS_PROVIDER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"cloudflare\.com$", re.I), "Cloudflare DNS"),
    (re.compile(r"awsdns-.*\.(?:com|net|org|co\.uk)$", re.I), "Amazon Route 53"),
    (re.compile(r"googledomains\.com$|google\.com$", re.I), "Google DNS"),
    (re.compile(r"azure-dns\.(?:com|net|org|info)$", re.I), "Microsoft Azure DNS"),
    (re.compile(r"ui-dns\.(?:com|de|biz|org)$|ionos\.", re.I), "IONOS DNS"),
    (re.compile(r"rzone\.de$|strato\.de$", re.I), "STRATO DNS"),
    (re.compile(r"hetzner\.(?:com|de)$|your-server\.de$", re.I), "Hetzner DNS"),
]

MAIL_PROVIDER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:google\.com|googlemail\.com)$", re.I), "Google Workspace / Gmail"),
    (re.compile(r"(?:protection\.outlook\.com|outlook\.com|microsoft\.com)$", re.I), "Microsoft 365 / Exchange Online"),
    (re.compile(r"(?:protonmail\.ch|protonmail\.com)$", re.I), "Proton Mail"),
    (re.compile(r"(?:zoho\.(?:com|eu)|zohomail\.)", re.I), "Zoho Mail"),
    (re.compile(r"(?:ionos\.|1and1\.|kundenserver\.de)", re.I), "IONOS"),
    (re.compile(r"(?:strato\.de|rzone\.de)$", re.I), "STRATO"),
    (re.compile(r"(?:mailbox\.org)$", re.I), "mailbox.org"),
    (re.compile(r"(?:mx\.cloudflare\.net|route.*\.mx\.cloudflare\.net)$", re.I), "Cloudflare Email Routing"),
    (re.compile(r"(?:secureserver\.net)$", re.I), "GoDaddy"),
    (re.compile(r"(?:mailgun\.(?:org|net))$", re.I), "Mailgun"),
    (re.compile(r"(?:sendgrid\.net)$", re.I), "Twilio SendGrid"),
    (re.compile(r"(?:mxroute\.com)$", re.I), "MXroute"),
    (re.compile(r"(?:hetzner\.(?:com|de)|your-server\.de)$", re.I), "Hetzner"),
]


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return s


def _dns_resolver() -> dns.resolver.Resolver:
    return dns.resolver.Resolver()


def query_dns(host: str, external_calls: list[dict[str, Any]]) -> dict[str, Any]:
    resolver = _dns_resolver()
    result: dict[str, Any] = {
        "captured_at": iso_now(),
        "host": host,
        "resolver_nameservers": list(getattr(resolver, "nameservers", []) or []),
        "records": {},
    }
    external_calls.append({
        "service": "lokal/systemseitig konfigurierter DNS-Resolver",
        "protocol": "DNS",
        "transmitted_data": host,
        "purpose": "DNS-Auflösung (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA)",
    })
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        rows: list[Any] = []
        try:
            answers = resolver.resolve(host, record_type, lifetime=6)
            for rdata in answers:
                if record_type == "MX":
                    rows.append({"priority": int(rdata.preference), "host": str(rdata.exchange).rstrip(".").lower()})
                elif record_type == "SOA":
                    rows.append({
                        "mname": str(rdata.mname).rstrip("."), "rname": str(rdata.rname).rstrip("."),
                        "serial": int(rdata.serial), "refresh": int(rdata.refresh), "retry": int(rdata.retry),
                        "expire": int(rdata.expire), "minimum": int(rdata.minimum),
                    })
                elif record_type == "TXT":
                    try:
                        rows.append(b"".join(rdata.strings).decode("utf-8", "replace"))
                    except Exception:
                        rows.append(str(rdata).strip('"'))
                else:
                    rows.append(str(rdata).rstrip("."))
        except Exception as exc:
            result["records"][record_type] = {"values": [], "error": safe_exception(exc)}
            continue
        result["records"][record_type] = {"values": rows}
    return result


def resolve_host_ips(host: str, external_calls: list[dict[str, Any]]) -> list[str]:
    resolver = _dns_resolver()
    external_calls.append({
        "service": "lokal/systemseitig konfigurierter DNS-Resolver",
        "protocol": "DNS",
        "transmitted_data": host,
        "purpose": "A-/AAAA-Auflösung eines Servers",
    })
    ips: list[str] = []
    for typ in ("A", "AAAA"):
        try:
            for rdata in resolver.resolve(host, typ, lifetime=6):
                ip = str(rdata)
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
    return ips


def reverse_dns(ip: str, external_calls: list[dict[str, Any]]) -> str | None:
    external_calls.append({
        "service": "lokal/systemseitig konfigurierter DNS-Resolver",
        "protocol": "DNS/PTR",
        "transmitted_data": ip,
        "purpose": "Reverse-DNS-Auflösung",
    })
    try:
        return socket.gethostbyaddr(ip)[0].rstrip(".")
    except Exception:
        return None


def fetch_json(url: str, service: str, transmitted: Any, purpose: str,
               external_calls: list[dict[str, Any]], timeout: int = 8) -> dict[str, Any]:
    external_calls.append({
        "service": service, "protocol": "HTTPS", "transmitted_data": transmitted, "purpose": purpose,
    })
    out: dict[str, Any] = {"request_url": url, "source_service": service, "captured_at": iso_now()}
    try:
        r = _session().get(url, timeout=timeout)
        out["http_status"] = r.status_code
        out["ok"] = bool(r.ok)
        if r.ok:
            out["data"] = r.json()
        else:
            out["error"] = f"HTTP {r.status_code}"
    except Exception as exc:
        out["ok"] = False
        out["error"] = safe_exception(exc)
    return out


def _entity_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "org"}:
                val = item[3]
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return None


def parse_rdap_registrar(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities", []) or []:
        roles = [str(x).lower() for x in entity.get("roles", []) or []]
        if "registrar" in roles:
            return _entity_name(entity) or entity.get("handle")
    return None


def domain_rdap(domain: str, external_calls: list[dict[str, Any]]) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    urls: list[tuple[str, str]] = []
    if domain.endswith(".de"):
        urls.append((f"https://rdap.denic.de/domain/{domain}", "DENIC RDAP"))
    urls.append((f"https://rdap.org/domain/{domain}", "RDAP.org"))
    selected: dict[str, Any] | None = None
    for url, service in urls:
        snap = fetch_json(url, service, domain, "Domain-RDAP-/Registrar-/Registrierungsinformationen", external_calls)
        attempts.append(snap)
        if snap.get("ok") and isinstance(snap.get("data"), dict):
            selected = snap
            break
    return {"query": domain, "attempts": attempts, "selected": selected}


def whois_query(server: str, query: str, external_calls: list[dict[str, Any]], timeout: int = 7) -> dict[str, Any]:
    external_calls.append({
        "service": server, "protocol": "WHOIS/TCP 43", "transmitted_data": query,
        "purpose": "WHOIS-/Registry-/Registrar-Auskunft",
    })
    out: dict[str, Any] = {"server": server, "query": query, "captured_at": iso_now()}
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((query + "\r\n").encode("utf-8"))
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(map(len, chunks)) > 4_000_000:
                    break
        out["text"] = b"".join(chunks).decode("utf-8", "replace")
        out["ok"] = True
    except Exception as exc:
        out["ok"] = False
        out["error"] = safe_exception(exc)
    return out


def _normalize_whois_server(value: str | None) -> str | None:
    if not value:
        return None
    server = value.strip().strip("<>[](){}.,; ")
    server = re.sub(r"^(?:whois|rwhois)://", "", server, flags=re.I)
    server = server.split("/", 1)[0]
    if server.count(":") == 1:
        host, port = server.rsplit(":", 1)
        if port.isdigit():
            server = host
    server = server.strip().rstrip(".").lower()
    return server or None


def _whois_referrals(text: str, stage: str) -> list[str]:
    """Extract every WHOIS referral server from a response, preserving order."""
    if stage.startswith("iana"):
        patterns = (
            r"(?im)^refer:\s*(\S+)",
            r"(?im)^whois:\s*(\S+)",
        )
    else:
        patterns = (
            r"(?im)^Registrar WHOIS Server:\s*(\S+)",
            r"(?im)^Registry WHOIS Server:\s*(\S+)",
            r"(?im)^ReferralServer:\s*(?:whois://)?(\S+)",
            r"(?im)^Whois Server:\s*(\S+)",
            r"(?im)^refer:\s*(\S+)",
        )

    found: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text or ""):
            server = _normalize_whois_server(match.group(1))
            if server and server not in found:
                found.append(server)
    return found


def _whois_query_candidates(server: str, domain: str) -> list[str]:
    server = server.lower()
    if server in {"whois.verisign-grs.com", "whois.crsnic.net"}:
        # VeriSign's classic WHOIS accepts an explicit domain-search command.
        # "dom" is also what CentralOps currently uses successfully.
        return [f"dom {domain}", f"domain {domain}", f"={domain}", domain]
    return [domain]


def _looks_like_domain_whois(text: str, domain: str) -> bool:
    low = (text or "").lower()
    d = domain.lower()
    return (
        ("domain name:" in low and d in low)
        or "registry domain id:" in low
        or "registrar whois server:" in low
        or (f"domain: {d}" in low)
    )


def _query_domain_whois_server(server: str, domain: str, stage: str,
                               attempts: list[dict[str, Any]],
                               external_calls: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidates = _whois_query_candidates(server, domain)
    last: dict[str, Any] | None = None
    for query in candidates:
        rec = whois_query(server, query, external_calls)
        rec["stage"] = stage
        rec["query_variant"] = query
        attempts.append(rec)
        last = rec
        if rec.get("ok") and _looks_like_domain_whois(rec.get("text", ""), domain):
            return rec
        if len(candidates) == 1:
            return rec
    return last


def whois_bundle(domain: str, external_calls: list[dict[str, Any]],
                 max_referral_servers: int = 8) -> dict[str, Any]:
    """Follow WHOIS referrals until no new server is named.

    The limit is only a loop/abuse safeguard, not a normal hop limit.
    Typical gTLD flow is IANA -> registry -> registrar.
    """
    attempts: list[dict[str, Any]] = []
    queried_servers: list[str] = []
    seen_servers: set[str] = set()
    referral_queue: list[tuple[str, str, str]] = []

    def remember_server(server: str) -> None:
        if server not in seen_servers:
            seen_servers.add(server)
            queried_servers.append(server)

    def enqueue(server: str | None, stage: str, referred_by: str) -> None:
        normalized = _normalize_whois_server(server)
        if not normalized or normalized in seen_servers:
            return
        if any(item[0] == normalized for item in referral_queue):
            return
        referral_queue.append((normalized, stage, referred_by))

    # Start at IANA. Querying the full domain often works; if IANA does not
    # return a referral, fall back to the TLD itself.
    iana_server = "whois.iana.org"
    remember_server(iana_server)
    iana = whois_query(iana_server, domain, external_calls)
    iana["stage"] = "iana"
    attempts.append(iana)

    initial_referrals = _whois_referrals(iana.get("text", ""), "iana") if iana.get("ok") else []
    if not initial_referrals:
        tld = domain.rsplit(".", 1)[-1]
        iana_tld = whois_query(iana_server, tld, external_calls)
        iana_tld["stage"] = "iana-tld-fallback"
        attempts.append(iana_tld)
        if iana_tld.get("ok"):
            initial_referrals = _whois_referrals(iana_tld.get("text", ""), "iana-tld-fallback")

    for server in initial_referrals:
        enqueue(server, "registry", iana_server)

    followed = 0
    truncated = False

    while referral_queue:
        if followed >= max_referral_servers:
            truncated = True
            break

        server, stage, referred_by = referral_queue.pop(0)
        if server in seen_servers:
            continue

        remember_server(server)
        followed += 1
        rec = _query_domain_whois_server(server, domain, stage, attempts, external_calls)
        if not rec:
            continue

        rec["referred_by"] = referred_by
        referrals = _whois_referrals(rec.get("text", ""), stage) if rec.get("ok") else []
        rec["referrals_found"] = referrals

        # Every later referral is followed as well. The labels are descriptive
        # only; the traversal itself is generic and does not stop after Registrar.
        next_stage = "registrar" if stage == "registry" else f"referral-{followed + 1}"
        for target in referrals:
            enqueue(target, next_stage, server)

    return {
        "query": domain,
        "attempts": attempts,
        "queried_servers": queried_servers,
        "referral_limit": max_referral_servers,
        "referral_limit_reached": truncated,
    }

def cymru_asn(ip: str, external_calls: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"ip": ip, "source": "Team Cymru IP-to-ASN DNS"}
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        else:
            hexed = addr.exploded.replace(":", "")
            q = ".".join(reversed(hexed)) + ".origin6.asn.cymru.com"
        external_calls.append({
            "service": "Team Cymru IP-to-ASN", "protocol": "DNS/TXT", "transmitted_data": ip,
            "purpose": "Zuordnung IP zu ASN und Netzpräfix",
        })
        answers = _dns_resolver().resolve(q, "TXT", lifetime=6)
        raw = str(next(iter(answers))).strip('"')
        parts = [p.strip() for p in raw.split("|")]
        if len(parts) >= 5:
            out.update({"asn": parts[0], "prefix": parts[1], "country": parts[2], "registry": parts[3], "allocated": parts[4]})
            asn_q = f"AS{parts[0]}.asn.cymru.com"
            external_calls.append({
                "service": "Team Cymru IP-to-ASN", "protocol": "DNS/TXT", "transmitted_data": f"AS{parts[0]}",
                "purpose": "ASN-Beschreibung",
            })
            try:
                asn_ans = _dns_resolver().resolve(asn_q, "TXT", lifetime=6)
                asn_raw = str(next(iter(asn_ans))).strip('"')
                asn_parts = [p.strip() for p in asn_raw.split("|")]
                if len(asn_parts) >= 5:
                    out["description"] = asn_parts[-1]
            except Exception:
                pass
    except Exception as exc:
        out["error"] = safe_exception(exc)
    return out


def ip_enrich(ip: str, external_calls: list[dict[str, Any]]) -> dict[str, Any]:
    ptr = reverse_dns(ip, external_calls)
    geo = fetch_json(
        f"https://ipwho.is/{ip}", "ipwho.is", ip,
        "GeoIP- und Netzbetreiber-/Providerhinweise", external_calls,
    )
    rdap = fetch_json(
        f"https://rdap.org/ip/{ip}", "RDAP.org", ip,
        "RIR-/Netzbereichsinformationen zur IP", external_calls,
    )
    asn = cymru_asn(ip, external_calls)
    geo_data = geo.get("data") if isinstance(geo.get("data"), dict) else {}
    conn = geo_data.get("connection") if isinstance(geo_data.get("connection"), dict) else {}
    rdap_data = rdap.get("data") if isinstance(rdap.get("data"), dict) else {}
    provider = (
        conn.get("isp") or conn.get("org") or conn.get("domain") or
        rdap_data.get("name") or rdap_data.get("handle") or asn.get("description")
    )
    location = {
        "city": geo_data.get("city"), "region": geo_data.get("region"), "country": geo_data.get("country"),
        "latitude": geo_data.get("latitude"), "longitude": geo_data.get("longitude"),
    }
    return {
        "ip": ip, "reverse_dns": ptr, "hosting_network_candidate": provider,
        "geoip": location, "geoip_raw": geo, "rdap_raw": rdap, "asn": asn,
        "sources": {
            "reverse_dns": "DNS/PTR", "geoip": "ipwho.is", "network_rdap": "RDAP.org",
            "asn": "Team Cymru IP-to-ASN DNS",
        },
    }


def infer_dns_providers(ns_hosts: list[str]) -> list[str]:
    providers: list[str] = []
    for ns in ns_hosts:
        for pattern, provider in DNS_PROVIDER_PATTERNS:
            if pattern.search(ns):
                if provider not in providers:
                    providers.append(provider)
                break
    return providers


def rdap_events(data: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for event in data.get("events", []) or []:
        action = str(event.get("eventAction") or "").strip()
        date = str(event.get("eventDate") or "").strip()
        if action and date:
            out.setdefault(action, []).append(date)
    return out


def infer_mail_provider(mx_host: str) -> str | None:
    for pattern, provider in MAIL_PROVIDER_PATTERNS:
        if pattern.search(mx_host):
            return provider
    return None


def _location_text(geo: dict[str, Any]) -> str:
    return ", ".join(str(x) for x in (geo.get("city"), geo.get("region"), geo.get("country")) if x) or "nicht ermittelt"


def _registrar_from_whois(bundle: dict[str, Any]) -> str | None:
    for attempt in reversed(bundle.get("attempts", []) or []):
        text = attempt.get("text") or ""
        for pattern in (
            r"(?im)^Registrar:\s*(.+)$", r"(?im)^registrar-name:\s*(.+)$", r"(?im)^registrar name:\s*(.+)$"
        ):
            m = re.search(pattern, text)
            if m:
                return m.group(1).strip()
    return None


def analyze_domain(value: str, output_dir: Path, har_server_ips: list[str] | None = None) -> dict[str, Any]:
    host = hostname_from_value(value)
    domain = registrable_domain(host)
    output_dir = ensure_dir(output_dir)
    external_calls: list[dict[str, Any]] = []

    dns_data = query_dns(domain, external_calls)
    rdap = domain_rdap(domain, external_calls)
    whois = whois_bundle(domain, external_calls)

    rdap_selected = (rdap.get("selected") or {}).get("data") if rdap.get("selected") else {}
    if not isinstance(rdap_selected, dict):
        rdap_selected = {}
    registrar = parse_rdap_registrar(rdap_selected) or _registrar_from_whois(whois)
    registration_events = rdap_events(rdap_selected)
    ns_values = dns_data.get("records", {}).get("NS", {}).get("values", []) or []
    dns_provider_indicators = infer_dns_providers([str(x) for x in ns_values])

    # Web/server IPs: DNS plus optional serverIPAddress evidence from HAR.
    web_ips: list[str] = []
    for typ in ("A", "AAAA"):
        for ip in dns_data.get("records", {}).get(typ, {}).get("values", []) or []:
            if ip not in web_ips:
                web_ips.append(ip)
    for ip in har_server_ips or []:
        if ip and ip not in web_ips:
            web_ips.insert(0, ip)

    ip_cache: dict[str, dict[str, Any]] = {}
    for ip in web_ips:
        ip_cache[ip] = ip_enrich(ip, external_calls)

    mx_rows = sorted(
        dns_data.get("records", {}).get("MX", {}).get("values", []) or [],
        key=lambda x: int(x.get("priority", 99999)) if isinstance(x, dict) else 99999,
    )
    mx_analysis: list[dict[str, Any]] = []
    for mx in mx_rows:
        mx_host = str(mx.get("host") or "").rstrip(".").lower()
        ips = resolve_host_ips(mx_host, external_calls) if mx_host else []
        ip_details: list[dict[str, Any]] = []
        for ip in ips:
            if ip not in ip_cache:
                ip_cache[ip] = ip_enrich(ip, external_calls)
            ip_details.append(ip_cache[ip])
        provider_hint = infer_mail_provider(mx_host)
        mx_analysis.append({
            "priority": mx.get("priority"), "host": mx_host, "mail_service_provider_hint": provider_hint,
            "mail_service_provider_basis": "MX-Hostname-Indiz" if provider_hint else "nicht eindeutig am MX-Hostname erkennbar",
            "ips": ips, "ip_details": ip_details,
        })

    result = {
        "tool": APP_NAME, "tool_version": APP_VERSION, "repository": REPOSITORY_URL, "captured_at": iso_now(),
        "input": value, "host": host, "registered_domain": domain,
        "dns": dns_data, "rdap": rdap, "whois": whois, "registrar": registrar,
        "registration_events": registration_events, "dns_provider_indicators": dns_provider_indicators,
        "web_server_ips": web_ips,
        "web_server_ip_details": [ip_cache[ip] for ip in web_ips if ip in ip_cache],
        "mx_analysis": mx_analysis,
        "external_calls": external_calls,
        "disclaimer": DISCLAIMER,
    }

    write_json(output_dir / "domain_analysis.json", result)
    write_json(output_dir / "dns_records.json", dns_data)
    write_json(output_dir / "domain_rdap.json", rdap)
    # WHOIS raw text as one readable file.
    whois_lines: list[str] = []
    for i, attempt in enumerate(whois.get("attempts", []) or [], 1):
        stage = str(attempt.get("stage") or "whois").upper()
        whois_lines += [
            f"===== WHOIS {i} [{stage}]: {attempt.get('server')} / Query {attempt.get('query')} =====",
            attempt.get("text") or attempt.get("error") or "",
            "",
        ]
    write_text(output_dir / "domain_whois.txt", "\n".join(whois_lines))

    ip_rows: list[dict[str, Any]] = []
    for rec in result["web_server_ip_details"]:
        ip_rows.append({
            "role": "web", "host": host, "ip": rec.get("ip"), "reverse_dns": rec.get("reverse_dns"),
            "provider": rec.get("hosting_network_candidate"), "country": rec.get("geoip", {}).get("country"),
            "region": rec.get("geoip", {}).get("region"), "city": rec.get("geoip", {}).get("city"),
            "asn": rec.get("asn", {}).get("asn"), "asn_description": rec.get("asn", {}).get("description"),
        })
    for mx in mx_analysis:
        for rec in mx.get("ip_details", []):
            ip_rows.append({
                "role": "mx", "host": mx.get("host"), "ip": rec.get("ip"), "reverse_dns": rec.get("reverse_dns"),
                "provider": rec.get("hosting_network_candidate"), "country": rec.get("geoip", {}).get("country"),
                "region": rec.get("geoip", {}).get("region"), "city": rec.get("geoip", {}).get("city"),
                "asn": rec.get("asn", {}).get("asn"), "asn_description": rec.get("asn", {}).get("description"),
            })
    write_csv(output_dir / "ip_addresses.csv", ip_rows,
              ["role", "host", "ip", "reverse_dns", "provider", "country", "region", "city", "asn", "asn_description"])

    mx_csv: list[dict[str, Any]] = []
    for mx in mx_analysis:
        if not mx.get("ip_details"):
            mx_csv.append({
                "priority": mx.get("priority"), "mx_host": mx.get("host"),
                "mail_service_provider_hint": mx.get("mail_service_provider_hint"),
                "ip": "", "network_provider": "", "geoip_location": "",
            })
        for rec in mx.get("ip_details", []):
            mx_csv.append({
                "priority": mx.get("priority"), "mx_host": mx.get("host"),
                "mail_service_provider_hint": mx.get("mail_service_provider_hint"),
                "ip": rec.get("ip"), "network_provider": rec.get("hosting_network_candidate"),
                "geoip_location": _location_text(rec.get("geoip", {})),
            })
    write_csv(output_dir / "mx_servers.csv", mx_csv,
              ["priority", "mx_host", "mail_service_provider_hint", "ip", "network_provider", "geoip_location"])

    # Human-readable report.
    lines: list[str] = [
        f"{APP_NAME} – Domainanalyse", "=" * 72, "",
        f"Version: {APP_VERSION}", f"Projekt / Quellcode: {REPOSITORY_URL}", f"Erstellt: {result['captured_at']}",
        f"Eingabe: {value}", f"Host: {host}", f"Registrierbare Domain: {domain}", "",
        "REGISTRIERUNG / REGISTRAR", "-" * 72,
        f"Registrar: {registrar or 'nicht automatisiert ermittelt'}",
        f"RDAP-Quelle: {((rdap.get('selected') or {}).get('source_service') or 'keine erfolgreiche RDAP-Abfrage')}",
        f"RDAP-Status: {', '.join(str(x) for x in (rdap_selected.get('status') or [])) or '-'}",
        f"Registrierungsereignisse: {json.dumps(registration_events, ensure_ascii=False) if registration_events else '-'}",
        "WHOIS: ergänzende direkte Registry-/Registrar-Abfragen; Rohdaten siehe domain_whois.txt.", "",
        "DNS", "-" * 72,
        "Quelle: lokal/systemseitig konfigurierter DNS-Resolver.",
    ]
    for typ in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        vals = dns_data.get("records", {}).get(typ, {}).get("values", []) or []
        lines.append(f"{typ}: {json.dumps(vals, ensure_ascii=False) if vals else '-'}")
    lines.append(f"Nameserver-/DNS-Provider (Indiz): {', '.join(dns_provider_indicators) if dns_provider_indicators else 'nicht eindeutig aus NS-Hostnamen erkannt'}")

    lines += ["", "WEB-/SERVER-INFRASTRUKTUR", "-" * 72]
    if not result["web_server_ip_details"]:
        lines.append("Keine A-/AAAA-/HAR-Server-IP ermittelt.")
    for rec in result["web_server_ip_details"]:
        lines += [
            f"IP: {rec.get('ip')}",
            f"Reverse-DNS: {rec.get('reverse_dns') or '-'}",
            f"Netz-/Hosting-Provider (Indiz): {rec.get('hosting_network_candidate') or 'nicht ermittelt'}",
            f"ASN: {rec.get('asn', {}).get('asn') or '-'} | {rec.get('asn', {}).get('description') or '-'}",
            f"Vermuteter Standort (GeoIP): {_location_text(rec.get('geoip', {}))}",
            "Quellen: GeoIP/Provider ipwho.is; Netzbereich RDAP.org; ASN Team Cymru; PTR lokaler DNS-Resolver.",
            "Hinweis: GeoIP/Netzbetreiber belegen keinen physischen Serverstandort.", "",
        ]

    lines += ["MX / E-MAIL-INFRASTRUKTUR", "-" * 72,
              "Maildienst-Anbieter und Netz-/Hosting-Provider werden getrennt dargestellt."]
    if not mx_analysis:
        lines.append("Kein MX-Record ermittelt.")
    for mx in mx_analysis:
        lines += [
            "", f"MX Priorität {mx.get('priority')}: {mx.get('host')}",
            f"Vermuteter Maildienst-Anbieter: {mx.get('mail_service_provider_hint') or 'nicht eindeutig erkennbar'}",
            f"Grundlage Maildienst-Zuordnung: {mx.get('mail_service_provider_basis')}",
        ]
        if not mx.get("ip_details"):
            lines.append("IP-Auflösung: keine A-/AAAA-Adresse ermittelt.")
        for rec in mx.get("ip_details", []):
            lines += [
                f"  IP: {rec.get('ip')}",
                f"  Reverse-DNS: {rec.get('reverse_dns') or '-'}",
                f"  Netz-/Hosting-Provider (Indiz): {rec.get('hosting_network_candidate') or 'nicht ermittelt'}",
                f"  ASN: {rec.get('asn', {}).get('asn') or '-'} | {rec.get('asn', {}).get('description') or '-'}",
                f"  Vermuteter Mailserver-Standort (GeoIP): {_location_text(rec.get('geoip', {}))}",
                "  Quellen: DNS, ipwho.is, RDAP.org, Team Cymru.",
                "  Hinweis: GeoIP ist eine Standortindikation des IP-Netzes, kein Beweis für den physischen Mailserverstandort.",
            ]

    lines += ["", "DISCLAIMER", "-" * 72, DISCLAIMER]
    write_text(output_dir / "Domain_Analyse.txt", "\n".join(lines))

    # Transparency report for this standalone/full domain analysis.
    trans = {
        "tool": APP_NAME, "tool_version": APP_VERSION, "repository": REPOSITORY_URL, "created_at": iso_now(),
        "scope": "Domainanalyse", "external_communications_and_sources": external_calls,
        "note": "Es werden keine HARs, Screenshots oder Fallakten zu Analyse-Clouds hochgeladen; es gibt keine KI-Anbindung.",
    }
    write_json(output_dir / "EXTERNE_DIENSTE_UND_DATEN.json", trans)
    tlines = [f"{APP_NAME} – Externe Dienste und Datenquellen", "", f"Projekt / Quellcode: {REPOSITORY_URL}", "Keine KI-/Cloud-Analyse.", ""]
    for i, rec in enumerate(external_calls, 1):
        tlines += [
            f"{i}. {rec.get('service')}", f"   Protokoll: {rec.get('protocol')}",
            f"   Übertragen: {json.dumps(rec.get('transmitted_data'), ensure_ascii=False)}",
            f"   Zweck: {rec.get('purpose')}",
        ]
    write_text(output_dir / "EXTERNE_DIENSTE_UND_DATEN.txt", "\n".join(tlines))
    return result


def supplement_origin_ip(domain_dir: Path, ips: list[str], note: str = "") -> dict[str, Any]:
    domain_dir = domain_dir.resolve()
    original = domain_dir / "Domain_Analyse.txt"
    data_file = domain_dir / "domain_analysis.json"
    if not original.exists():
        raise FileNotFoundError("Domain_Analyse.txt wurde im gewählten Ordner nicht gefunden.")
    external_calls: list[dict[str, Any]] = []
    enriched: list[dict[str, Any]] = []
    for raw in ips:
        ip = str(ipaddress.ip_address(raw.strip()))
        enriched.append(ip_enrich(ip, external_calls))
    result = {"created_at": iso_now(), "manual_origin_ips": enriched, "source_note": note,
              "origin": "manuelle Angabe durch Nutzer/Auswerter", "external_calls": external_calls}
    write_json(domain_dir / "manual_origin_ips.json", result)

    supplement_lines = [
        f"{APP_NAME} – Manuelle Origin-/Server-IP-Ergänzung", "=" * 72, "", f"Projekt / Quellcode: {REPOSITORY_URL}",
        "Herkunft der IP: manuelle Angabe durch Nutzer/Auswerter",
        f"Quelle/Ermittlungsvermerk: {note or '(nicht angegeben)'}", "",
    ]
    for rec in enriched:
        supplement_lines += [
            f"IP: {rec.get('ip')}", f"Reverse-DNS: {rec.get('reverse_dns') or '-'}",
            f"Netz-/Hosting-Provider (Indiz): {rec.get('hosting_network_candidate') or '-'}",
            f"ASN: {rec.get('asn', {}).get('asn') or '-'} | {rec.get('asn', {}).get('description') or '-'}",
            f"Vermuteter Standort (GeoIP): {_location_text(rec.get('geoip', {}))}",
            "Quellen: ipwho.is, RDAP.org, Team Cymru, DNS/PTR.",
            "Hinweis: Diese IP wurde NICHT durch das Programm als Origin-IP ermittelt.", "",
        ]
    supplement_lines += ["DISCLAIMER", "-" * 72, DISCLAIMER]
    supplement = domain_dir / "Manuelle_Origin_IP_Ergaenzung.txt"
    write_text(supplement, "\n".join(supplement_lines))

    combined = domain_dir / "Domain_Analyse_mit_manueller_Origin_IP.txt"
    write_text(combined, original.read_text(encoding="utf-8") + "\n\n" + supplement.read_text(encoding="utf-8"))

    base_data: dict[str, Any] = {}
    if data_file.exists():
        try:
            base_data = json.loads(data_file.read_text(encoding="utf-8"))
        except Exception:
            base_data = {}
    combined_data = {"automatic_domain_analysis": base_data, "manual_origin_ip_supplement": result}
    write_json(domain_dir / "domain_analysis_mit_manueller_origin_ip.json", combined_data)

    transparency_file = domain_dir / "EXTERNE_DIENSTE_MANUELLE_ORIGIN_IP.json"
    write_json(transparency_file, {
        "created_at": iso_now(), "external_communications_and_sources": external_calls
    })

    # Die Origin-IP-Ergänzung ist ein nachträglicher, klar abgegrenzter Befund.
    # Sie erhält deshalb einen eigenen Hashsatz und verändert den ursprünglichen
    # SHA256SUMS-Bestand einer vollständigen Sicherung nicht.
    supplement_files = [
        domain_dir / "manual_origin_ips.json",
        supplement,
        combined,
        domain_dir / "domain_analysis_mit_manueller_origin_ip.json",
        transparency_file,
    ]
    hash_lines = [f"{sha256_file(path)}  {path.name}" for path in supplement_files if path.exists()]
    write_text(domain_dir / "MANUELLE_ERGAENZUNG_SHA256SUMS.txt", "\n".join(hash_lines))
    return result
