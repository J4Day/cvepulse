#!/usr/bin/env python3
"""
CVE//PULSE aggregator
Тянет источники из sources.yml, нормализует в единый формат,
дедуплицирует, сортирует и пишет docs/feed.json.
Запускается из GitHub Actions по cron. Без сервера, без БД.
"""

import json
import hashlib
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
import requests
import feedparser

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "docs" / "feed.json"
SOURCES = ROOT / "sources.yml"
MAX_ITEMS = 250            # сколько храним в ленте
USER_AGENT = "CVEPulse/1.0 (+personal feed aggregator)"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()   # опционально, ускоряет лимиты

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "": 0}

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


def log(*a):
    print("[cvepulse]", *a, file=sys.stderr)


def uid(*parts) -> str:
    """Стабильный id для дедупликации."""
    return hashlib.sha1("::".join(p.lower() for p in parts if p).encode()).hexdigest()[:16]


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def clean(text: str, limit: int = 240) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)          # выкинуть html-теги
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit].rstrip() + ("…" if len(text) > limit else "")


# ---------------------------------------------------------------- CISA KEV
def fetch_cisa_kev(src) -> list[dict]:
    items = []
    try:
        r = session.get(src["url"], timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log(f"CISA KEV failed: {e}")
        return items

    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "")
        added = v.get("dateAdded", "")
        try:
            dt = datetime.fromisoformat(added).replace(tzinfo=timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
        items.append({
            "id": uid(cve, "kev"),
            "kind": "cve",
            "cve": cve,
            "title": v.get("vulnerabilityName", cve),
            "summary": clean(v.get("shortDescription", "")),
            "severity": "CRITICAL",          # KEV = эксплуатируется в дикой природе
            "score": None,
            "source": src["name"],
            "tags": ["KEV"] + (["RANSOMWARE"] if ransomware == "Known" else []),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "published": iso(dt),
        })
    log(f"CISA KEV: {len(items)} items")
    return items


# ---------------------------------------------------------------- NVD API 2.0
def fetch_nvd(src) -> list[dict]:
    items = []
    days = src.get("lookback_days", 3)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": 200,
    }
    sev = src.get("min_severity", "HIGH").upper()
    # NVD фильтрует по конкретной severity; собираем нужные ступени
    wanted = [s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
              if SEV_ORDER[s] >= SEV_ORDER.get(sev, 3)]

    for level in wanted:
        p = dict(params, cvssV3Severity=level)
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        try:
            r = session.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params=p, headers=headers, timeout=40)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            log(f"NVD ({level}) failed: {e}")
            continue

        for entry in data.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            cid = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score, severity = None, level
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if key in metrics and metrics[key]:
                    cd = metrics[key][0]["cvssData"]
                    score = cd.get("baseScore")
                    severity = cd.get("baseSeverity", level)
                    break
            pub = cve.get("published", "")
            try:
                dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            except Exception:
                dt = datetime.now(timezone.utc)
            items.append({
                "id": uid(cid, "nvd"),
                "kind": "cve",
                "cve": cid,
                "title": cid,
                "summary": clean(desc),
                "severity": severity.upper(),
                "score": score,
                "source": src["name"],
                "tags": ["NVD"],
                "vendor": "",
                "product": "",
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                "published": iso(dt),
            })
        time.sleep(1)   # вежливость к rate-limit (без ключа ~5 req / 30s)
    log(f"NVD: {len(items)} items")
    return items


# ---------------------------------------------------------------- RSS / Atom
def fetch_rss(src) -> list[dict]:
    items = []
    try:
        # сами качаем — feedparser иногда душат без UA
        r = session.get(src["url"], timeout=30)
        r.raise_for_status()
        parsed = feedparser.parse(r.content)
    except Exception as e:
        log(f"RSS {src['name']} failed: {e}")
        return items

    for e in parsed.entries[:40]:
        link = e.get("link", "")
        title = clean(e.get("title", ""), 180)
        summary = clean(e.get("summary", e.get("description", "")))
        dt = datetime.now(timezone.utc)
        for field in ("published_parsed", "updated_parsed"):
            if e.get(field):
                dt = datetime(*e[field][:6], tzinfo=timezone.utc)
                break
        # вытащить CVE-id из заголовка/текста, если есть
        m = re.search(r"CVE-\d{4}-\d{4,7}", (title + " " + summary), re.I)
        items.append({
            "id": uid(link or title),
            "kind": "research",
            "cve": m.group(0).upper() if m else None,
            "title": title,
            "summary": summary,
            "severity": "",
            "score": None,
            "source": src["name"],
            "tags": [src.get("tag", "NEWS")],
            "vendor": "",
            "product": "",
            "url": link,
            "published": iso(dt),
        })
    log(f"RSS {src['name']}: {len(items)} items")
    return items


# ---------------------------------------------------------------- Google News proxy
def fetch_gnews(src) -> list[dict]:
    """Для сайтов, которые блокируют прямой доступ к RSS (Cloudflare и т.п.)
       либо вообще не отдают фид. Тянем их публикации через Google News RSS."""
    domain = src["domain"]
    q = f"https://news.google.com/rss/search?q=site:{domain}&hl=en-US&gl=US&ceid=US:en"
    items = []
    try:
        r = session.get(q, timeout=30)
        r.raise_for_status()
        parsed = feedparser.parse(r.content)
    except Exception as e:
        log(f"gnews {src['name']} failed: {e}")
        return items

    for e in parsed.entries[:25]:
        title = clean(e.get("title", ""), 180)
        # Google News добавляет " - SourceName" в хвост — отрезаем
        title = re.sub(r"\s+-\s+[^-]+$", "", title).strip()
        link = e.get("link", "")
        dt = datetime.now(timezone.utc)
        if e.get("published_parsed"):
            dt = datetime(*e["published_parsed"][:6], tzinfo=timezone.utc)
        m = re.search(r"CVE-\d{4}-\d{4,7}", title, re.I)
        items.append({
            "id": uid(link or title),
            "kind": "research",
            "cve": m.group(0).upper() if m else None,
            "title": title,
            "summary": "",
            "severity": "",
            "score": None,
            "source": src["name"],
            "tags": [src.get("tag", "RESEARCH")],
            "vendor": "", "product": "",
            "url": link,
            "published": iso(dt),
        })
    log(f"gnews {src['name']}: {len(items)} items")
    return items


# ---------------------------------------------------------------- main
def main():
    cfg = yaml.safe_load(SOURCES.read_text(encoding="utf-8"))
    all_items: list[dict] = []

    for src in cfg.get("structured", []) + cfg.get("research", []):
        t = src.get("type")
        if t == "cisa_kev":
            all_items += fetch_cisa_kev(src)
        elif t == "nvd":
            all_items += fetch_nvd(src)
        elif t == "rss":
            all_items += fetch_rss(src)
        elif t == "gnews":
            all_items += fetch_gnews(src)
        else:
            log(f"unknown source type: {t}")

    # дедуп по id (KEV побеждает NVD для одного CVE, т.к. идёт первым)
    seen, deduped = set(), []
    for it in all_items:
        if it["id"] in seen:
            continue
        seen.add(it["id"])
        deduped.append(it)

    # сортировка: сначала по дате (свежее выше), CVE с severity подтягиваем
    deduped.sort(key=lambda x: x["published"], reverse=True)

    feed = {
        "generated": iso(datetime.now(timezone.utc)),
        "count": len(deduped[:MAX_ITEMS]),
        "items": deduped[:MAX_ITEMS],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(feed, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"wrote {OUT} — {feed['count']} items total")


if __name__ == "__main__":
    main()
