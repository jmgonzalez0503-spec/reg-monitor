#!/usr/bin/env python3
"""Regulatory and legislative monitor.

Checks a fixed list of public sources, records what is new since the last run,
and writes the results to docs/data/ for the website.

Rules this script follows:
  * It identifies itself honestly and does not pose as a browser.
  * It honors robots.txt on ordinary web pages. Official APIs and feeds are
    published for automated use and are called directly.
  * It never reports "nothing new" for a source it could not read. Every
    source ends each run as one of: new, none, failed, blocked, needs_key, manual.
"""
import datetime as dt
import hashlib
import io
import json
import os
import re
import sys
import time
from urllib import robotparser
from urllib.parse import urljoin, urlparse

import feedparser
import requests
from bs4 import BeautifulSoup

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "docs", "data")
CFG = json.load(open(os.path.join(ROOT, "sources.json"), encoding="utf-8"))
UA = "reg-monitor/1.0 (public regulatory monitoring; +https://github.com/jmgonzalez0503-spec/reg-monitor)"
TIMEOUT = 40
NOW = dt.datetime.now(dt.timezone.utc)
TODAY = NOW.strftime("%Y-%m-%d")

session = requests.Session()
session.headers.update({"User-Agent": UA, "Accept": "*/*"})
LOG = []


def redact(text):
    """Keep API keys and tokens out of logs and published status messages."""
    return re.sub(r"(?i)(api_key|token)=[^&\s'\")]+", r"\1=***", str(text))


def log(msg):
    msg = redact(msg)
    line = f"{dt.datetime.now(dt.timezone.utc).strftime('%H:%M:%S')} {msg}"
    LOG.append(line)
    print(line, flush=True)


class Blocked(Exception):
    """The site refused automated access."""


class NeedsKey(Exception):
    """The source needs an API key that is not configured."""


# ---------------------------------------------------------------- HTTP

_robots = {}


def robots_allows(url):
    host = "{0.scheme}://{0.netloc}".format(urlparse(url))
    if host not in _robots:
        rp = robotparser.RobotFileParser()
        try:
            r = session.get(host + "/robots.txt", timeout=20)
            if r.status_code in (401, 403):
                rp.parse(["User-agent: *", "Disallow: /"])
            elif r.status_code >= 400:
                rp.parse([])
            else:
                rp.parse(r.text.splitlines())
        except requests.RequestException:
            rp.parse([])
        _robots[host] = rp
    return _robots[host].can_fetch("reg-monitor", url)


def http_get(url, check_robots=False, **kw):
    if check_robots and not robots_allows(url):
        raise Blocked("robots.txt does not allow automated access to this page")
    r = session.get(url, timeout=TIMEOUT, **kw)
    if r.status_code in (401, 403, 406, 429):
        raise Blocked(f"site returned HTTP {r.status_code}")
    r.raise_for_status()
    return r


# ---------------------------------------------------------------- helpers

def kw_match(text, keywords):
    """Acronyms (all caps) match as whole words, case-sensitive. Phrases match case-insensitive."""
    if not keywords:
        return True
    low = text.lower()
    for k in keywords:
        if k.isupper() or (k[:-1].isupper() and k.endswith("s")):
            if re.search(r"\b" + re.escape(k) + r"\b", text):
                return True
        elif k.lower() in low:
            return True
    return False


def clean(s, n=300):
    s = re.sub(r"\s+", " ", BeautifulSoup(s or "", "html.parser").get_text(" ")).strip()
    return s[:n]


def item(id_, title, url, date=""):
    return {"id": str(id_), "title": clean(title), "url": url or "", "date": (date or "")[:10]}


# ---------------------------------------------------------------- fetchers

def f_federal_register(f, src):
    params = [("order", "newest"), ("per_page", "40")]
    for k, v in f["params"].items():
        params.append((k, v))
    r = http_get("https://www.federalregister.gov/api/v1/documents.json", params=params)
    out = []
    for d in r.json().get("results", []):
        t = d.get("type", "")
        out.append(item(d["document_number"], f"{d.get('title', '')} ({t})", d.get("html_url"), d.get("publication_date")))
    return out, len(out)


def f_rss(f, src):
    keywords = CFG["keywords"] if f.get("use_global_keywords") else f.get("keywords")
    out, raw, errors, ok = [], 0, [], 0
    for url in f["urls"]:
        try:
            r = http_get(url)
            d = feedparser.parse(r.content)
            if not d.entries:
                raise ValueError("feed had no entries")
            ok += 1
            for e in d.entries:
                raw += 1
                title = e.get("title", "")
                if not kw_match(title + " " + clean(e.get("summary", ""), 2000), keywords):
                    continue
                date = ""
                tp = e.get("published_parsed") or e.get("updated_parsed")
                if tp:
                    date = time.strftime("%Y-%m-%d", tp)
                out.append(item(e.get("id") or e.get("link"), title, e.get("link"), date))
        except Exception as ex:  # one bad feed must not sink the rest
            errors.append(redact(f"{urlparse(url).netloc}: {ex}"))
    if ok == 0:
        if errors and all("HTTP 4" in e or "robots" in e for e in errors):
            raise Blocked("; ".join(errors))
        raise RuntimeError("; ".join(errors) or "no feeds read")
    if errors:
        log(f"   partial: {'; '.join(errors)}")
    return out, raw


def f_html_links(f, src):
    r = http_get(f["url"], check_robots=True)
    soup = BeautifulSoup(r.text, "html.parser")
    if f.get("require_text") and not re.search(f["require_text"], soup.get_text(" ")):
        raise RuntimeError("page loaded but expected text was missing (page may need a browser to render)")
    rx = re.compile(f["link_regex"])
    seen, out = set(), []
    for a in soup.find_all("a", href=True):
        href = urljoin(f["url"], a["href"].strip())
        text = clean(a.get_text(" "))
        if not text or href.startswith(("mailto:", "javascript:")):
            continue
        if not (rx.search(href) or rx.search(text)):
            continue
        key = href.split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(item(key, text, href))
    return out, len(out)


def f_page_version(f, src):
    r = http_get(f["url"], check_robots=True)
    text = re.sub(r"\s+", " ", BeautifulSoup(r.text, "html.parser").get_text(" "))
    if len(text) < 200:
        raise RuntimeError("page returned almost no text (page may need a browser to render)")
    m = re.search(f["marker_regex"], text) if f.get("marker_regex") else None
    if m:
        marker = m.group(0).strip()
        return [item(f"{f['url']}|{marker.lower()}", f"{f['title']}: {marker}", f["url"], TODAY)], 1
    digest = hashlib.sha256(text.encode()).hexdigest()[:12]
    return [item(f"{f['url']}|{digest}", f"{f['title']}: page content changed", f["url"], TODAY)], 1


def _congress_key():
    return os.environ.get("CONGRESS_API_KEY") or "DEMO_KEY"


def f_congress_bill_actions(f, src):
    out = []
    for b in f["bills"]:
        url = f"https://api.congress.gov/v3/bill/{b['congress']}/{b['type']}/{b['number']}/actions"
        r = http_get(url, params={"format": "json", "limit": 50, "api_key": _congress_key()})
        for a in r.json().get("actions", []):
            text = a.get("text", "")
            aid = hashlib.sha256(f"{b['label']}|{a.get('actionDate')}|{text}".encode()).hexdigest()[:16]
            out.append(item(aid, f"{b['label']}: {text}", b["url"], a.get("actionDate")))
    return out, len(out)


def f_congress_crs(f, src):
    r = http_get("https://api.congress.gov/v3/crsreport", params={"format": "json", "limit": 100, "api_key": _congress_key()})
    reports = r.json().get("CRSReports", [])
    out = []
    for c in reports:
        title = c.get("title", "")
        if kw_match(title, f.get("keywords")):
            out.append(item(c.get("id"), f"{c.get('id', '')}: {title}", c.get("url"), c.get("publishDate") or c.get("updateDate")))
    return out, len(reports)


def f_sam_opportunities(f, src):
    key = os.environ.get("SAM_API_KEY")
    if not key:
        raise NeedsKey("SAM.gov API key is not configured")
    start = (NOW - dt.timedelta(days=30)).strftime("%m/%d/%Y")
    end = NOW.strftime("%m/%d/%Y")
    out, seen = [], set()
    for title in f["titles"]:
        r = http_get("https://api.sam.gov/opportunities/v2/search",
                     params={"api_key": key, "postedFrom": start, "postedTo": end, "title": title, "limit": 100})
        for o in r.json().get("opportunitiesData", []) or []:
            if o.get("noticeId") in seen:
                continue
            seen.add(o.get("noticeId"))
            out.append(item(o.get("noticeId"), f"{o.get('title', '')} ({o.get('fullParentPathName', '')})", o.get("uiLink"), o.get("postedDate")))
    return out, len(out)


def f_courtlistener(f, src):
    headers = {}
    if os.environ.get("COURTLISTENER_TOKEN"):
        headers["Authorization"] = "Token " + os.environ["COURTLISTENER_TOKEN"]
    r = http_get("https://www.courtlistener.com/api/rest/v4/search/",
                 params={"q": f["query"], "type": "o", "order_by": "dateFiled desc", "court": f["courts"]}, headers=headers)
    out = []
    for c in r.json().get("results", []):
        url = "https://www.courtlistener.com" + (c.get("absolute_url") or "")
        out.append(item(c.get("cluster_id") or url, f"{c.get('caseName', '')} ({c.get('court', '')})", url, c.get("dateFiled")))
    return out, len(out)


def f_pdf_reports(f, src):
    from pypdf import PdfReader
    out = []
    for rep in f["reports"]:
        r = http_get(rep["url"], check_robots=True)
        text = PdfReader(io.BytesIO(r.content)).pages[0].extract_text() or ""
        m = re.search(r"(?i)as of\s+([A-Za-z]+\s+\d{1,2},\s+\d{4}|\d{1,2}/\d{1,2}/\d{4})", text)
        if not m:
            raise RuntimeError(f"{rep['label']}: could not find the report date")
        asof = re.sub(r"\s+", " ", m.group(1))
        out.append(item(f"{rep['label']}|{asof}", f"{rep['label']} updated, as of {asof}", rep["url"], TODAY))
    return out, len(out)


FETCHERS = {
    "federal_register": f_federal_register, "rss": f_rss, "html_links": f_html_links,
    "page_version": f_page_version, "congress_bill_actions": f_congress_bill_actions,
    "congress_crs": f_congress_crs, "sam_opportunities": f_sam_opportunities,
    "courtlistener": f_courtlistener, "pdf_reports": f_pdf_reports,
}


# ---------------------------------------------------------------- run

def load(name, default):
    p = os.path.join(DATA, name)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return default


def save(name, obj):
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


def check_source(src):
    """Try each route in order. Returns (status, label, items, message)."""
    if src.get("manual") or not src["fetchers"]:
        return "manual", "", [], src.get("manual_note", "Checked manually.")
    errors, kinds = [], set()
    for f in src["fetchers"]:
        try:
            items, raw = FETCHERS[f["kind"]](f, src)
            min_items = f.get("min_items", 1)
            if len(items) < min_items or raw < f.get("min_raw", 0):
                raise RuntimeError(f"returned {len(items)} items; expected at least {max(min_items, 1)}")
            log(f"   ok via {f['label']}: {len(items)} items")
            note = "; ".join(errors)
            return "ok", f["label"], items, (f"Primary route failed, backup used. {note}" if errors else "")
        except Blocked as ex:
            kinds.add("blocked"); errors.append(redact(f"{f['label']}: {ex}"))
        except NeedsKey as ex:
            kinds.add("needs_key"); errors.append(f"{f['label']}: {ex}")
        except Exception as ex:
            kinds.add("failed"); errors.append(redact(f"{f['label']}: {type(ex).__name__}: {str(ex)[:200]}"))
        log(f"   route failed: {errors[-1]}")
    status = "failed" if "failed" in kinds else ("blocked" if "blocked" in kinds else "needs_key")
    return status, "", [], " | ".join(errors)


def main():
    only = None
    if "--source" in sys.argv:
        only = int(sys.argv[sys.argv.index("--source") + 1])
    state = load("state.json", {"seen": {}, "baselined": {}, "fail_streak": {}, "last_success": {}})
    findings = load("findings.json", [])
    prev_status = {s["id"]: s for s in load("status.json", {}).get("sources", [])}
    known = {(f["source_id"], f["id"]) for f in findings}
    rows, new_total = [], 0

    for src in CFG["sources"]:
        sid = str(src["id"])
        if only and src["id"] != only:
            if src["id"] in prev_status:
                rows.append(prev_status[src["id"]])
            continue
        log(f"Source {sid}: {src['name']}")
        status, label, items, message = check_source(src)
        new_count = 0
        if status == "ok":
            seen = set(state["seen"].get(sid, []))
            baselined = state["baselined"].setdefault(sid, [])
            first_time = label not in baselined
            for it in items:
                if it["id"] in seen:
                    continue
                seen.add(it["id"])
                if (src["id"], it["id"]) in known:
                    continue
                findings.append({"source_id": src["id"], "source": src["name"], "type": src["type"], "id": it["id"],
                                 "title": it["title"], "url": it["url"], "date": it["date"],
                                 "first_seen": TODAY, "baseline": first_time})
                if not first_time:
                    new_count += 1
            if first_time:
                baselined.append(label)
                message = (message + " " if message else "") + "First successful read by this route; existing items recorded as the baseline."
            state["seen"][sid] = sorted(seen)[-4000:]
            state["fail_streak"][sid] = 0
            state["last_success"][sid] = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
            status = "new" if new_count else "none"
        elif status in ("failed", "blocked"):
            state["fail_streak"][sid] = state["fail_streak"].get(sid, 0) + 1
        new_total += new_count
        rows.append({"id": src["id"], "name": src["name"], "type": src["type"], "cadence": src["cadence"],
                     "covers": src["covers"], "url": src["url"], "status": status, "route": label,
                     "items_read": len(items), "new_count": new_count, "message": message,
                     "manual_note": src.get("manual_note", ""),
                     "last_success": state["last_success"].get(sid, ""), "fail_streak": state["fail_streak"].get(sid, 0),
                     "checked_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ")})

    findings.sort(key=lambda x: (x["first_seen"], x.get("date", "")), reverse=True)
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    save("state.json", state)
    save("findings.json", findings[:6000])
    save("status.json", {"generated_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "new_total": new_total,
                         "counts": counts, "sources": rows})
    log(f"Done. {new_total} new items. Status counts: {counts}")
    with open(os.path.join(DATA, "last_run.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(LOG) + "\n")
    repeated = [r["name"] for r in rows if r["status"] in ("failed", "blocked") and r["fail_streak"] >= 2]
    if repeated:
        print("Sources unreadable on two or more runs in a row: " + "; ".join(repeated))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
