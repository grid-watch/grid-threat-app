#!/usr/bin/env python3
"""Rule-based daily updater for the Sydney Grid Threat Rating app.

No AI. Pulls public feeds, matches fixed keyword rules, picks a level
(green / yellow / orange / red) and writes data/status.json and
data/history.json for the app to read.

Sources
- ASD's ACSC alerts and advisories (RSS)
- AEMO market notices (NEMWEB text files)
- Google News RSS searches (headlines only)

Edit RULES / NEWS_QUERIES below to tune it.
"""
import datetime as dt
import email.utils
import html
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
SYD = dt.timezone(dt.timedelta(hours=10))  # AEST; good enough for dating reports
UA = "GridThreatRating/1.0 (+github pages household dashboard)"
LOOKBACK_HOURS = 48
HISTORY_DAYS = 120

LEVELS = ["green", "yellow", "orange", "red"]
ACTIONS = {
    "green": "No material change. Keep supplies rotated.",
    "yellow": "Strategic warning sign. Top up and rotate water, food and batteries.",
    "orange": "Operational warning sign. Fill water, charge everything, fuel the car, get cash.",
    "red": "Possible widespread outage. Switch to the household plan; tune to ABC Radio Sydney 702 AM.",
}

ACSC_FEEDS = [
    ("ACSC alert", "https://www.cyber.gov.au/rss/alerts"),
    ("ACSC advisory", "https://www.cyber.gov.au/rss/advisories"),
]
NEMWEB_DIR = "https://nemweb.com.au/Reports/Current/Market_Notice/"

# (label, google news query). when:2d limits to the last 2 days.
NEWS_QUERIES = [
    ("au-grid-cyber", '(cyberattack OR "cyber attack" OR hackers) (Ausgrid OR Transgrid OR "Endeavour Energy" OR AEMO OR "NSW grid" OR "Australian grid" OR "power grid") Australia when:2d'),
    ("taiwan", 'Taiwan (blockade OR quarantine OR encircle OR invasion OR "live-fire" OR "live fire") China when:2d'),
    ("volt-typhoon", '("Volt Typhoon" OR "Salt Typhoon") Australia when:2d'),
    ("allied-grid", '("power grid" OR blackout OR "electric grid") (cyberattack OR "cyber attack" OR hackers) when:2d'),
    ("sydney-blackout", '(Sydney OR NSW) (blackout OR "power outage") (widespread OR statewide OR "hundreds of thousands") when:2d'),
]

# ---------------------------------------------------------------- rules
def any_re(*words):
    return re.compile(r"\b(" + "|".join(words) + r")", re.I)

CI = any_re("critical infrastructure", "energy", "electric", "power grid", "utilit", "operational technology",
            r"\bOT\b", "ICS", "SCADA", "water")
SEVERE = any_re("actively exploit", "active exploitation", "state-sponsored", "state sponsored", "PRC", "China",
                "Russia", "urgent", "pre-position", "Volt Typhoon", "destructive", "wiper")
AU_GRID = any_re("Ausgrid", "Transgrid", "TransGrid", "Endeavour Energy", "Essential Energy", "AEMO",
                 "NSW grid", "NSW power", "Australian grid", "Australia's grid", "Australian energy")
ATTACK = any_re("cyberattack", "cyber attack", "cyber-attack", "hack", "ransomware", "breach", "intrusion")
TAIWAN_ESC = any_re("blockade", "quarantine", "encircle", "invasion", "live-fire", "live fire", "exercise", "drill")
ALLIED = any_re("United States", r"\bUS\b", "U\\.S\\.", "Guam", "Japan", "Philippines", "Poland", "Europe",
                "Germany", r"\bUK\b", "Britain", "Canada", "New Zealand", "Taiwan")
GRID = any_re("power grid", "electric grid", "electricity grid", "blackout", "substation", "power plant", "utility")
NOT_ATTACK = any_re("data breach", "customer data", "personal information", "phishing scam")
PAST = any_re("anniversary", "years ago", "lessons from", "retrospective")
NSW = any_re("NSW", "New South Wales")


def rule_hits(item):
    """Return list of (level, reason) for one item."""
    src, title, text = item["source"], item["title"], item.get("text", "")
    blob = f"{title} {text}"
    hits = []
    if src.startswith("AEMO"):
        if NSW.search(blob) and re.search(r"black system|system black", blob, re.I):
            hits.append(("red", "AEMO notice: black system in NSW"))
        elif NSW.search(blob) and re.search(r"load shedding|actual lor3|lor3", blob, re.I) and re.search(r"actual", blob, re.I):
            hits.append(("orange", "AEMO notice: actual LOR3 / load shedding in NSW (grid emergency)"))
        elif NSW.search(blob) and re.search(r"actual lor2|actual lack of reserve level 2", blob, re.I):
            hits.append(("yellow", "AEMO notice: actual LOR2 (tight supply) in NSW"))
        elif NSW.search(blob) and re.search(r"cyber", blob, re.I):
            hits.append(("orange", "AEMO notice mentions cyber in NSW"))
        return hits
    if src.startswith("ACSC"):
        if CI.search(blob) and SEVERE.search(blob):
            hits.append(("orange" if re.search(r"australia", blob, re.I) and re.search(r"actively exploit|active exploitation|compromis", blob, re.I) else "yellow",
                         f"{src} on critical infrastructure"))
        elif CI.search(blob):
            hits.append(("yellow", f"{src} mentions critical infrastructure"))
        return hits
    # news
    if PAST.search(blob):
        return hits
    if AU_GRID.search(blob) and ATTACK.search(blob) and not NOT_ATTACK.search(blob):
        hits.append(("orange", "News: cyber attack reported on Australian grid company"))
    elif AU_GRID.search(blob) and ATTACK.search(blob):
        hits.append(("yellow", "News: data breach at an Australian energy company"))
    if re.search(r"Taiwan", blob) and TAIWAN_ESC.search(blob):
        hits.append(("yellow", "News: Taiwan Strait escalation or major exercise"))
    if re.search(r"Volt Typhoon|Salt Typhoon", blob) and re.search(r"Australia", blob):
        hits.append(("yellow", "News: Chinese state hackers and Australia"))
    if GRID.search(blob) and re.search(r"cyber|hack", blob, re.I) and ALLIED.search(blob) and re.search(r"blackout|outage|disrupt|cut power", blob, re.I):
        hits.append(("yellow", "News: cyber disruption of a grid in an allied country"))
    if NSW.search(blob) or re.search(r"Sydney", blob):
        if re.search(r"blackout|power outage", blob, re.I) and re.search(r"widespread|statewide|state-wide|hundreds of thousands|million", blob, re.I):
            hits.append(("orange", "News: widespread outage reported in Sydney/NSW"))
    return hits


# ---------------------------------------------------------------- fetching
def get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def strip_tags(s):
    return html.unescape(re.sub(r"<[^>]+>", " ", s or "")).strip()


def parse_date(s):
    if not s:
        return None
    try:
        d = email.utils.parsedate_to_datetime(s)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y/%m/%d %H:%M:%S"):
        try:
            d = dt.datetime.strptime(s.strip(), fmt)
            return d if d.tzinfo else d.replace(tzinfo=SYD)
        except Exception:
            continue
    return None


def parse_rss(raw, source):
    items = []
    root = ET.fromstring(raw)
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for it in root.iter("item"):
        items.append({
            "source": source,
            "title": strip_tags(it.findtext("title")),
            "text": strip_tags(it.findtext("description"))[:600],
            "url": (it.findtext("link") or "").strip(),
            "date": parse_date(it.findtext("pubDate")),
            "publisher": strip_tags(it.findtext("source")) or None,
        })
    for it in root.findall("a:entry", ns):
        link = it.find("a:link", ns)
        items.append({
            "source": source,
            "title": strip_tags(it.findtext("a:title", namespaces=ns)),
            "text": strip_tags(it.findtext("a:summary", namespaces=ns))[:600],
            "url": link.get("href") if link is not None else "",
            "date": parse_date(it.findtext("a:updated", namespaces=ns)),
            "publisher": None,
        })
    return items


def fetch_acsc(errors):
    out = []
    for name, url in ACSC_FEEDS:
        try:
            out += parse_rss(get(url), name)
        except Exception as e:
            errors.append(f"{name}: {e.__class__.__name__}")
    return out


def fetch_news(errors):
    out = []
    for label, q in NEWS_QUERIES:
        url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
            {"q": q, "hl": "en-AU", "gl": "AU", "ceid": "AU:en"})
        try:
            items = parse_rss(get(url), "News")
            for i in items:
                i["query"] = label
            out += items[:15]
        except Exception as e:
            errors.append(f"News ({label}): {e.__class__.__name__}")
    return out


def fetch_aemo(errors, max_files=60):
    out = []
    try:
        listing = get(NEMWEB_DIR).decode("utf-8", "replace")
    except Exception as e:
        errors.append(f"AEMO notices: {e.__class__.__name__}")
        return out
    files = re.findall(r'href="([^"]*MKTNOTICE[^"]*)"', listing, re.I)
    files = sorted(set(files), key=lambda f: int(re.search(r"(\d+)$", f).group(1)) if re.search(r"(\d+)$", f) else 0)
    for f in files[-max_files:]:
        url = urllib.parse.urljoin(NEMWEB_DIR, f)
        try:
            txt = get(url, timeout=15).decode("utf-8", "replace")
        except Exception:
            continue
        def field(name):
            m = re.search(name + r"\s*:\s*(.+)", txt, re.I)
            return m.group(1).strip() if m else ""
        title = field("External Reference") or field("Notice Type Description") or "AEMO market notice"
        ntype = field("Notice Type ID")
        reason = re.split(r"Reason\s*:", txt, flags=re.I)
        body = reason[1] if len(reason) > 1 else txt
        out.append({
            "source": "AEMO notice",
            "title": f"{title}" + (f" [{ntype}]" if ntype else ""),
            "text": re.sub(r"\s+", " ", body)[:600],
            "url": url,
            "date": parse_date(field("Issue Date")),
            "publisher": "AEMO",
        })
    return out


# ---------------------------------------------------------------- main
def main():
    now = dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(hours=LOOKBACK_HOURS)
    errors = []
    items = fetch_acsc(errors) + fetch_aemo(errors) + fetch_news(errors)

    recent = [i for i in items if i["date"] is None or i["date"] >= since]
    # ACSC: only consider items from the last 7 days (feeds post rarely)
    recent = [i for i in recent if not (i["source"].startswith("ACSC") and i["date"] and i["date"] < now - dt.timedelta(days=7))]

    scored, seen = [], set()
    for i in recent:
        key = re.sub(r"\W+", "", i["title"].lower())[:80]
        if not key or key in seen:
            continue
        seen.add(key)
        hits = rule_hits(i)
        if hits:
            lvl = max((h[0] for h in hits), key=LEVELS.index)
            scored.append((lvl, hits, i))

    level = "green"
    for lvl, _, _ in scored:
        if LEVELS.index(lvl) > LEVELS.index(level):
            level = lvl
    # dampen: a single news headline alone can't push above yellow
    if level in ("orange",) and sum(1 for l, h, i in scored if l == "orange") == 1:
        only = [i for l, h, i in scored if l == "orange"][0]
        if only["source"] == "News":
            level = "yellow"

    scored.sort(key=lambda s: (-LEVELS.index(s[0]), -(s[2]["date"].timestamp() if s[2]["date"] else 0)))
    out_items = []
    for lvl, hits, i in scored[:8]:
        out_items.append({
            "text": i["title"],
            "source": i.get("publisher") or i["source"],
            "url": i["url"] if i["url"].startswith("http") else "",
            "level": lvl,
            "why": hits[0][1],
        })

    reasons = sorted({h[1] for l, hs, i in scored for h in hs if l == level})
    today = now.astimezone(SYD).date().isoformat()
    headline = reasons[0] if reasons else "Nothing notable noticed or released."

    hist_path = os.path.join(DATA, "history.json")
    try:
        with open(hist_path) as f:
            history = json.load(f)
    except Exception:
        history = []
    if not items:
        if any(r.get("id") == today for r in history):
            print("No sources reachable; keeping today's existing report.")
            return 0
        prev = history[0] if history else None
        level = prev["level"] if prev else "green"
        headline = "Sources couldn't be reached on this check; showing the last known rating."
    report = {
        "id": today,
        "date": today,
        "level": level,
        "headline": headline,
        "items": out_items,
        "action": ACTIONS[level],
        "checkedAt": now.isoformat(timespec="minutes"),
        "sourcesChecked": len(items),
        "sourceErrors": errors,
        "auto": True,
    }

    os.makedirs(DATA, exist_ok=True)
    history = [r for r in history if r.get("id") != today]
    history.insert(0, report)
    history = sorted(history, key=lambda r: r.get("date", ""), reverse=True)[:HISTORY_DAYS]
    with open(hist_path, "w") as f:
        json.dump(history, f, indent=1)
    with open(os.path.join(DATA, "status.json"), "w") as f:
        json.dump(report, f, indent=1)
    print(f"{today}: {level.upper()} from {len(items)} items, {len(scored)} matched; errors: {errors}")


if __name__ == "__main__":
    sys.exit(main())
