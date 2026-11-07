#!/usr/bin/env python3
"""Rule-based daily updater for the Grid Threat Rating app (worldwide).

No AI. For each country it reads that country's equivalent sources where
they exist:
  - the national cyber agency / CERT alert feed (RSS/Atom)
  - a local-language Google News search in that country's edition
  - for Australia, AEMO electricity market notices (per state)
It then applies fixed keyword rules, rates each country (and Australian
state) green / yellow / orange / red, and writes data/history.json and
data/status.json for the app.

Tune COUNTRIES, AGENCY_FEEDS, NEWS_EDITIONS or the rules below.
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
UA = "GridThreatRating/2.0 (+github pages household dashboard)"
LOOKBACK_HOURS = 48
AGENCY_LOOKBACK_DAYS = 7
HISTORY_DAYS = 120
LEVELS = ["green", "yellow", "orange", "red"]

ACTIONS = {
    "green": "No material change. Keep supplies rotated.",
    "yellow": "Strategic warning sign. Top up and rotate water, food and batteries.",
    "orange": "Operational warning sign. Fill water, charge everything, fuel the car, get cash.",
    "red": "Possible widespread outage. Switch to your household plan and tune to your local emergency broadcaster.",
}

EU = ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT",
      "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"]
INDO_PACIFIC = ["AU", "US", "JP", "TW", "PH", "KR", "NZ"]

# Country names, demonyms and major cities (English + local language) used to tag items.
COUNTRIES = {
    "AU": ["Australia", "Australian", "Sydney", "Melbourne", "Brisbane", "Perth", "Adelaide", "Canberra", "Hobart", "Darwin"],
    "NZ": ["New Zealand", "Auckland", "Wellington", "Christchurch"],
    "US": ["United States", r"\bU\.S\.", r"\bUSA\b", "American", "Texas", "California", "New York", r"Washington, D\.C\.", "Guam"],
    "CA": ["Canada", "Canadian", "Toronto", "Montreal", "Vancouver", "Ottawa"],
    "GB": ["United Kingdom", r"\bUK\b", "Britain", "British", "England", "Scotland", "Wales", "London"],
    "IE": ["Ireland", "Irish", "Dublin"],
    "FR": ["France", "French", "Paris", "Français", "française"],
    "DE": ["Germany", "German", "Deutschland", "deutsche", "Berlin", "München", "Munich", "Hamburg"],
    "AT": ["Austria", "Österreich", "Vienna", "Wien"],
    "CH": ["Switzerland", "Schweiz", "Suisse", "Zurich", "Zürich", "Geneva", "Genève"],
    "NL": ["Netherlands", "Dutch", "Nederland", "Amsterdam", "Rotterdam"],
    "BE": ["Belgium", "Belgian", "België", "Belgique", "Brussels", "Bruxelles"],
    "ES": ["Spain", "Spanish", "España", "Madrid", "Barcelona"],
    "PT": ["Portugal", "Portuguese", "Lisbon", "Lisboa"],
    "IT": ["Italy", "Italian", "Italia", "Rome", "Roma", "Milan", "Milano"],
    "PL": ["Poland", "Polish", "Polska", "Warsaw", "Warszawa"],
    "UA": ["Ukraine", "Ukrainian", "Україна", "Україн", "Kyiv", "Київ"],
    "SE": ["Sweden", "Swedish", "Sverige", "Stockholm"],
    "NO": ["Norway", "Norwegian", "Norge", "Oslo"],
    "FI": ["Finland", "Finnish", "Suomi", "Helsinki"],
    "DK": ["Denmark", "Danish", "Danmark", "Copenhagen", "København"],
    "EE": ["Estonia", "Estonian", "Tallinn"],
    "LT": ["Lithuania", "Lithuanian", "Vilnius"],
    "LV": ["Latvia", "Latvian", "Riga"],
    "CZ": ["Czech", "Czechia", "Prague", "Praha"],
    "RO": ["Romania", "Romanian", "Bucharest"],
    "GR": ["Greece", "Greek", "Athens"],
    "JP": ["Japan", "Japanese", "Tokyo", "Osaka", "日本", "東京"],
    "KR": ["South Korea", "Korean", "Seoul", "한국", "서울"],
    "TW": ["Taiwan", "Taiwanese", "Taipei", "台灣", "臺灣", "台北"],
    "PH": ["Philippines", "Philippine", "Filipino", "Manila"],
    "SG": ["Singapore"],
    "IN": ["India", "Indian", "Delhi", "Mumbai", "Bengaluru"],
    "IL": ["Israel", "Israeli", "Tel Aviv", "Jerusalem", "ישראל"],
    "ZA": ["South Africa", "Johannesburg", "Cape Town", "Eskom"],
    "BR": ["Brazil", "Brasil", "Brazilian", "São Paulo", "Rio de Janeiro"],
    "MX": ["Mexico", "México", "Mexican", "Mexico City"],
    "AR": ["Argentina", "Buenos Aires"],
    "CL": ["Chile", "Santiago"],
}

# National cyber agency / CERT feeds (verified addresses). "EU" applies to all EU members.
AGENCY_FEEDS = [
    ("AU", "ASD's ACSC alerts", "https://www.cyber.gov.au/rss/alerts"),
    ("AU", "ASD's ACSC advisories", "https://www.cyber.gov.au/rss/advisories"),
    ("US", "CISA advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("US", "CISA ICS advisories", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"),
    ("GB", "UK NCSC", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"),
    ("CA", "Canadian Centre for Cyber Security", "https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en"),
    ("EU", "CERT-EU", "https://cert.europa.eu/publications/security-advisories-rss"),
    ("FR", "CERT-FR alertes", "https://www.cert.ssi.gouv.fr/alerte/feed/"),
    ("FR", "CERT-FR SCADA", "https://www.cert.ssi.gouv.fr/feed/scada/"),
    ("NL", "NCSC-NL", "https://advisories.ncsc.nl/rss/advisories"),
    ("ES", "INCIBE-CERT avisos", "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed"),
    ("ES", "INCIBE-CERT avisos SCI", "https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/feed"),
    ("JP", "JPCERT/CC", "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf"),
    ("UA", "CERT-UA", "https://cert.gov.ua/api/articles/rss"),
    ("PL", "CERT Polska", "https://cert.pl/en/atom.xml"),
    ("FI", "NCSC-FI", "https://www.kyberturvallisuuskeskus.fi/feed/rss/fi/399"),
]

EN_Q = '("power grid" OR "electric grid" OR blackout OR "power outage" OR substation OR utility) (cyberattack OR "cyber attack" OR hackers OR ransomware) when:2d'
# (country, hl, gl, ceid, query in the local language)
NEWS_EDITIONS = [
    ("US", "en-US", "US", "US:en", EN_Q),
    ("GB", "en-GB", "GB", "GB:en", EN_Q),
    ("CA", "en-CA", "CA", "CA:en", EN_Q),
    ("AU", "en-AU", "AU", "AU:en", EN_Q),
    ("NZ", "en-NZ", "NZ", "NZ:en", EN_Q),
    ("IE", "en-IE", "IE", "IE:en", EN_Q),
    ("IN", "en-IN", "IN", "IN:en", EN_Q),
    ("SG", "en-SG", "SG", "SG:en", EN_Q),
    ("ZA", "en-ZA", "ZA", "ZA:en", EN_Q),
    ("PH", "en-PH", "PH", "PH:en", EN_Q),
    ("DE", "de", "DE", "DE:de", "(Stromausfall OR Stromnetz OR Blackout OR Umspannwerk) (Cyberangriff OR Hackerangriff OR Hacker) when:2d"),
    ("AT", "de-AT", "AT", "AT:de", "(Stromausfall OR Stromnetz OR Blackout) (Cyberangriff OR Hacker) when:2d"),
    ("CH", "de-CH", "CH", "CH:de", "(Stromausfall OR Stromnetz OR Blackout) (Cyberangriff OR Hacker) when:2d"),
    ("FR", "fr", "FR", "FR:fr", '(panne OR "coupure de courant" OR "réseau électrique" OR blackout) (cyberattaque OR pirates OR hackers) when:2d'),
    ("BE", "fr-BE", "BE", "BE:fr", '(panne OR "coupure de courant" OR "réseau électrique") (cyberattaque OR pirates) when:2d'),
    ("NL", "nl", "NL", "NL:nl", "(stroomstoring OR stroomnet OR elektriciteitsnet) (cyberaanval OR hackers) when:2d"),
    ("ES", "es", "ES", "ES:es", '(apagón OR "red eléctrica" OR "corte de luz") (ciberataque OR hackers) when:2d'),
    ("PT", "pt-PT", "PT", "PT:pt-150", '(apagão OR "rede elétrica" OR "falha de energia") (ciberataque OR "ataque informático" OR hackers) when:2d'),
    ("IT", "it", "IT", "IT:it", '(blackout OR "rete elettrica" OR "interruzione di corrente") ("attacco informatico" OR hacker) when:2d'),
    ("PL", "pl", "PL", "PL:pl", '(blackout OR "sieć energetyczna" OR "awaria prądu") (cyberatak OR hakerzy) when:2d'),
    ("UA", "uk", "UA", "UA:uk", "(блекаут OR енергосистема OR знеструмлення) (кібератака OR хакери) when:2d"),
    ("SE", "sv", "SE", "SE:sv", "(strömavbrott OR elnät) (cyberattack OR hackare OR it-attack) when:2d"),
    ("NO", "no", "NO", "NO:no", "(strømbrudd OR strømnett) (dataangrep OR hackere) when:2d"),
    ("FI", "fi", "FI", "FI:fi", "(sähkökatko OR sähköverkko) (kyberhyökkäys OR hakkerit) when:2d"),
    ("DK", "da", "DK", "DK:da", "(strømafbrydelse OR elnet) (cyberangreb OR hackere) when:2d"),
    ("JP", "ja", "JP", "JP:ja", "(停電 OR 電力網 OR 送電網) サイバー攻撃 when:2d"),
    ("KR", "ko", "KR", "KR:ko", "(정전 OR 전력망) (사이버공격 OR 해킹) when:2d"),
    ("TW", "zh-TW", "TW", "TW:zh-Hant", "(停電 OR 電網) (網路攻擊 OR 駭客) when:2d"),
    ("BR", "pt-BR", "BR", "BR:pt-419", '(apagão OR "rede elétrica") ("ataque cibernético" OR hackers) when:2d'),
    ("MX", "es-419", "MX", "MX:es-419", '(apagón OR "red eléctrica") (ciberataque OR hackers) when:2d'),
    ("AR", "es-419", "AR", "AR:es-419", '(apagón OR "red eléctrica") (ciberataque OR hackers) when:2d'),
    ("CL", "es-419", "CL", "CL:es-419", '(apagón OR "red eléctrica") (ciberataque OR hackers) when:2d'),
    ("IL", "iw", "IL", "IL:he", '("הפסקת חשמל" OR "רשת החשמל") ("מתקפת סייבר" OR האקרים) when:2d'),
]
# Worldwide context searches (English).
GLOBAL_NEWS = [
    ("taiwan", 'Taiwan (blockade OR quarantine OR encircle OR invasion OR "live-fire" OR "live fire") China when:2d'),
    ("apt", '("Volt Typhoon" OR "Salt Typhoon" OR Sandworm OR ELECTRUM) when:2d'),
    ("widespread", '("nationwide blackout" OR "widespread blackout" OR "massive blackout" OR "grid collapse") when:2d'),
]

NEMWEB_DIR = "https://nemweb.com.au/Reports/Current/Market_Notice/"
AU_STATES = {
    "NSW": [r"\bNSW1?\b", "New South Wales"], "QLD": [r"\bQLD1?\b", "Queensland"], "VIC": [r"\bVIC1?\b", "Victoria"],
    "SA": [r"\bSA1\b", "South Australia"], "TAS": [r"\bTAS1?\b", "Tasmania"],
}

# ---------------------------------------------------------------- keyword sets (multilingual)
def rx(*w):
    return re.compile("(" + "|".join(w) + ")", re.I)

CI = rx("critical infrastructure", "energy", "electric", "power grid", "utilit", "operational technology", r"\bOT\b",
        r"\bICS\b", "SCADA", "industrial control", "Energie", "énergie", "energía", "SCI", "電力", "energetyk", "енерг")
SEVERE = rx("actively exploit", "active exploitation", "exploited in the wild", "state-sponsored", "state sponsored",
            r"\bPRC\b", "China", "Russia", "urgent", "pre-position", "Volt Typhoon", "Sandworm", "destructive", "wiper",
            "exploitée", "explotad", "ausgenutzt", "aktiv")
GRID = rx("power grid", "electric grid", "electricity grid", "grid", "blackout", "power outage", "substation", "power plant",
          "utility", "Stromausfall", "Stromnetz", "Umspannwerk", "panne", "coupure de courant", "réseau électrique",
          "apagón", "red eléctrica", "corte de luz", "apagão", "rede elétrica", "rete elettrica", "interruzione di corrente",
          "stroomstoring", "stroomnet", "elektriciteitsnet", "sieć energetyczna", "awaria prądu", "блекаут", "енергосистем",
          "знеструмлен", "strömavbrott", "elnät", "strømbrudd", "strømnett", "sähkökatko", "sähköverkko", "strømafbrydelse",
          "elnet", "停電", "電力網", "送電網", "電網", "정전", "전력망", "הפסקת חשמל", "רשת החשמל")
CYBER = rx("cyber", "hack", "ransomware", "malware", "wiper", "Cyberangriff", "Hackerangriff", "cyberattaque", "pirates",
           "ciberataque", "ataque cibernético", "ataque informático", "attacco informatico", "cyberaanval", "cyberatak",
           "hakerzy", "кібератак", "хакер", "it-attack", "hackare", "dataangrep", "hackere", "kyberhyökkäys", "hakkerit",
           "cyberangreb", "サイバー攻撃", "사이버공격", "해킹", "網路攻擊", "駭客", "מתקפת סייבר", "האקרים")
DISRUPT = rx("blackout", "outage", "disrupt", "cut power", "knocked out", "shut down", "offline", "without power",
              "Stromausfall", "panne", "coupure", "apagón", "corte", "apagão", "interruzione", "stroomstoring",
              "awaria", "блекаут", "знеструмлен", "strömavbrott", "strømbrudd", "sähkökatko", "strømafbrydelse",
              "停電", "정전", "הפסקת חשמל")
FAILED = rx("thwart", "foiled", "stopped", "prevented", "repelled", "no outage", "without causing", "unsuccessful",
            "vereitelt", "déjoué", "frustrado", "sventato", "udaremn")
PAST = rx("anniversary", "years ago", "lessons from", "retrospective", "documentary", "Jahrestag", "anniversaire", "aniversario")
DATA_BREACH = rx("data breach", "customer data", "personal information", "phishing scam", "Datenleck", "fuite de données")
TAIWAN_ESC = rx("blockade", "quarantine", "encircle", "invasion", "live-fire", "live fire", "exercise", "drill")
WIDESPREAD = rx("nationwide", "widespread", "massive", "grid collapse", "entire country", "millions without power")


def countries_in(text):
    found = []
    for code, names in COUNTRIES.items():
        for n in names:
            if "\\" in n:
                pat, flags = n, re.I
            elif n.isascii():
                pat, flags = r"\b" + re.escape(n) + r"\b", re.I
            else:
                pat, flags = re.escape(n), 0
            if re.search(pat, text, flags):
                found.append(code)
                break
    return found


# ---------------------------------------------------------------- rules
def rules(item):
    """Return list of (level, reason, targets) where targets are codes like 'AU', 'EU', 'AU-NSW', 'GLOBAL'."""
    kind, home, blob = item["kind"], item.get("home"), f'{item["title"]} {item.get("text", "")}'
    out = []
    if kind == "aemo":
        states = [s for s, pats in AU_STATES.items() if any(re.search(p, blob, re.I) for p in pats)]
        targets = ["AU-" + s for s in states] or ["AU"]
        if re.search(r"black system|system black", blob, re.I):
            out.append(("red", "AEMO notice: black system", targets))
        elif re.search(r"load shedding|actual lor3", blob, re.I):
            out.append(("orange", "AEMO notice: load shedding or actual LOR3 (grid emergency)", targets))
        elif re.search(r"actual lor2|actual lack of reserve level 2", blob, re.I):
            out.append(("yellow", "AEMO notice: actual LOR2 (tight supply)", targets))
        if re.search(r"cyber", blob, re.I):
            out.append(("orange", "AEMO notice mentions cyber", targets))
        return out
    if kind == "agency":
        if CI.search(blob) and SEVERE.search(blob):
            lvl = "orange" if re.search(r"actively exploit|active exploitation|exploited in the wild|compromis", blob, re.I) else "yellow"
            out.append((lvl, f"{item['source']}: alert on critical infrastructure", [home]))
        elif CI.search(blob):
            out.append(("yellow", f"{item['source']}: critical infrastructure advisory", [home]))
        return out
    # news
    if PAST.search(blob):
        return out
    mentioned = countries_in(blob)
    if item.get("query") == "taiwan":
        if re.search(r"Taiwan", blob) and TAIWAN_ESC.search(blob):
            out.append(("yellow", "Taiwan Strait escalation or major exercise", INDO_PACIFIC))
        return out
    if item.get("query") == "apt":
        if mentioned:
            out.append(("yellow", "State hacking group linked to infrastructure in this country", mentioned))
        return out
    targets = mentioned or ([home] if home else [])
    if not targets:
        return out
    if GRID.search(blob) and CYBER.search(blob):
        if DATA_BREACH.search(blob) and not DISRUPT.search(blob):
            out.append(("yellow", "Data breach at an energy company", targets))
        elif DISRUPT.search(blob) and not FAILED.search(blob):
            out.append(("orange", "Reported cyber disruption of the power grid", targets))
        else:
            out.append(("yellow", "Cyber attack attempt on energy infrastructure reported", targets))
    if item.get("query") == "widespread" and WIDESPREAD.search(blob) and re.search(r"blackout|power", blob, re.I):
        out.append(("orange", "Widespread blackout reported", targets))
    return out


# ---------------------------------------------------------------- fetching
def get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def strip_tags(s):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", s or ""))).strip()


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except Exception:
        pass
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except Exception:
        pass
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone(dt.timedelta(hours=10)))
        except Exception:
            continue
    return None


def local(tag):
    return tag.rsplit("}", 1)[-1]


def child_text(el, *names):
    for c in el:
        if local(c.tag) in names:
            if local(c.tag) == "link" and c.get("href"):
                return c.get("href")
            if c.text and c.text.strip():
                return c.text
    return ""


def parse_feed(raw):
    """RSS 2.0, RSS 1.0 (RDF) and Atom, namespace-agnostic."""
    items = []
    root = ET.fromstring(raw)
    for el in root.iter():
        if local(el.tag) not in ("item", "entry"):
            continue
        items.append({
            "title": strip_tags(child_text(el, "title")),
            "text": strip_tags(child_text(el, "description", "summary", "content"))[:600],
            "url": (child_text(el, "link") or "").strip(),
            "date": parse_date(child_text(el, "pubDate", "updated", "published", "date")),
            "publisher": strip_tags(child_text(el, "source")) or None,
        })
    return items


def fetch_agencies(errors):
    out = []
    for home, name, url in AGENCY_FEEDS:
        try:
            for i in parse_feed(get(url)):
                i.update(kind="agency", home=home, source=name, publisher=name)
                out.append(i)
        except Exception as e:
            errors.append(f"{name}: {e.__class__.__name__}")
    return out


def gnews(q, hl="en-US", gl="US", ceid="US:en"):
    return "https://news.google.com/rss/search?" + urllib.parse.urlencode({"q": q, "hl": hl, "gl": gl, "ceid": ceid})


def fetch_news(errors):
    out = []
    for home, hl, gl, ceid, q in NEWS_EDITIONS:
        try:
            for i in parse_feed(get(gnews(q, hl, gl, ceid)))[:12]:
                i.update(kind="news", home=home, source=f"News ({home})", query="local")
                out.append(i)
        except Exception as e:
            errors.append(f"News {home}: {e.__class__.__name__}")
    for label, q in GLOBAL_NEWS:
        try:
            for i in parse_feed(get(gnews(q)))[:15]:
                i.update(kind="news", home=None, source="News (worldwide)", query=label)
                out.append(i)
        except Exception as e:
            errors.append(f"News {label}: {e.__class__.__name__}")
    return out


def fetch_aemo(errors, max_files=60):
    out = []
    try:
        listing = get(NEMWEB_DIR).decode("utf-8", "replace")
    except Exception as e:
        errors.append(f"AEMO notices: {e.__class__.__name__}")
        return out
    files = sorted(set(re.findall(r'href="([^"]*MKTNOTICE[^"]*)"', listing, re.I)),
                   key=lambda f: int(re.search(r"(\d+)$", f).group(1)) if re.search(r"(\d+)$", f) else 0)
    for f in files[-max_files:]:
        url = urllib.parse.urljoin(NEMWEB_DIR, f)
        try:
            txt = get(url, timeout=15).decode("utf-8", "replace")
        except Exception:
            continue

        def field(name):
            m = re.search(name + r"\s*:\s*(.+)", txt, re.I)
            return m.group(1).strip() if m else ""
        body = re.split(r"Reason\s*:", txt, flags=re.I)
        out.append({
            "kind": "aemo", "home": "AU", "source": "AEMO notice", "publisher": "AEMO",
            "title": (field("External Reference") or "AEMO market notice") + (f" [{field('Notice Type ID')}]" if field("Notice Type ID") else ""),
            "text": re.sub(r"\s+", " ", body[1] if len(body) > 1 else txt)[:600],
            "url": url, "date": parse_date(field("Issue Date")),
        })
    return out


# ---------------------------------------------------------------- main
def bump(d, key, lvl):
    if LEVELS.index(lvl) > LEVELS.index(d.get(key, "green")):
        d[key] = lvl


def main():
    now = dt.datetime.now(dt.timezone.utc)
    errors = []
    items = fetch_agencies(errors) + fetch_aemo(errors) + fetch_news(errors)

    def recent(i):
        if i["date"] is None:
            return True
        limit = dt.timedelta(days=AGENCY_LOOKBACK_DAYS) if i["kind"] == "agency" else dt.timedelta(hours=LOOKBACK_HOURS)
        return i["date"] >= now - limit

    matched, seen = [], set()
    for i in filter(recent, items):
        key = re.sub(r"\W+", "", i["title"].lower())[:90]
        if not key or key in seen:
            continue
        seen.add(key)
        for lvl, why, targets in rules(i):
            matched.append((lvl, why, targets, i))

    # Rate each target. A single news headline alone can't push a place above yellow.
    levels, orange_news = {}, {}
    for lvl, why, targets, i in matched:
        for t in targets:
            if lvl == "orange" and i["kind"] == "news":
                orange_news[t] = orange_news.get(t, 0) + 1
                continue
            bump(levels, t, lvl)
    for t, n in orange_news.items():
        bump(levels, t, "orange" if n >= 2 else "yellow")

    countries = {k: v for k, v in levels.items() if "-" not in k and k not in ("EU", "GLOBAL")}
    regions = {k: v for k, v in levels.items() if "-" in k}
    eu_level = levels.get("EU", "green")
    worst = max([*levels.values(), "green"], key=LEVELS.index)
    global_level = "yellow" if LEVELS.index(worst) >= LEVELS.index("orange") else "green"

    matched.sort(key=lambda m: (-LEVELS.index(m[0]), -(m[3]["date"].timestamp() if m[3]["date"] else 0)))
    out_items, used = [], set()
    for lvl, why, targets, i in matched:
        k = (i["title"], tuple(targets))
        if k in used:
            continue
        used.add(k)
        out_items.append({"text": i["title"], "source": i.get("publisher") or i["source"],
                          "url": i["url"] if str(i["url"]).startswith("http") else "",
                          "level": lvl, "why": why, "targets": targets})
        if len(out_items) >= 60:
            break

    today = now.astimezone(dt.timezone(dt.timedelta(hours=10))).date().isoformat()
    hist_path = os.path.join(DATA, "history.json")
    try:
        with open(hist_path) as f:
            history = json.load(f)
    except Exception:
        history = []
    if not items and any(r.get("id") == today for r in history):
        print("No sources reachable; keeping today's existing report.")
        return 0

    report = {
        "id": today, "date": today, "auto": True,
        "level": global_level, "countries": countries, "regions": regions, "eu": eu_level,
        "headline": (out_items[0]["why"] if out_items else "Nothing notable noticed or released."),
        "items": out_items, "actions": ACTIONS,
        "checkedAt": now.isoformat(timespec="minutes"), "sourcesChecked": len(items), "sourceErrors": errors,
    }
    os.makedirs(DATA, exist_ok=True)
    history = [r for r in history if r.get("id") != today]
    history.insert(0, report)
    history = sorted(history, key=lambda r: r.get("date", ""), reverse=True)[:HISTORY_DAYS]
    with open(hist_path, "w") as f:
        json.dump(history, f, indent=1, ensure_ascii=False)
    with open(os.path.join(DATA, "status.json"), "w") as f:
        json.dump(report, f, indent=1, ensure_ascii=False)
    print(f"{today}: worldwide {global_level}; {len(countries)} countries rated; {len(items)} items; errors: {errors}")


if __name__ == "__main__":
    sys.exit(main())
