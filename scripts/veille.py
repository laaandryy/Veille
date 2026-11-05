#!/usr/bin/env python3
"""Veille technologique quotidienne.

Lit technologies.csv, collecte pour chaque technologie :
  - la dernière version publiée (GitHub Releases, ou kernel.org pour le noyau),
  - les billets récents des flux officiels (RSS/Atom),
  - les actualités récentes (Google News, en français puis en anglais),
puis génère index.html (site vitrine statique, données embarquées)
et data/veille.json (instantané + historique des éléments déjà vus).

Uniquement la bibliothèque standard Python : aucune dépendance à installer.
"""
from __future__ import annotations

import csv
import html
import json
import os
import re
import sys
from fnmatch import fnmatch
import unicodedata
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "technologies.csv"
SOURCES_PATH = ROOT / "scripts" / "sources.json"
TEMPLATE_PATH = ROOT / "scripts" / "template.html"
DATA_PATH = ROOT / "data" / "veille.json"
OUT_PATH = ROOT / "index.html"

NOW = datetime.now(timezone.utc)
NEWS_WINDOW_DAYS = 30      # actualités plus anciennes ignorées
MAX_NEWS = 6               # actualités affichées par technologie
MAX_RELEASES = 3
HISTORY_DAYS = 120         # durée de conservation des liens « déjà vus »
CVE_WINDOW_DAYS = 30       # CVE publiées sur les 30 derniers jours
MAX_CVES = 5               # CVE affichées par technologie
UA = "veille-bot/1.0 (+https://github.com/laaandryy/Veille)"
TIMEOUT = 20


# --------------------------------------------------------------------------- utils
def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def fetch(url: str, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    try:
        d = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        d = None
    if d is None:
        try:
            d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def iso(d: datetime | None) -> str | None:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def clean_text(s: str | None, limit: int = 220) -> str:
    if not s:
        return ""
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(re.sub(r"\s+", " ", s)).strip()
    return s if len(s) <= limit else s[: limit - 1].rsplit(" ", 1)[0] + "…"


# --------------------------------------------------------------------------- inputs
def read_technologies() -> list[dict]:
    raw = CSV_PATH.read_bytes().decode("utf-8-sig", errors="replace")
    rows = list(csv.reader(raw.splitlines(), delimiter=";"))
    techs = []
    for row in rows[1:]:
        if not row or not row[0].strip():
            continue
        name = row[0].strip()
        info = row[1].strip() if len(row) > 1 else ""
        installed = row[2].strip() if len(row) > 2 else ""
        techs.append({"name": name, "info": info, "installed": installed})
    return techs


def load_sources() -> tuple[dict, dict]:
    data = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    sources = {k.strip().lower(): v for k, v in data.items() if not k.startswith("_")}
    return sources, data.get("_filtres", {})


# --------------------------------------------------------------------------- filtres
def norm(s: str) -> str:
    """Minuscules, sans accents ni ponctuation, pour comparer des titres."""
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    return " " + re.sub(r"[^a-z0-9.+]+", " ", s).strip() + " "


class NewsFilter:
    """Écarte les articles hors sujet ou commerciaux (pubs, promos, comparatifs…)."""

    def __init__(self, cfg: dict):
        self.title_re = re.compile("|".join(cfg.get("titres_exclus", [])) or r"(?!x)x", re.I)
        self.sources = [norm(x) for x in cfg.get("sources_exclues", [])]
        self.dropped = 0

    def ok(self, item: dict, terms: list[str]) -> bool:
        title = item["title"]
        if self.title_re.search(title):
            return self._drop()
        src = norm(item.get("source") or "") + norm(urllib.parse.urlparse(item["url"]).netloc)
        if any(b in src for b in self.sources):
            return self._drop()
        # Hors flux officiels : la technologie doit être nommée dans le titre.
        if not item.get("official") and terms and not any(t in norm(title) for t in terms):
            return self._drop()
        return True

    def _drop(self) -> bool:
        self.dropped += 1
        return False


NEWS_FILTER: NewsFilter | None = None
NEWS_FILTER_CFG: dict = {}


def github_repo_from(url: str) -> str | None:
    m = re.match(r"https?://github\.com/([^/\s]+)/([^/\s#?]+)", url or "")
    return f"{m.group(1)}/{m.group(2).removesuffix('.git')}" if m else None


# --------------------------------------------------------------------------- collectors
def gh_releases(repo: str) -> tuple[list[dict], dict | None]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    releases: list[dict] = []
    try:
        data = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases?per_page=30", headers))
        for r in data:
            if r.get("draft") or r.get("prerelease"):
                continue
            releases.append({
                "version": r.get("name") or r.get("tag_name"),
                "tag": r.get("tag_name"),
                "date": iso(parse_date(r.get("published_at"))),
                "url": r.get("html_url"),
            })
            if len(releases) >= MAX_RELEASES:
                break
        if not releases:  # dépôt sans releases : repli sur les tags
            tags = json.loads(fetch(f"https://api.github.com/repos/{repo}/tags?per_page=3", headers))
            releases = [{"version": t["name"], "tag": t["name"], "date": None,
                         "url": f"https://github.com/{repo}/releases/tag/{urllib.parse.quote(t['name'])}"}
                        for t in tags[:MAX_RELEASES]]
    except Exception as e:  # noqa: BLE001
        log(f"  ! releases {repo}: {e}")
    repo_meta = None
    try:
        meta = json.loads(fetch(f"https://api.github.com/repos/{repo}", headers))
        repo_meta = {"stars": meta.get("stargazers_count"), "pushed": meta.get("pushed_at"),
                     "url": meta.get("html_url"), "description": meta.get("description")}
    except Exception as e:  # noqa: BLE001
        log(f"  ! repo {repo}: {e}")
    return releases, repo_meta


def kernel_releases() -> list[dict]:
    try:
        data = json.loads(fetch("https://www.kernel.org/releases.json"))
    except Exception as e:  # noqa: BLE001
        log(f"  ! kernel.org: {e}")
        return []
    out = []
    for r in data.get("releases", []):
        if r.get("moniker") not in ("mainline", "stable", "longterm"):
            continue
        ts = (r.get("released") or {}).get("timestamp")
        out.append({
            "version": f"{r['version']} ({r['moniker']})",
            "tag": r["version"],
            "date": iso(datetime.fromtimestamp(ts, timezone.utc)) if ts else None,
            "url": r.get("changelog") or "https://www.kernel.org",
        })
    out.sort(key=lambda x: x["date"] or "", reverse=True)
    return out[:MAX_RELEASES]


def parse_feed(xml_bytes: bytes, source_label: str | None = None) -> list[dict]:
    items = []
    root = ET.fromstring(xml_bytes)
    ns_atom = "{http://www.w3.org/2005/Atom}"
    # RSS 2.0 / RDF
    for it in root.iter():
        tag = it.tag.split("}")[-1]
        if tag not in ("item", "entry"):
            continue
        def get(*names, _it=it):
            # NB : un Element sans enfant est « falsy », d'où les tests explicites à None.
            for name in names:
                for c in _it:
                    if c.tag.split("}")[-1] == name:
                        return c
            return None
        title_el = get("title")
        title = clean_text(title_el.text if title_el is not None else "", 200)
        link = None
        link_el = get("link")
        if link_el is not None:
            link = link_el.get("href") or (link_el.text or "").strip()
        if tag == "entry":
            for l in it.findall(f"{ns_atom}link"):
                if l.get("rel", "alternate") == "alternate":
                    link = l.get("href")
                    break
        date_el = get("pubDate", "published", "updated", "date")
        desc_el = get("description", "summary", "content")
        src_el = get("source")
        source = (src_el.text.strip() if src_el is not None and src_el.text else None) or source_label
        if title and source and tag == "item" and title.endswith(f" - {source}"):
            title = title[: -len(f" - {source}")]
        if not title or not link:
            continue
        items.append({
            "title": title,
            "url": link,
            "date": iso(parse_date(date_el.text if date_el is not None else None)),
            "source": source,
            "summary": "" if "news.google.com" in link else clean_text(desc_el.text if desc_el is not None else ""),
        })
    return items


def official_feed(url: str) -> list[dict]:
    try:
        host = urllib.parse.urlparse(url).netloc.removeprefix("www.")
        return [dict(i, official=True) for i in parse_feed(fetch(url), host)]
    except Exception as e:  # noqa: BLE001
        log(f"  ! flux {url}: {e}")
        return []


def google_news(query: str, lang: str, negative: str = "") -> list[dict]:
    params = {"fr": "hl=fr&gl=FR&ceid=FR:fr", "en": "hl=en-US&gl=US&ceid=US:en"}[lang]
    q = " ".join(x for x in (query, negative, "when:30d") if x)
    url = f"https://news.google.com/rss/search?q={urllib.parse.quote(q)}&{params}"
    try:
        return [dict(i, lang=lang) for i in parse_feed(fetch(url))]
    except Exception as e:  # noqa: BLE001
        log(f"  ! news {lang} '{query}': {e}")
        return []


def eol_cycles(product: str) -> list[dict]:
    """Branches d'un produit sur endoflife.date, normalisées.

    Chaque branche : {cycle, release, eol (date ISO, True/False), lts, latest, latest_date, link}.
    Gère l'API v1 et, en repli, l'ancienne API /api/<produit>.json.
    """
    def as_eol(v):
        return v if isinstance(v, (bool, str)) or v is None else None
    try:
        data = json.loads(fetch(f"https://endoflife.date/api/v1/products/{product}"))
        out = []
        for r in (data.get("result") or {}).get("releases", []):
            latest = r.get("latest") or {}
            eol = r.get("eolFrom") or r.get("isEol")
            out.append({"cycle": str(r.get("name")), "release": r.get("releaseDate"), "eol": as_eol(eol),
                        "lts": bool(r.get("isLts")), "latest": latest.get("name"),
                        "latest_date": latest.get("date"), "link": latest.get("link")})
        if out:
            return out
    except Exception as e:  # noqa: BLE001
        log(f"  ! endoflife v1 {product}: {e}")
    try:
        data = json.loads(fetch(f"https://endoflife.date/api/{product}.json"))
        return [{"cycle": str(r.get("cycle")), "release": r.get("releaseDate"), "eol": as_eol(r.get("eol")),
                 "lts": bool(r.get("lts")), "latest": r.get("latest"),
                 "latest_date": r.get("latestReleaseDate"), "link": r.get("link")} for r in data]
    except Exception as e:  # noqa: BLE001
        log(f"  ! endoflife {product}: {e}")
        return []


def eol_status(cycle: dict) -> tuple[bool, str | None]:
    """(branche en fin de support ?, date de fin de support ISO ou None)."""
    eol = cycle.get("eol")
    if isinstance(eol, str):
        d = parse_date(eol + "T00:00:00Z") if len(eol) == 10 else parse_date(eol)
        return (bool(d and d <= NOW), eol[:10])
    return (bool(eol), None)


def eol_match(cycles: list[dict], installed: tuple | None) -> dict | None:
    """Branche correspondant à la version installée (préfixe le plus long : 6.1 pour 6.1.115)."""
    if not installed:
        return None
    best = None
    for c in cycles:
        cv = parse_version(c["cycle"])
        if cv and installed[: len(cv)] == cv and (best is None or len(cv) > len(parse_version(best["cycle"]))):
            best = c
    return best


def parse_version(s: str | None) -> tuple[int, ...] | None:
    """'v1.2.3', 'Release 1.2.3 (…)', '2.51.0.windows.1' -> (1, 2, 3)."""
    m = re.search(r"\d+(?:\.\d+)*", s or "")
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def vcmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def cpe_affects(match: dict, version: tuple) -> bool:
    """La version installée tombe-t-elle dans la plage vulnérable d'un cpeMatch NVD ?"""
    exact = match["criteria"].split(":")[5]
    if exact not in ("*", "-"):
        v = parse_version(exact)
        return bool(v) and vcmp(version, v) == 0
    bounds = (("versionStartIncluding", lambda c: c >= 0), ("versionStartExcluding", lambda c: c > 0),
              ("versionEndIncluding", lambda c: c <= 0), ("versionEndExcluding", lambda c: c < 0))
    for key, ok in bounds:
        if match.get(key):
            b = parse_version(match[key])
            if b and not ok(vcmp(version, b)):
                return False
    return True


def cpe_check(cve: dict, patterns: list[str], installed: tuple | None) -> tuple[str, bool | None]:
    """Statut produit d'une CVE d'après ses configurations CPE.

    'confirmed' : un CPE vulnérable correspond à la technologie ;
    'pending'   : CVE pas encore analysée par la NVD (aucun CPE) ;
    'other'     : analysée, mais concerne un autre produit (à écarter).
    Second élément : la version installée est-elle concernée ? (None si inconnu)
    """
    matches = [m for conf in cve.get("configurations", []) for node in conf.get("nodes", [])
               for m in node.get("cpeMatch", []) if m.get("vulnerable")]
    if not matches:
        return "pending", None
    mine = []
    for m in matches:
        parts = m.get("criteria", "").split(":")
        if len(parts) > 5 and any(fnmatch(f"{parts[3]}:{parts[4]}", p) for p in patterns):
            mine.append(m)
    if not mine:
        return "other", None
    if not installed:
        return "confirmed", None
    return "confirmed", any(cpe_affects(m, installed) for m in mine)


def nvd_cves(keyword: str, patterns: list[str] | None = None, installed: str = "") -> list[dict] | None:
    """CVE récentes de la base NVD (NIST) dont la description contient `keyword`.

    Si `patterns` (motifs 'éditeur:produit' des CPE) est fourni, les CVE déjà analysées
    qui visent un autre produit sont écartées, et la version installée est comparée
    aux plages vulnérables.

    Renvoie None en cas d'échec (pour conserver les données de la veille précédente).
    Sans clé API, la NVD autorise 5 requêtes / 30 s : l'appelant espace les appels.
    """
    start = (NOW - timedelta(days=CVE_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    params = urllib.parse.urlencode({
        "keywordSearch": keyword, "keywordExactMatch": "",
        "pubStartDate": start, "pubEndDate": end, "resultsPerPage": 2000,
        "noRejected": "",
    }).replace("keywordExactMatch=&", "keywordExactMatch&").replace("&noRejected=", "&noRejected")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    data = None
    for attempt in range(3):
        try:
            data = json.loads(fetch(url, headers))
            break
        except Exception as e:  # noqa: BLE001
            log(f"  ! nvd '{keyword}' (essai {attempt + 1}): {e}")
            time.sleep(12 * (attempt + 1))
    if data is None:
        return None
    out = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        if c.get("vulnStatus") == "Rejected":
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        sev, score = None, None
        metrics = c.get("metrics", {})
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                m = metrics[k][0]
                cd = m.get("cvssData", {})
                score = cd.get("baseScore")
                sev = cd.get("baseSeverity") or m.get("baseSeverity")
                break
        status, affects = ("keyword", None)
        if patterns:
            status, affects = cpe_check(c, patterns, parse_version(installed) if installed else None)
            if status == "other":
                continue
        out.append({
            "status": status,
            "affects": affects,
            "id": c.get("id"),
            "url": f"https://nvd.nist.gov/vuln/detail/{c.get('id')}",
            "date": iso(parse_date(c.get("published"))),
            "severity": (sev or "").upper() or None,
            "score": score,
            "exploited": bool(c.get("cisaExploitAdd")),
            "summary": clean_text(desc, 260),
        })
    out.sort(key=lambda x: x["date"] or "", reverse=True)
    for c in out:
        d = parse_date(c["date"])
        c["new"] = bool(d and NOW - d < timedelta(hours=48))
    return out


CVEORG_MAX_PER_TECH = 150  # CVE non analysées par la NVD vérifiées sur CVE.org, par techno


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9*]+", "_", (s or "").lower()).strip("_")


def _le_wild(v: tuple, bound: str) -> bool:
    """v <= bound, où bound peut finir par '*' (ex. '6.1.*' = toute la branche 6.1)."""
    if bound.strip() == "*":
        return True
    if bound.endswith("*"):
        p = parse_version(bound)
        return bool(p) and v[: len(p)] <= p
    b = parse_version(bound)
    return bool(b) and vcmp(v, b) <= 0


def cna_affects(entry: dict, installed: tuple) -> bool | None:
    """Statut d'une version d'après un bloc 'affected' du format CVE 5 (CVE.org)."""
    hits = []
    for ver in entry.get("versions", []):
        if ver.get("versionType") == "git":
            continue
        start = parse_version(ver.get("version")) if ver.get("version") not in (None, "*", "n/a") else (0,)
        if start is None:
            continue
        lt, le = ver.get("lessThan"), ver.get("lessThanOrEqual")
        if lt or le:
            inside = vcmp(installed, start) >= 0
            if le:
                inside = inside and _le_wild(installed, le)
            if lt and lt.strip() != "*":
                if lt.endswith("*"):
                    inside = inside and _le_wild(installed, lt)
                else:
                    b = parse_version(lt)
                    inside = inside and bool(b) and vcmp(installed, b) < 0
        else:
            inside = vcmp(installed, start) == 0
        if inside:
            hits.append(ver.get("status"))
    if "unaffected" in hits:
        return False
    if "affected" in hits:
        return True
    default = entry.get("defaultStatus")
    return True if default == "affected" else False if default == "unaffected" else None


def cveorg_check(cve_id: str, patterns: list[str], name: str, installed: tuple | None):
    """Interroge CVE.org (données de l'organisme qui publie la CVE, disponibles dès sa publication).

    Renvoie (statut, version installée concernée ?) ou None si l'API ne répond pas.
    """
    try:
        rec = json.loads(fetch(f"https://cveawg.mitre.org/api/cve/{cve_id}"))
    except Exception as e:  # noqa: BLE001
        log(f"  ! cve.org {cve_id}: {e}")
        return None
    cont = rec.get("containers", {})
    entries = list(cont.get("cna", {}).get("affected", []))
    for adp in cont.get("adp", []):
        entries += adp.get("affected", [])
    entries = [e for e in entries if e.get("product") or e.get("vendor")]
    if not entries:
        return ("pending", None)
    key = _slug(name)
    mine = [e for e in entries
            if any(fnmatch(f"{_slug(e.get('vendor'))}:{_slug(e.get('product'))}", p) for p in patterns)
            or (key and key in _slug(e.get("product")))]
    if not mine:
        return ("other", None)
    if not installed:
        return ("cna", None)
    verdicts = [cna_affects(e, installed) for e in mine]
    return ("cna", True if True in verdicts else False if False in verdicts else None)


def collect_cves(results: list[dict], sources: dict, previous: dict) -> None:
    """Interroge la NVD séquentiellement (limite de débit) et remplit r['cves']."""
    prev = {r["name"]: r.get("cves", []) for r in previous.get("results", [])}
    pause = 0.8 if os.environ.get("NVD_API_KEY") else 6.5
    for i, r in enumerate(results):
        cfg = sources.get(r["name"].lower(), {})
        keyword = cfg.get("cve", r["name"])
        if not keyword:  # "cve": "" dans sources.json pour désactiver
            r["cves"], r["cve_total"] = [], 0
            continue
        if i:
            time.sleep(pause)
        found = nvd_cves(keyword, cfg.get("cpe"), r.get("installed", ""))
        if found and cfg.get("cpe"):
            # CVE pas encore analysées par la NVD : on complète avec CVE.org.
            pending = [c for c in found if c["status"] == "pending"][:CVEORG_MAX_PER_TECH]
            iv = parse_version(r.get("installed", ""))
            with ThreadPoolExecutor(max_workers=8) as pool:
                checks = list(pool.map(lambda c: cveorg_check(c["id"], cfg["cpe"], r["name"], iv), pending))
            for c, res in zip(pending, checks):
                if res:
                    c["status"], c["affects"] = res
            found = [c for c in found if c["status"] != "other"]
        if found is None:
            r["cves"] = prev.get(r["name"], [])
            r["cve_total"] = len(r["cves"])
            r["cve_stale"] = True
        else:
            # Les CVE qui touchent la version installée passent en priorité dans les 5 affichées.
            mine = [c for c in found if c.get("affects")]
            rest = [c for c in found if not c.get("affects")]
            r["cves"] = sorted(mine[:MAX_CVES] + rest[: max(0, MAX_CVES - len(mine))],
                               key=lambda c: c["date"] or "", reverse=True)
            r["cve_total"] = len(found)
            r["cves_affecting"] = len(mine)
            r["cves_pending"] = sum(1 for c in found if c["status"] == "pending")
            r["cves_cna"] = sum(1 for c in found if c["status"] == "cna")
        log(f"- CVE {r['name']} ({keyword}) : {r['cve_total']} "
            f"(CVE.org {r.get('cves_cna', 0)}, à confirmer {r.get('cves_pending', 0)}, "
            f"version installée {r.get('cves_affecting', 0)})")


# --------------------------------------------------------------------------- pipeline
def collect(tech: dict, cfg: dict) -> dict:
    name = tech["name"]
    log(f"- {name}")
    info = tech["info"]
    repo = github_repo_from(info) or cfg.get("github")
    releases, repo_meta = ([], None)
    if cfg.get("kernel"):
        releases = kernel_releases()
    elif repo:
        releases, repo_meta = gh_releases(repo)

    query = cfg.get("query") or f'"{name}"'
    news: list[dict] = []
    for f in cfg.get("feeds", []):
        news += official_feed(f)
    negative = " ".join(f"-{w}" for w in NEWS_FILTER_CFG.get("mots_exclus_recherche", []))
    news += google_news(query, "fr", negative)
    news += google_news(query, "en", negative)
    # Termes devant figurer dans le titre : "match" de sources.json, sinon le nom.
    terms = [" " + norm(t).strip() for t in cfg.get("match", [name])]
    extra = re.compile("|".join(cfg["exclure"]), re.I) if cfg.get("exclure") else None
    news = [n for n in news if NEWS_FILTER.ok(n, terms) and not (extra and extra.search(n["title"]))]

    cutoff = NOW - timedelta(days=NEWS_WINDOW_DAYS)
    seen_urls, seen_titles, kept = set(), set(), []
    for n in sorted(news, key=lambda x: x["date"] or "", reverse=True):
        d = parse_date(n["date"])
        if d and d < cutoff:
            continue
        key_t = re.sub(r"\W+", "", n["title"].lower())[:80]
        if n["url"] in seen_urls or key_t in seen_titles:
            continue
        seen_urls.add(n["url"]); seen_titles.add(key_t)
        kept.append(n)
    # Les billets officiels d'abord s'ils sont récents, puis le reste par date.
    kept.sort(key=lambda x: (x["date"] or ""), reverse=True)
    official = [n for n in kept if n.get("official")][:2]
    others = [n for n in kept if not n.get("official")]
    final = sorted(official + others[: MAX_NEWS - len(official)], key=lambda x: x["date"] or "", reverse=True)

    links = []
    if cfg.get("site"):
        links.append({"label": "Site officiel", "url": cfg["site"]})
    if repo:
        links.append({"label": "GitHub", "url": f"https://github.com/{repo}"})
    if info and not info.startswith("http"):
        links.append({"label": f"Note : {info}", "url": None})

    installed = tech.get("installed", "")
    latest, status = None, None
    iv = parse_version(installed)

    # endoflife.date : branches, dernière version de chaque branche et fin de support.
    eol = None
    if cfg.get("eol"):
        cycles = eol_cycles(cfg["eol"])
        if cycles:
            current = cycles[0]
            if not releases and current.get("latest"):  # pas de releases GitHub : on prend endoflife.date
                releases = [{"version": f"{current['latest']}", "tag": current["latest"],
                             "date": iso(parse_date((current.get("latest_date") or "") + "T00:00:00Z"))
                             if current.get("latest_date") else None,
                             "url": current.get("link") or f"https://endoflife.date/{cfg['eol']}"}]
            mine = eol_match(cycles, iv)
            eol = {"product": cfg["eol"], "url": f"https://endoflife.date/{cfg['eol']}",
                   "current": current["cycle"]}
            if mine:
                ended, until = eol_status(mine)
                eol.update(cycle=mine["cycle"], ended=ended, until=until, lts=mine.get("lts"),
                           cycle_latest=mine.get("latest"))
                if mine.get("latest") and parse_version(mine["latest"]):
                    # mise à jour comparée dans la branche installée (ex. 6.1.x, Debian 12.x)
                    latest = mine["latest"]
                    status = "update" if vcmp(iv, parse_version(latest)) < 0 else "ok"

    if iv and releases and status is None:
        cands = [(parse_version(x["tag"] or x["version"]), x) for x in releases]
        cands = [(v, x) for v, x in cands if v]
        if cfg.get("kernel"):  # noyau : comparer dans la même branche (ex. 6.1.x LTS)
            same = [(v, x) for v, x in cands if v[:2] == iv[:2]]
            cands = same or cands
        if cands:
            v, x = max(cands, key=lambda t: t[0] + (0,) * (6 - len(t[0])))
            latest = x["tag"] or x["version"]
            status = "update" if vcmp(iv, v) < 0 else "ok"

    return {
        "name": name,
        "installed": installed,
        "latest_version": latest,
        "version_status": status,
        "eol": eol,
        "category": cfg.get("category", "Autres"),
        "repo": repo,
        "repo_meta": repo_meta,
        "releases": releases,
        "news": final,
        "news_count": len(kept),
        "links": links,
    }


def mark_new(results: list[dict], history: dict) -> dict:
    """Marque comme « nouveau » ce qui n'a jamais été vu lors des passages précédents."""
    today = NOW.strftime("%Y-%m-%d")
    first_run = not history
    for r in results:
        for item in r["news"] + r["releases"]:
            url = item.get("url")
            if not url:
                continue
            first = history.setdefault(url, today)
            item["new"] = (first == today) and not first_run
            if first_run:  # premier passage : ce qui date de < 48 h est « nouveau »
                d = parse_date(item.get("date"))
                item["new"] = bool(d and NOW - d < timedelta(hours=48))
        r["new_count"] = sum(1 for i in r["news"] + r["releases"] if i.get("new"))
    limit = (NOW - timedelta(days=HISTORY_DAYS)).strftime("%Y-%m-%d")
    return {u: d for u, d in history.items() if d >= limit}


def render(payload: dict) -> str:
    tpl = TEMPLATE_PATH.read_text(encoding="utf-8")
    blob = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    return tpl.replace("/*__DATA__*/null", blob)


def main() -> int:
    global NEWS_FILTER, NEWS_FILTER_CFG
    techs = read_technologies()
    sources, NEWS_FILTER_CFG = load_sources()
    NEWS_FILTER = NewsFilter(NEWS_FILTER_CFG)
    log(f"{len(techs)} technologies à suivre")
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda t: collect(t, sources.get(t["name"].lower(), {})), techs))

    previous = {}
    if DATA_PATH.exists():
        try:
            previous = json.loads(DATA_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous = {}
    log(f"Filtre actualités : {NEWS_FILTER.dropped} articles écartés")
    history = mark_new(results, previous.get("history", {}))
    collect_cves(results, sources, previous)

    total_items = sum(len(r["news"]) + len(r["releases"]) for r in results)
    if total_items == 0 and previous.get("results"):
        log("Aucune donnée collectée (réseau ?) : on conserve la version précédente.")
        return 1

    payload = {
        "generated_at": iso(NOW),
        "results": results,
        "stats": {
            "technologies": len(results),
            "cves": sum(len(r["cves"]) for r in results),
            "to_update": sum(1 for r in results if r.get("version_status") == "update"),
            "eol_ended": sum(1 for r in results if (r.get("eol") or {}).get("ended")),
            "cves_affecting": sum(r.get("cves_affecting", 0) for r in results),
            "cves_critical": sum(1 for r in results for c in r["cves"] if c["severity"] in ("CRITICAL", "HIGH")),
            "news": sum(len(r["news"]) for r in results),
            "new": sum(r["new_count"] for r in results),
            "releases_week": sum(
                1 for r in results for rel in r["releases"][:1]
                if (d := parse_date(rel.get("date"))) and NOW - d < timedelta(days=7)
            ),
        },
    }
    DATA_PATH.parent.mkdir(exist_ok=True)
    DATA_PATH.write_text(json.dumps({**payload, "history": history}, ensure_ascii=False, indent=1), encoding="utf-8")
    OUT_PATH.write_text(render(payload), encoding="utf-8")
    log(f"OK : {payload['stats']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
