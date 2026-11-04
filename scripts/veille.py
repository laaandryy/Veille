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
        techs.append({"name": name, "info": info})
    return techs


def load_sources() -> dict:
    data = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    return {k.strip().lower(): v for k, v in data.items() if not k.startswith("_")}


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


def google_news(query: str, lang: str) -> list[dict]:
    params = {"fr": "hl=fr&gl=FR&ceid=FR:fr", "en": "hl=en-US&gl=US&ceid=US:en"}[lang]
    url = f"https://news.google.com/rss/search?q={urllib.parse.quote(query + ' when:30d')}&{params}"
    try:
        return [dict(i, lang=lang) for i in parse_feed(fetch(url))]
    except Exception as e:  # noqa: BLE001
        log(f"  ! news {lang} '{query}': {e}")
        return []


def nvd_cves(keyword: str) -> list[dict] | None:
    """CVE récentes de la base NVD (NIST) dont la description contient `keyword`.

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
        out.append({
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
        found = nvd_cves(keyword)
        if found is None:
            r["cves"] = prev.get(r["name"], [])
            r["cve_total"] = len(r["cves"])
            r["cve_stale"] = True
        else:
            r["cves"], r["cve_total"] = found[:MAX_CVES], len(found)
        log(f"- CVE {r['name']} ({keyword}) : {r['cve_total']}")


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
    news += google_news(query, "fr")
    news += google_news(query, "en")

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

    return {
        "name": name,
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
    techs = read_technologies()
    sources = load_sources()
    log(f"{len(techs)} technologies à suivre")
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda t: collect(t, sources.get(t["name"].lower(), {})), techs))

    previous = {}
    if DATA_PATH.exists():
        try:
            previous = json.loads(DATA_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous = {}
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
