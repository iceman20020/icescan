from __future__ import annotations

import re
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"


TECH_PATTERNS = {
    "PHP": [r"PHP/[\d.]+", r"\.php(?:\?|$)", r"PHPSESSID"],
    "ASP.NET": [r"ASP\.NET", r"X-AspNet-Version", r"\.aspx(?:\?|$)"],
    "Ruby on Rails": [r"X-Runtime", r"X-Powered-By:\s*Phusion"],
    "Django": [r"csrftoken", r"__cfduid=.*Django", r"X-Frame-Options.*django"],
    "Laravel": [r"laravel_session", r"X-Powered-By:\s*Laravel"],
    "Express": [r"X-Powered-By:\s*Express"],
    "Nginx": [r"Server:\s*nginx/[\d.]+"],
    "Apache": [r"Server:\s*Apache/[\d.]+"],
    "IIS": [r"Server:\s*Microsoft-IIS/[\d.]+"],
    "Cloudflare": [r"Server:\s*cloudflare", r"CF-RAY", r"cf-cache-status"],
    "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
    "Drupal": [r"Drupal", r"sites/default/files"],
    "Joomla": [r"joomla", r"/media/system/"],
    "jQuery": [r"jquery[.-][\d.]+"],
    "React": [r"react(?:-dom)?\.[\w.]+\.js", r"data-reactroot"],
    "Vue": [r"vue(?:\.runtime)?\.[\w.]+\.js", r"data-v-"],
    "Angular": [r"ng-version", r"angular(?:\.min)?\.js"],
}


async def run_recon(client, url: str) -> dict:
    out: dict = {"url": url, "tech": [], "headers": {}, "cookies": [], "waf": None}

    r = await client.get(url)
    if r.error:
        return out

    out["headers"] = {k: v for k, v in r.headers.items()}
    out["cookies"] = r.header("Set-Cookie").split(",") if r.header("Set-Cookie") else []
    out["status"] = r.status

    haystack = "\n".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n" + (r.body or "")[:10000]

    for tech, pats in TECH_PATTERNS.items():
        for pat in pats:
            if re.search(pat, haystack, re.I):
                out["tech"].append(tech)
                break

    out["waf"] = _detect_waf(haystack)
    out["robots"] = await _get_optional(client, url.rstrip("/") + "/robots.txt")
    out["sitemap"] = await _get_optional(client, url.rstrip("/") + "/sitemap.xml")

    return out


def _detect_waf(haystack: str) -> str | None:
    try:
        waf_file = DATA / "signatures" / "waf.txt"
        if not waf_file.exists():
            return None
        for line in waf_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" in line:
                name, pat = line.split("|", 1)
                if re.search(pat, haystack, re.I):
                    return name.strip()
    except Exception:
        pass
    return None


async def _get_optional(client, url: str) -> str:
    r = await client.get(url)
    if r.error or r.status >= 400:
        return ""
    return r.body[:5000]
