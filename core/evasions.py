from __future__ import annotations

import random
import urllib.parse


def case_randomize(s: str, p: float = 0.5) -> str:
    return "".join(c.upper() if random.random() < p else c.lower() for c in s)


def comment_split(s: str) -> str:
    keywords = ["UNION", "SELECT", "AND", "OR", "WHERE", "FROM", "ORDER", "BY", "SLEEP"]
    out = s
    for kw in keywords:
        if kw.lower() in out.lower():
            idx = out.lower().index(kw.lower())
            out = out[:idx] + kw + "/**/" + out[idx + len(kw):]
    return out


def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def hex_encode(s: str) -> str:
    return "0x" + s.encode().hex()


def whitespace_sub(s: str) -> str:
    return s.replace(" ", random.choice(["/**/", "%0a", "%09", "%0b", "+"]))


def apply_all(s: str, waf: str | None) -> list[str]:
    variants = [s]
    if waf:
        variants.append(case_randomize(s))
        variants.append(comment_split(s))
        variants.append(whitespace_sub(s))
        variants.append(url_encode(s))
        variants.append(double_url_encode(s))
    return list(dict.fromkeys(variants))
