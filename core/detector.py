from __future__ import annotations

import difflib
import re
import statistics
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"


class SignatureSet:
    def __init__(self, name: str, patterns: list[tuple[str, re.Pattern]]):
        self.name = name
        self.patterns = patterns

    def match(self, text: str) -> list[str]:
        hits = []
        for raw, rx in self.patterns:
            if rx.search(text):
                hits.append(raw)
        return hits


def _load_signatures(path: Path) -> SignatureSet:
    pats: list[tuple[str, re.Pattern]] = []
    if not path.exists():
        return SignatureSet(path.stem, pats)
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            pats.append((line, re.compile(line, re.I)))
        except re.error:
            continue
    return SignatureSet(path.stem, pats)


class Detector:
    def __init__(self):
        sig_dir = DATA / "signatures"
        self.sets: dict[str, SignatureSet] = {}
        for f in sig_dir.glob("errors_*.txt"):
            self.sets[f.stem.replace("errors_", "")] = _load_signatures(f)
        self.soft_404_sig = _load_signatures(sig_dir / "soft_404.txt")

    def match_errors(self, body: str) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        for dbms, sig in self.sets.items():
            for m in sig.match(body or ""):
                hits.append((dbms, m))
        return hits

    def similarity(self, a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        return difflib.SequenceMatcher(None, a or "", b or "").ratio()

    def length_delta(self, a: int, b: int) -> float:
        if a == 0 and b == 0:
            return 0.0
        m = max(a, b, 1)
        return abs(a - b) / m

    def is_soft_404(self, body: str) -> bool:
        return bool(self.soft_404_sig.match(body or ""))

    def timing_confirm(self, times: list[float], baseline_mean: float, baseline_stdev: float, expected_delay: float) -> bool:
        if len(times) < 2:
            return False
        mean = statistics.mean(times)
        threshold = max(baseline_mean + expected_delay * 0.7, baseline_mean + 3 * baseline_stdev)
        return mean > threshold


class TimingBaseline:
    def __init__(self):
        self.samples: list[float] = []

    def add(self, t: float) -> None:
        self.samples.append(t)

    @property
    def mean(self) -> float:
        return statistics.mean(self.samples) if self.samples else 0.0

    @property
    def stdev(self) -> float:
        return statistics.pstdev(self.samples) if len(self.samples) > 1 else 0.0
