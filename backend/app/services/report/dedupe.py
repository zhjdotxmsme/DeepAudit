"""Finding deduplication engine.

DeepAudit runs multiple detectors (regex patterns, Semgrep, agents, RAG)
against the same codebase, so the same vulnerability is often reported
multiple times with slightly different wording or line offsets. This module
folds duplicate findings into a single deduplicated finding using a stable
fingerprint.

Fingerprint components (in order of decreasing importance):

1. ``issue_type`` (normalized) — same vulnerability class
2. ``file_path`` (normalized) — same file
3. Normalized code fingerprint — a hash of the trimmed, whitespace-collapsed
   code snippet. If the snippet is missing we fall back to a ``(line // 3)``
   bucket so findings within a 3-line window are considered duplicates.
4. ``sink`` marker — the AST-relevant function/method name extracted from the
   code snippet when possible (e.g. ``exec``, ``os.system``, ``eval``).

Inspired by ``strix/report/dedupe.py`` but rewritten to fit the DeepAudit
``AuditIssue`` shape.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Ordered severity used to keep the "worst" finding when merging.
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Common sink patterns. Findings sharing the same sink+file are almost always
# duplicates even if line numbers drift due to code formatting.
_SINK_PATTERN = re.compile(
    r"\b("
    r"eval|exec|system|popen|subprocess\.[A-Za-z_]+|os\.system|"
    r"Runtime\.getRuntime|ProcessBuilder|"
    r"createQuery|createNativeQuery|executeQuery|executeUpdate|"
    r"innerHTML|outerHTML|document\.write|v-html|dangerouslySetInnerHTML|"
    r"pickle\.loads|yaml\.load|ObjectInputStream|readObject|"
    r"parseExpression|SpelExpression|"
    r"redirect|sendRedirect|forward|"
    r"open\(|readfile|file_get_contents|include|require"
    r")\b"
)

_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class Fingerprint:
    """Stable identity of a finding, used as a dict key."""

    issue_type: str
    file_path: str
    sink: str
    code_hash: str
    line_bucket: int

    def as_str(self) -> str:
        return "|".join(
            [
                self.issue_type,
                self.file_path,
                self.sink,
                self.code_hash,
                str(self.line_bucket),
            ]
        )


@dataclass
class DedupeStats:
    input_count: int = 0
    output_count: int = 0
    duplicates_merged: int = 0
    fingerprints: Dict[str, int] = field(default_factory=dict)


class FindingDeduplicator:
    """Merge duplicate findings using stable fingerprints.

    Usage::

        deduper = FindingDeduplicator()
        unique, stats = deduper.dedupe(findings)

    Findings may be ORM instances or plain dicts. Merging preserves the
    highest severity, aggregates alternate ``ai_explanation`` values into a
    ``duplicates`` count on the merged finding, and keeps the smallest
    ``line_number`` seen for that fingerprint.
    """

    def __init__(self, *, line_window: int = 3) -> None:
        # Group lines into buckets of this many lines so slight offsets from
        # different detectors still collide onto the same fingerprint.
        self.line_window = max(1, int(line_window))

    # ---------------- public ----------------

    def fingerprint(self, finding: Any) -> Fingerprint:
        issue_type = (_get(finding, "issue_type") or "unknown").strip().lower()
        file_path = _normalize_path(_get(finding, "file_path") or "")
        line = _safe_int(_get(finding, "line_number")) or 0
        code_snippet = _get(finding, "code_snippet") or ""

        code_hash = _hash_snippet(code_snippet)
        sink = _extract_sink(code_snippet)
        line_bucket = line // self.line_window if code_hash == _EMPTY_HASH else 0

        return Fingerprint(
            issue_type=issue_type,
            file_path=file_path,
            sink=sink,
            code_hash=code_hash,
            line_bucket=line_bucket,
        )

    def dedupe(
        self, findings: Iterable[Any]
    ) -> Tuple[List[Any], DedupeStats]:
        """Return (unique_findings, stats).

        Unique findings are returned in first-seen order. ORM instances are
        preserved as-is (we mutate ``ai_explanation`` on the merged one). Dicts
        get a ``duplicates`` counter merged in.
        """
        stats = DedupeStats()
        seen: Dict[str, Any] = {}

        for f in findings:
            stats.input_count += 1
            fp = self.fingerprint(f).as_str()
            stats.fingerprints[fp] = stats.fingerprints.get(fp, 0) + 1
            if fp in seen:
                stats.duplicates_merged += 1
                seen[fp] = self._merge(seen[fp], f)
            else:
                seen[fp] = f

        unique = list(seen.values())
        stats.output_count = len(unique)
        return unique, stats

    # ---------------- internals ----------------

    def _merge(self, keep: Any, other: Any) -> Any:
        """Merge ``other`` into ``keep``, returning the survivor.

        We prefer the finding with higher severity. Ties broken by keeping
        ``keep``. On dicts we also increment a ``duplicates`` counter.
        """
        keep_sev = _sev_rank(_get(keep, "severity"))
        other_sev = _sev_rank(_get(other, "severity"))
        winner = keep if keep_sev >= other_sev else other
        loser = other if winner is keep else keep

        # For dicts only, expose merge metadata to callers.
        if isinstance(winner, dict):
            winner.setdefault("duplicates", 1)
            winner["duplicates"] += 1
            merged_ids = winner.setdefault("_merged_ids", [])
            for candidate in (keep, loser):
                cid = _get(candidate, "id")
                if cid and cid not in merged_ids:
                    merged_ids.append(cid)

        # Keep the smallest positive line_number seen (earliest occurrence).
        keep_line = _safe_int(_get(winner, "line_number"))
        loser_line = _safe_int(_get(loser, "line_number"))
        if isinstance(winner, dict):
            if loser_line and (not keep_line or loser_line < keep_line):
                winner["line_number"] = loser_line

        return winner


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_EMPTY_HASH = hashlib.sha1(b"").hexdigest()[:12]


def _hash_snippet(snippet: str) -> str:
    if not snippet:
        return _EMPTY_HASH
    text = _WHITESPACE_RE.sub(" ", str(snippet)).strip()
    if not text:
        return _EMPTY_HASH
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def _extract_sink(snippet: str) -> str:
    if not snippet:
        return ""
    m = _SINK_PATTERN.search(str(snippet))
    return m.group(1) if m else ""


def _normalize_path(path: str) -> str:
    return str(path).replace("\\", "/").strip()


def _safe_int(value: Any) -> Optional[int]:
    try:
        v = int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
    return v if v and v > 0 else None


def _sev_rank(sev: Optional[str]) -> int:
    if not sev:
        return 0
    return _SEVERITY_ORDER.get(str(sev).lower(), 0)


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


__all__ = ["FindingDeduplicator", "Fingerprint", "DedupeStats"]
