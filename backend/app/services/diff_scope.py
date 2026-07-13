"""Git-diff scope filter for incremental scanning.

When a scan is triggered by a Pull Request or CI job we only want to
audit the files that actually changed. Running the full pipeline against a
2000-file repo when a PR only touches 4 files is wasteful and slow — Strix
solves this with a ``--scope-mode diff --diff-base origin/main`` flag; this
module is the DeepAudit-side equivalent.

The filter is intentionally standalone (no ORM / no FastAPI deps) so it can be
imported by the scanner, agent tools and CLI without pulling the app graph.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)

# Statuses returned by `git diff --name-status`. We keep A/M/R (added, modified,
# renamed). Deletions (D) and unmerged (U) are skipped — there is no file to
# audit for a deletion, and unmerged files are transient.
_KEEP_STATUSES = {"A", "M", "R", "C", "T"}


@dataclass
class DiffScopeResult:
    changed_files: List[str] = field(default_factory=list)
    base_ref: str = ""
    head_ref: str = ""
    error: Optional[str] = None

    @property
    def is_empty(self) -> bool:
        return not self.changed_files

    def matches(self, path: str) -> bool:
        """Return True if the given path should be scanned."""
        if not self.changed_files:
            return False
        norm = _norm(path)
        return any(norm == cf or norm.endswith("/" + cf) for cf in self.changed_files)


class DiffScopeFilter:
    """Compute the list of changed files between two git refs.

    Example::

        flt = DiffScopeFilter(repo_dir)
        result = flt.compute(base_ref="origin/main", head_ref="HEAD")
        if not result.is_empty:
            files = [p for p in all_files if result.matches(p)]
    """

    def __init__(
        self,
        repo_dir: str | os.PathLike[str],
        *,
        extra_include_patterns: Optional[Sequence[str]] = None,
        timeout: int = 30,
    ) -> None:
        self.repo_dir = Path(repo_dir)
        self.extra_include_patterns = list(extra_include_patterns or [])
        self.timeout = timeout

    # ---------------- public ----------------

    def is_git_repo(self) -> bool:
        return (self.repo_dir / ".git").exists() or self._run_git_ok(["rev-parse", "--git-dir"])

    def compute(
        self,
        *,
        base_ref: str = "origin/main",
        head_ref: str = "HEAD",
    ) -> DiffScopeResult:
        """Compute changed files between ``base_ref`` and ``head_ref``.

        Both refs are passed as-is to git; we do not attempt to resolve merge
        bases here because the caller usually already knows the desired base
        (e.g. the PR target branch).

        On any git failure we return a ``DiffScopeResult`` with ``error`` set
        so the caller can decide whether to fall back to a full scan.
        """
        if not self.is_git_repo():
            return DiffScopeResult(
                base_ref=base_ref,
                head_ref=head_ref,
                error=f"not a git repository: {self.repo_dir}",
            )

        # Ensure the base ref is reachable (works in shallow clones commonly
        # produced by CI checkouts).
        self._fetch_ref_if_needed(base_ref)

        proc = self._run_git(
            [
                "diff",
                "--name-status",
                "-M",  # rename detection
                "--no-renames",  # emit A/D pairs for renames — simpler to parse
                f"{base_ref}...{head_ref}",
            ]
        )
        if proc.returncode != 0:
            return DiffScopeResult(
                base_ref=base_ref,
                head_ref=head_ref,
                error=proc.stderr.strip() or "git diff failed",
            )

        changed: List[str] = []
        for raw_line in proc.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            status, path = parts[0].strip(), parts[-1].strip()
            # Rename lines produce statuses like "R100" — keep the letter only.
            status_letter = status[:1]
            if status_letter not in _KEEP_STATUSES:
                continue
            changed.append(_norm(path))

        return DiffScopeResult(
            changed_files=changed,
            base_ref=base_ref,
            head_ref=head_ref,
        )

    def filter_paths(
        self,
        candidate_paths: Iterable[str],
        result: DiffScopeResult,
    ) -> List[str]:
        """Keep only paths that appear in ``result.changed_files``.

        If the diff result is empty (nothing changed or error) we return an
        empty list — the caller decides whether to fall back to a full scan.
        """
        if result.is_empty:
            return []
        changed_set: Set[str] = set(result.changed_files)
        out: List[str] = []
        for p in candidate_paths:
            n = _norm(p)
            if n in changed_set or any(n.endswith("/" + cf) for cf in changed_set):
                out.append(p)
        return out

    # ---------------- internals ----------------

    def _run_git(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        cmd = ["git", "-C", str(self.repo_dir), *args]
        logger.debug("diff-scope: running %s", " ".join(cmd))
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr=str(e),
            )

    def _run_git_ok(self, args: Sequence[str]) -> bool:
        return self._run_git(args).returncode == 0

    def _fetch_ref_if_needed(self, ref: str) -> None:
        """Best-effort fetch of ``ref`` (e.g. ``origin/main``) for shallow clones."""
        # Only bother when the ref points to a remote-tracking branch.
        if "/" not in ref:
            return
        remote, _, branch = ref.partition("/")
        if not remote or not branch:
            return
        # Skip if ref already resolvable.
        if self._run_git_ok(["rev-parse", "--verify", ref]):
            return
        self._run_git(["fetch", "--depth=1", remote, branch])


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _norm(path: str) -> str:
    return str(path).replace("\\", "/").strip().lstrip("./")


__all__ = ["DiffScopeFilter", "DiffScopeResult"]
