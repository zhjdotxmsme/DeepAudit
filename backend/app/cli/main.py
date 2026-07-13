"""DeepAudit CLI — ``deepaudit scan`` non-interactive entry point.

Designed for CI/CD:

* Non-interactive: all inputs come from flags or environment variables.
* Deterministic exit codes:
    * ``0`` — scan finished, no findings above threshold.
    * ``1`` — scan finished, findings above threshold.
    * ``2`` — configuration / network / server error.
* Machine-readable outputs: SARIF 2.1.0 file for GitHub Code Scanning.

Typical CI invocation::

    deepaudit scan \\
        --url https://deepaudit.example.com \\
        --token "$DEEPAUDIT_TOKEN" \\
        --project-id "$DEEPAUDIT_PROJECT_ID" \\
        --path . \\
        --wait \\
        --sarif-out deepaudit.sarif \\
        --fail-on high

Auth: pass ``--token`` (bearer) directly, or ``--email/--password`` to
login first. Credentials also read from environment variables
(``DEEPAUDIT_TOKEN``, ``DEEPAUDIT_EMAIL``, ``DEEPAUDIT_PASSWORD``).
"""

from __future__ import annotations

import io
import os
import sys
import time
import json
import zipfile
from pathlib import Path
from typing import Optional

import click
import httpx


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

DEFAULT_EXCLUDES = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".idea",
    ".vscode",
    "vendor",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    "coverage",
}

# Terminal task statuses returned by the DeepAudit backend.
TERMINAL_STATUSES = {"completed", "failed", "cancelled", "error"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _echo(msg: str, *, err: bool = False) -> None:
    """Log to stderr so stdout stays clean for machine-readable output."""
    click.echo(msg, err=err or True)


def _zip_source(root: Path, excludes: set[str]) -> bytes:
    """Zip a source directory in memory, honoring the exclude list.

    Excludes are matched as **path segments**, so ``node_modules`` will match
    any directory named ``node_modules`` at any depth.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune directories in-place so ``os.walk`` skips them entirely.
            dirnames[:] = [d for d in dirnames if d not in excludes]
            for filename in filenames:
                full = Path(dirpath) / filename
                try:
                    arcname = full.relative_to(root)
                except ValueError:
                    continue
                # Skip empty / oversized files silently.
                try:
                    if full.stat().st_size > 50 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                zf.write(full, arcname.as_posix())
    return buf.getvalue()


def _login(client: httpx.Client, email: str, password: str) -> str:
    """Exchange email/password for a bearer token."""
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if resp.status_code != 200:
        raise click.ClickException(
            f"Login failed ({resp.status_code}): {resp.text[:200]}"
        )
    token = resp.json().get("access_token")
    if not token:
        raise click.ClickException("Login response missing access_token")
    return token


def _upload_zip(
    client: httpx.Client,
    project_id: str,
    zip_bytes: bytes,
    scan_config: dict,
) -> str:
    """POST the zip to /api/v1/scan/upload-zip, return the created task_id."""
    files = {"file": ("deepaudit-cli.zip", zip_bytes, "application/zip")}
    data = {
        "project_id": project_id,
        "scan_config": json.dumps(scan_config),
    }
    resp = client.post("/api/v1/scan/upload-zip", data=data, files=files)
    if resp.status_code >= 400:
        raise click.ClickException(
            f"Upload failed ({resp.status_code}): {resp.text[:300]}"
        )
    body = resp.json()
    task_id = body.get("task_id")
    if not task_id:
        raise click.ClickException(f"Upload response missing task_id: {body}")
    return task_id


def _poll_task(
    client: httpx.Client,
    task_id: str,
    timeout: int,
    interval: int,
) -> dict:
    """Poll the task until it terminates or the timeout elapses."""
    deadline = time.time() + timeout
    last_status: Optional[str] = None
    while time.time() < deadline:
        resp = client.get(f"/api/v1/tasks/{task_id}")
        if resp.status_code >= 400:
            raise click.ClickException(
                f"Task poll failed ({resp.status_code}): {resp.text[:200]}"
            )
        task = resp.json()
        status = task.get("status")
        if status != last_status:
            _echo(f"[deepaudit] task {task_id[:8]} status={status}")
            last_status = status
        if status in TERMINAL_STATUSES:
            return task
        time.sleep(interval)
    raise click.ClickException(
        f"Timed out after {timeout}s waiting for task {task_id}"
    )


def _fetch_sarif(client: httpx.Client, task_id: str, dedupe: bool) -> dict:
    """Download the SARIF 2.1.0 export for a completed task."""
    resp = client.get(
        f"/api/v1/tasks/{task_id}/report/sarif",
        params={"dedupe": "true" if dedupe else "false"},
    )
    if resp.status_code >= 400:
        raise click.ClickException(
            f"SARIF export failed ({resp.status_code}): {resp.text[:200]}"
        )
    return resp.json()


def _worst_severity_from_sarif(sarif: dict) -> str:
    """Return the highest SARIF ``level`` observed, mapped back to severity.

    SARIF uses ``error / warning / note`` for levels; DeepAudit encodes the
    original severity in the rule's ``security-severity`` property. We look
    at both to derive the strongest signal.
    """
    worst = 0
    worst_name = "info"

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            # Priority 1: explicit ``properties.security-severity`` when present.
            props = result.get("properties") or {}
            sev = props.get("security-severity") or props.get("severity")
            if isinstance(sev, str):
                key = sev.lower()
                if key in SEVERITY_ORDER and SEVERITY_ORDER[key] > worst:
                    worst = SEVERITY_ORDER[key]
                    worst_name = key
                    continue

            # Priority 2: SARIF ``level`` mapped to a coarse severity.
            level = (result.get("level") or "warning").lower()
            level_map = {
                "error": ("high", 3),
                "warning": ("medium", 2),
                "note": ("low", 1),
                "none": ("info", 0),
            }
            name, score = level_map.get(level, ("medium", 2))
            if score > worst:
                worst = score
                worst_name = name

    return worst_name


# ---------------------------------------------------------------------------
# Click commands
# ---------------------------------------------------------------------------

@click.group(help="DeepAudit CLI — code security audit for CI/CD pipelines.")
@click.version_option(package_name="deepaudit-backend", prog_name="deepaudit")
def cli() -> None:
    pass


@cli.command(
    "scan",
    help="Upload a source tree, run an audit, and export findings as SARIF.",
)
@click.option(
    "--url",
    envvar="DEEPAUDIT_URL",
    required=True,
    help="Base URL of the DeepAudit server, e.g. https://deepaudit.example.com",
)
@click.option(
    "--token",
    envvar="DEEPAUDIT_TOKEN",
    help="Bearer token. If omitted, --email/--password are used to login.",
)
@click.option("--email", envvar="DEEPAUDIT_EMAIL", help="Login email.")
@click.option("--password", envvar="DEEPAUDIT_PASSWORD", help="Login password.")
@click.option(
    "--project-id",
    envvar="DEEPAUDIT_PROJECT_ID",
    required=True,
    help="Target project ID on the DeepAudit server.",
)
@click.option(
    "--path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
    help="Directory to scan (will be zipped and uploaded).",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Extra directory names to exclude (repeatable).",
)
@click.option(
    "--rule-set-id",
    envvar="DEEPAUDIT_RULE_SET_ID",
    help="Audit rule set ID to apply.",
)
@click.option(
    "--prompt-template-id",
    envvar="DEEPAUDIT_PROMPT_TEMPLATE_ID",
    help="Prompt template ID to apply.",
)
@click.option(
    "--diff-files",
    multiple=True,
    help="Limit scan to these file paths (repeatable). Supply the git-diff "
    "file list from your CI runner for a fast PR-only scan.",
)
@click.option(
    "--wait/--no-wait",
    default=True,
    show_default=True,
    help="Block until the audit completes.",
)
@click.option(
    "--timeout",
    type=int,
    default=1800,
    show_default=True,
    help="Max seconds to wait for the audit to finish.",
)
@click.option(
    "--poll-interval",
    type=int,
    default=5,
    show_default=True,
    help="Seconds between task status polls.",
)
@click.option(
    "--sarif-out",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write SARIF 2.1.0 report to this path.",
)
@click.option(
    "--dedupe/--no-dedupe",
    default=True,
    show_default=True,
    help="Collapse duplicate findings via fingerprint before export.",
)
@click.option(
    "--fail-on",
    type=click.Choice(list(SEVERITY_ORDER.keys()), case_sensitive=False),
    default="high",
    show_default=True,
    help="Exit with code 1 when any finding meets or exceeds this severity.",
)
@click.option(
    "--verify-ssl/--no-verify-ssl",
    default=True,
    show_default=True,
    help="Verify TLS certificate of the server.",
)
def scan(
    url: str,
    token: Optional[str],
    email: Optional[str],
    password: Optional[str],
    project_id: str,
    path: Path,
    exclude: tuple[str, ...],
    rule_set_id: Optional[str],
    prompt_template_id: Optional[str],
    diff_files: tuple[str, ...],
    wait: bool,
    timeout: int,
    poll_interval: int,
    sarif_out: Optional[Path],
    dedupe: bool,
    fail_on: str,
    verify_ssl: bool,
) -> None:
    """Run a DeepAudit scan and enforce a severity gate for CI."""
    base_url = url.rstrip("/")

    with httpx.Client(
        base_url=base_url,
        timeout=httpx.Timeout(60.0, connect=10.0),
        verify=verify_ssl,
    ) as client:
        # ---- auth ------------------------------------------------------
        if not token:
            if not (email and password):
                raise click.ClickException(
                    "Provide --token or both --email and --password "
                    "(also readable from DEEPAUDIT_TOKEN / DEEPAUDIT_EMAIL "
                    "/ DEEPAUDIT_PASSWORD)."
                )
            token = _login(client, email, password)
        client.headers["Authorization"] = f"Bearer {token}"

        # ---- package source -------------------------------------------
        excludes = DEFAULT_EXCLUDES | set(exclude)
        _echo(f"[deepaudit] zipping {path.resolve()} (excludes: {len(excludes)})")
        zip_bytes = _zip_source(path, excludes)
        _echo(f"[deepaudit] uploading {len(zip_bytes) / 1024:.1f} KiB")

        scan_config = {
            "full_scan": True,
            "exclude_patterns": [],
            "rule_set_id": rule_set_id,
            "prompt_template_id": prompt_template_id,
        }
        if diff_files:
            scan_config["file_paths"] = list(diff_files)
            scan_config["full_scan"] = False

        # ---- upload + poll --------------------------------------------
        task_id = _upload_zip(client, project_id, zip_bytes, scan_config)
        _echo(f"[deepaudit] task queued: {task_id}")

        if not wait:
            _echo("[deepaudit] --no-wait: not polling. exit=0")
            sys.exit(0)

        task = _poll_task(client, task_id, timeout, poll_interval)
        status = task.get("status")
        if status != "completed":
            raise click.ClickException(
                f"Task {task_id} finished with status={status}"
            )

        # ---- fetch SARIF ----------------------------------------------
        sarif = _fetch_sarif(client, task_id, dedupe=dedupe)
        if sarif_out:
            sarif_out.parent.mkdir(parents=True, exist_ok=True)
            sarif_out.write_text(
                json.dumps(sarif, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            _echo(f"[deepaudit] wrote SARIF: {sarif_out}")

        # ---- severity gate --------------------------------------------
        worst = _worst_severity_from_sarif(sarif)
        threshold = SEVERITY_ORDER[fail_on.lower()]
        worst_score = SEVERITY_ORDER.get(worst, 0)
        _echo(
            f"[deepaudit] worst-finding={worst} "
            f"threshold=--fail-on={fail_on}"
        )
        if worst_score >= threshold:
            _echo(
                f"[deepaudit] FAIL: findings at or above '{fail_on}' present."
            )
            sys.exit(1)
        _echo("[deepaudit] PASS: no findings above threshold.")
        sys.exit(0)


def main() -> None:
    """Console-script entry point."""
    try:
        cli(standalone_mode=False)
    except click.ClickException as exc:
        exc.show()
        sys.exit(2)
    except click.Abort:
        _echo("[deepaudit] aborted")
        sys.exit(2)
    except Exception as exc:  # pragma: no cover - defensive
        _echo(f"[deepaudit] unexpected error: {exc}")
        sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    main()
