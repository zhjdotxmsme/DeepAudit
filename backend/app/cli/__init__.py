"""DeepAudit CLI — Non-interactive scan client for CI/CD pipelines.

Entry point: ``deepaudit`` (see ``[project.scripts]`` in pyproject.toml).

The CLI is a **thin HTTP client** against a running DeepAudit backend. It
zips the target directory, uploads it, polls task status, downloads the
SARIF report, and exits with a non-zero status when findings exceed the
``--fail-on`` severity threshold — the contract every CI/CD pipeline
expects.
"""

from app.cli.main import main

__all__ = ["main"]
