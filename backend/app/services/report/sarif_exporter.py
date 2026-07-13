"""SARIF 2.1.0 Exporter for DeepAudit findings.

Converts AuditIssue rows into a SARIF v2.1.0 document. The output can be
uploaded directly to GitHub Code Scanning, GitLab SAST, SonarQube, DefectDojo,
Azure DevOps Advanced Security, etc.

Reference:
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
  https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

Design notes:
  * DeepAudit's ``AuditIssue`` has no explicit CWE column, so we derive a rule id
    from ``issue_type`` (e.g. ``sql_injection`` -> ``DA-SQL-INJECTION``) and map
    the common issue types to CWE numbers when a mapping exists. Anything
    unmapped simply omits the ``taxa`` field.
  * ``severity`` (critical/high/medium/low) is mapped to both SARIF ``level``
    (error/warning/note) and the optional ``security-severity`` property expected
    by GitHub Code Scanning (numeric 0.0-10.0).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "DeepAudit"
TOOL_ORG = "DeepAudit"
TOOL_INFO_URI = "https://github.com/usestrix/strix"  # placeholder; overridable


# ---------------------------------------------------------------------------
# Severity / CWE mappings
# ---------------------------------------------------------------------------

# SARIF `level` values: none, note, warning, error
_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub Code Scanning uses `security-severity` (CVSS-style numeric string).
_SEVERITY_TO_SECURITY_SCORE: Dict[str, str] = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}

# Minimal issue_type -> CWE mapping. Extend as new rule categories appear.
_ISSUE_TYPE_TO_CWE: Dict[str, int] = {
    "sql_injection": 89,
    "xss": 79,
    "command_injection": 78,
    "code_injection": 94,
    "path_traversal": 22,
    "ldap_injection": 90,
    "ssrf": 918,
    "insecure_deserialization": 502,
    "deserialization": 502,
    "open_redirect": 601,
    "xxe": 611,
    "csrf": 352,
    "auth_bypass": 287,
    "auth": 287,
    "broken_authentication": 287,
    "broken_access_control": 284,
    "hardcoded_secret": 798,
    "hardcoded_credentials": 798,
    "weak_crypto": 327,
    "crypto": 327,
    "race_condition": 362,
    "business_logic": 840,
    # SpringBoot specific (from init_templates.py SB001-SB008)
    "spel_injection": 917,
    "actuator_exposure": 200,
    "mass_assignment": 915,
    "jpa_injection": 89,
    "cors_misconfig": 942,
    "jndi_injection": 917,
    # Frontend specific (FE001-FE008)
    "v_html_xss": 79,
    "route_guard_bypass": 862,
    "token_storage": 922,
    "env_leak": 200,
    "eval_injection": 95,
    "clickjacking": 1021,
    "csp_missing": 693,
    "sri_missing": 353,
}


def _issue_type_to_rule_id(issue_type: str) -> str:
    """Normalize an issue_type into a stable SARIF ``ruleId``.

    Examples:
      ``sql_injection`` -> ``DA-SQL-INJECTION``
      ``V-Html-Xss``    -> ``DA-V-HTML-XSS``
    """
    slug = (issue_type or "unknown").strip().replace(" ", "_")
    slug = slug.replace(".", "_").upper()
    slug = slug.replace("_", "-")
    return f"DA-{slug}"


def _issue_type_to_cwe(issue_type: str) -> Optional[int]:
    if not issue_type:
        return None
    return _ISSUE_TYPE_TO_CWE.get(issue_type.strip().lower())


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _RuleKey:
    rule_id: str
    issue_type: str
    cwe: Optional[int]


class SARIFExporter:
    """Convert DeepAudit findings into SARIF 2.1.0 documents.

    Input findings may be ORM ``AuditIssue`` instances or plain dicts sharing
    the same field names. The exporter is intentionally tolerant of missing
    fields so it can be reused by the smart-scan tool, agent tools and the
    HTTP API without adaptation glue.
    """

    def __init__(
        self,
        tool_name: str = TOOL_NAME,
        tool_version: str = "3.0.4",
        information_uri: str = TOOL_INFO_URI,
    ) -> None:
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.information_uri = information_uri

    # ---------------- public API ----------------

    def export(
        self,
        findings: Iterable[Any],
        *,
        repo_uri: Optional[str] = None,
        commit_sha: Optional[str] = None,
        base_dir: Optional[str] = None,
        run_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a full SARIF log dict.

        ``repo_uri`` / ``commit_sha`` populate the ``versionControlProvenance``
        block that GitHub uses to attach findings to a specific commit.
        ``base_dir`` is prepended to relative file paths as a ``srcroot``
        original URI base.  ``run_metadata`` is attached under
        ``run.properties`` for round-trip context (task id, project, dedupe
        stats, etc.).
        """
        findings_list = list(findings)
        rules_by_id: Dict[str, _RuleKey] = {}
        results: List[Dict[str, Any]] = []

        for f in findings_list:
            issue_type = _get(f, "issue_type") or "unknown"
            rule_id = _issue_type_to_rule_id(issue_type)
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = _RuleKey(
                    rule_id=rule_id,
                    issue_type=issue_type,
                    cwe=_issue_type_to_cwe(issue_type),
                )
            results.append(self._finding_to_result(f, rule_id))

        run: Dict[str, Any] = {
            "tool": self._build_tool(rules_by_id.values()),
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
            ],
        }

        if base_dir:
            run["originalUriBaseIds"] = {
                "SRCROOT": {"uri": self._as_uri(base_dir)},
            }

        if repo_uri or commit_sha:
            provenance: Dict[str, Any] = {}
            if repo_uri:
                provenance["repositoryUri"] = repo_uri
            if commit_sha:
                provenance["revisionId"] = commit_sha
            run["versionControlProvenance"] = [provenance]

        # Attach a CWE taxonomy referencing MITRE for downstream tooling.
        taxonomies = self._build_taxonomies(rules_by_id.values())
        if taxonomies:
            run["taxonomies"] = taxonomies

        if run_metadata:
            run["properties"] = {
                k: v for k, v in run_metadata.items() if v is not None
            }

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run],
        }

    def export_json(self, findings: Iterable[Any], **kwargs: Any) -> str:
        """Return SARIF JSON as a UTF-8 string, pretty-printed."""
        return json.dumps(
            self.export(findings, **kwargs),
            indent=2,
            ensure_ascii=False,
        )

    def export_bytes(self, findings: Iterable[Any], **kwargs: Any) -> bytes:
        """Return SARIF JSON encoded as UTF-8 bytes (suitable for HTTP download)."""
        return self.export_json(findings, **kwargs).encode("utf-8")

    # ---------------- internals ----------------

    def _build_tool(self, rules: Iterable[_RuleKey]) -> Dict[str, Any]:
        rule_objs: List[Dict[str, Any]] = []
        for rk in rules:
            rule_obj: Dict[str, Any] = {
                "id": rk.rule_id,
                "name": _humanize(rk.issue_type),
                "shortDescription": {
                    "text": f"DeepAudit rule: {_humanize(rk.issue_type)}"
                },
                "fullDescription": {
                    "text": (
                        f"Automatically generated rule for issue_type "
                        f"'{rk.issue_type}'. Findings are produced by "
                        "DeepAudit Multi-Agent audit pipeline."
                    ),
                },
                "helpUri": self.information_uri,
                "defaultConfiguration": {"level": "warning"},
                "properties": {
                    "issue_type": rk.issue_type,
                    "tags": ["security", "deepaudit"],
                },
            }
            if rk.cwe is not None:
                rule_obj["relationships"] = [
                    {
                        "target": {
                            "id": f"CWE-{rk.cwe}",
                            "toolComponent": {"name": "CWE"},
                        },
                        "kinds": ["superset"],
                    }
                ]
                rule_obj["properties"]["cwe"] = f"CWE-{rk.cwe}"
                rule_obj["properties"]["tags"].append(f"external/cwe/cwe-{rk.cwe}")
            rule_objs.append(rule_obj)

        return {
            "driver": {
                "name": self.tool_name,
                "organization": TOOL_ORG,
                "version": self.tool_version,
                "informationUri": self.information_uri,
                "rules": rule_objs,
            }
        }

    def _build_taxonomies(self, rules: Iterable[_RuleKey]) -> List[Dict[str, Any]]:
        cwe_ids = sorted({rk.cwe for rk in rules if rk.cwe is not None})
        if not cwe_ids:
            return []
        return [
            {
                "name": "CWE",
                "organization": "MITRE",
                "shortDescription": {"text": "Common Weakness Enumeration"},
                "informationUri": "https://cwe.mitre.org/",
                "isComprehensive": False,
                "taxa": [
                    {
                        "id": f"CWE-{cwe}",
                        "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
                    }
                    for cwe in cwe_ids
                ],
            }
        ]

    def _finding_to_result(self, f: Any, rule_id: str) -> Dict[str, Any]:
        severity = (_get(f, "severity") or "medium").lower()
        level = _SEVERITY_TO_LEVEL.get(severity, "warning")

        title = _get(f, "title") or _get(f, "message") or "Unnamed finding"
        description = _get(f, "description") or title
        suggestion = _get(f, "suggestion")
        code_snippet = _get(f, "code_snippet")
        file_path = _get(f, "file_path") or ""
        line = _get(f, "line_number")
        column = _get(f, "column_number")

        message_parts = [str(description)]
        if suggestion:
            message_parts.append(f"\n\nSuggestion: {suggestion}")
        message_text = "".join(message_parts)

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "properties": {
                "severity": severity,
                "security-severity": _SEVERITY_TO_SECURITY_SCORE.get(severity, "5.5"),
                "issue_type": _get(f, "issue_type") or "unknown",
            },
        }

        finding_id = _get(f, "id")
        if finding_id:
            # Stable partial fingerprint keyed off primary DB id.
            result["partialFingerprints"] = {"deepauditId/v1": str(finding_id)}

        # Location block. SARIF requires artifactLocation.uri.
        location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": _sanitize_path(file_path),
                    "uriBaseId": "SRCROOT",
                },
            }
        }
        region: Dict[str, Any] = {}
        if isinstance(line, int) and line > 0:
            region["startLine"] = line
        if isinstance(column, int) and column > 0:
            region["startColumn"] = column
        if code_snippet:
            region["snippet"] = {"text": str(code_snippet)}
        if region:
            location["physicalLocation"]["region"] = region
        result["locations"] = [location]

        return result

    @staticmethod
    def _as_uri(path: str) -> str:
        p = path.replace("\\", "/")
        if not p.endswith("/"):
            p += "/"
        if p.startswith("/"):
            return f"file://{p}"
        return p


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _humanize(issue_type: str) -> str:
    if not issue_type:
        return "Unknown"
    return " ".join(part.capitalize() for part in issue_type.replace("-", "_").split("_"))


def _sanitize_path(path: str) -> str:
    """Normalize a file path for SARIF `artifactLocation.uri`.

    SARIF requires forward slashes and expects paths relative to a ``uriBaseId``
    (here ``SRCROOT``). Absolute paths are kept as-is so downstream tooling can
    still resolve them.
    """
    if not path:
        return ""
    return path.replace("\\", "/")


__all__ = ["SARIFExporter"]
