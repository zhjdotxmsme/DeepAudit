"""Report export & post-processing services.

- sarif_exporter: convert AuditIssue -> SARIF 2.1.0 (GitHub Security / SonarQube compatible)
- dedupe: fingerprint-based finding deduplication
"""

from app.services.report.sarif_exporter import SARIFExporter
from app.services.report.dedupe import FindingDeduplicator, Fingerprint

__all__ = ["SARIFExporter", "FindingDeduplicator", "Fingerprint"]
