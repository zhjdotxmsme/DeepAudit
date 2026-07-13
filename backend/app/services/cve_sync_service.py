"""
CVE 同步服务
从 NVD、OSV 等外部漏洞库同步 CVE 数据到本地知识库
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update

from app.models.cve_knowledge import CVEKnowledge, CVESyncLog

logger = logging.getLogger(__name__)


class NVDClient:
    """NVD (National Vulnerability Database) API 客户端"""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # NVD API 速率限制: 建议 6 秒内不超过 1 个请求（无 API Key）
    # 有 API Key 时可以更快
    RATE_LIMIT_DELAY = 6.0

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._last_request_time = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(30.0, connect=10.0),
            )
        return self._client

    async def _rate_limited_request(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """带速率限制的请求"""
        import time

        # 确保符合速率限制
        elapsed = time.time() - self._last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            await asyncio.sleep(self.RATE_LIMIT_DELAY - elapsed)

        client = await self._get_client()
        try:
            response = await client.get(url, params=params)
            self._last_request_time = time.time()
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API HTTP error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"NVD API request failed: {e}")
            raise

    async def fetch_cves(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        results_per_page: int = 20,
        start_index: int = 0,
        keyword: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        获取 CVE 列表

        Args:
            start_date: 开始日期（包含）
            end_date: 结束日期（包含）
            results_per_page: 每页结果数（最大 2000）
            start_index: 起始索引
            keyword: 关键词搜索
            cvss_v3_severity: CVSS v3 严重程度过滤 (LOW, MEDIUM, HIGH, CRITICAL)
        """
        params: Dict[str, Any] = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index,
        }

        if start_date:
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if end_date:
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if keyword:
            params["keywordSearch"] = keyword
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity

        return await self._rate_limited_request(self.BASE_URL, params)

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


class OSVClient:
    """OSV (Open Source Vulnerabilities) API 客户端"""

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
            )
        return self._client

    async def query_vulnerabilities(
        self,
        ecosystem: str,
        package_name: str,
        version: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        查询特定包的漏洞

        Args:
            ecosystem: 包生态系统 (Maven, npm, PyPI, Go, etc.)
            package_name: 包名称
            version: 版本号（可选）
        """
        client = await self._get_client()
        url = f"{self.BASE_URL}/query"

        payload = {
            "package": {
                "ecosystem": ecosystem,
                "name": package_name,
            }
        }
        if version:
            payload["version"] = version

        try:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("vulns", [])
        except Exception as e:
            logger.error(f"OSV API request failed for {ecosystem}/{package_name}: {e}")
            return []

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


class CVESyncService:
    """CVE 同步服务"""

    def __init__(self, db: AsyncSession, nvd_api_key: Optional[str] = None):
        self.db = db
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.osv_client = OSVClient()

    async def sync_nvd(
        self,
        days_back: int = 30,
        max_results: int = 2000,
        severity_filter: Optional[str] = None,
    ) -> CVESyncLog:
        """
        从 NVD 同步 CVE 数据

        Args:
            days_back: 回溯天数
            max_results: 最大同步数量
            severity_filter: 严重程度过滤
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)

        sync_log = CVESyncLog(
            source="nvd",
            status="running",
            start_date=start_date,
            end_date=end_date,
        )
        self.db.add(sync_log)
        await self.db.flush()

        total_new = 0
        total_updated = 0
        total_failed = 0
        total_processed = 0

        try:
            start_index = 0
            results_per_page = min(2000, max_results)

            while total_processed < max_results:
                logger.info(f"Fetching NVD CVEs: startIndex={start_index}, resultsPerPage={results_per_page}")

                data = await self.nvd_client.fetch_cves(
                    start_date=start_date,
                    end_date=end_date,
                    results_per_page=results_per_page,
                    start_index=start_index,
                    cvss_v3_severity=severity_filter,
                )

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    try:
                        cve_data = vuln.get("cve", {})
                        cve_id = cve_data.get("id", "")

                        if not cve_id:
                            continue

                        # 解析描述
                        descriptions = cve_data.get("descriptions", [])
                        description = ""
                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")
                                break
                        if not description and descriptions:
                            description = descriptions[0].get("value", "")

                        # 解析 CVSS
                        metrics = cve_data.get("metrics", {})
                        cvss_score = None
                        severity = None

                        cvss_v31 = metrics.get("cvssMetricV31", [])
                        if cvss_v31:
                            cvss_data = cvss_v31[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        else:
                            cvss_v30 = metrics.get("cvssMetricV30", [])
                            if cvss_v30:
                                cvss_data = cvss_v30[0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore")
                                severity = cvss_data.get("baseSeverity", "UNKNOWN")

                        # 解析 CWE
                        weaknesses = cve_data.get("weaknesses", [])
                        cwe_ids = []
                        for weakness in weaknesses:
                            for desc in weakness.get("description", []):
                                if desc.get("lang") == "en":
                                    cwe_id = desc.get("value", "")
                                    if cwe_id.startswith("CWE-"):
                                        cwe_ids.append(cwe_id)

                        # 解析影响包
                        configurations = cve_data.get("configurations", [])
                        affected_packages = []
                        for config in configurations:
                            for node in config.get("nodes", []):
                                for cpe_match in node.get("cpeMatch", []):
                                    if cpe_match.get("vulnerable", False):
                                        criteria = cpe_match.get("criteria", "")
                                        # 解析 CPE: cpe:2.3:a:vendor:product:version...
                                        parts = criteria.split(":")
                                        if len(parts) >= 5:
                                            affected_packages.append({
                                                "cpe": criteria,
                                                "vendor": parts[3] if len(parts) > 3 else "",
                                                "product": parts[4] if len(parts) > 4 else "",
                                                "versionStart": cpe_match.get("versionStartExcluding"),
                                                "versionEnd": cpe_match.get("versionEndExcluding"),
                                            })

                        # 解析参考链接
                        references = []
                        for ref in cve_data.get("references", []):
                            ref_url = ref.get("url", "")
                            if ref_url:
                                references.append({
                                    "url": ref_url,
                                    "tags": ref.get("tags", []),
                                })

                        # 解析时间
                        published = cve_data.get("published")
                        modified = cve_data.get("lastModified")

                        # 检查是否已存在
                        result = await self.db.execute(
                            select(CVEKnowledge).where(CVEKnowledge.cve_id == cve_id)
                        )
                        existing = result.scalar_one_or_none()

                        if existing:
                            # 更新
                            existing.title = description[:200] if description else cve_id
                            existing.description = description
                            existing.cvss_score = cvss_score
                            existing.severity = severity
                            existing.affected_packages = affected_packages
                            existing.cwe_ids = cwe_ids
                            existing.references = references
                            existing.raw_data = cve_data
                            existing.modified_at = datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None
                            existing.sync_status = "active"
                            total_updated += 1
                        else:
                            # 新建
                            cve = CVEKnowledge(
                                cve_id=cve_id,
                                title=description[:200] if description else cve_id,
                                description=description,
                                cvss_score=cvss_score,
                                severity=severity,
                                affected_packages=affected_packages,
                                cwe_ids=cwe_ids,
                                references=references,
                                source="nvd",
                                raw_data=cve_data,
                                published_at=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
                                modified_at=datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None,
                                sync_status="active",
                                embedding_synced=0,
                            )
                            self.db.add(cve)
                            total_new += 1

                        total_processed += 1

                    except Exception as e:
                        logger.error(f"Failed to process CVE: {e}")
                        total_failed += 1

                # 分页
                start_index += results_per_page

                # 检查是否还有更多数据
                total_results = data.get("totalResults", 0)
                if start_index >= total_results or start_index >= max_results:
                    break

            await self.db.flush()

            sync_log.status = "success"
            sync_log.total_count = total_processed
            sync_log.new_count = total_new
            sync_log.updated_count = total_updated
            sync_log.failed_count = total_failed

            logger.info(
                f"NVD sync completed: {total_processed} processed, "
                f"{total_new} new, {total_updated} updated, {total_failed} failed"
            )

        except Exception as e:
            sync_log.status = "failed"
            sync_log.error_message = str(e)
            logger.error(f"NVD sync failed: {e}")

        await self.db.commit()
        return sync_log

    async def sync_osv_for_packages(
        self,
        packages: List[Dict[str, str]],
    ) -> CVESyncLog:
        """
        从 OSV 同步指定包的漏洞信息

        Args:
            packages: 包列表 [{"ecosystem": "Maven", "name": "spring-core", "version": "5.3.17"}]
        """
        sync_log = CVESyncLog(
            source="osv",
            status="running",
        )
        self.db.add(sync_log)
        await self.db.flush()

        total_new = 0
        total_updated = 0

        try:
            for pkg in packages:
                ecosystem = pkg.get("ecosystem", "")
                name = pkg.get("name", "")
                version = pkg.get("version")

                if not ecosystem or not name:
                    continue

                logger.info(f"Querying OSV for {ecosystem}/{name}@{version}")

                vulns = await self.osv_client.query_vulnerabilities(
                    ecosystem=ecosystem,
                    package_name=name,
                    version=version,
                )

                for vuln in vulns:
                    try:
                        vuln_id = vuln.get("id", "")
                        if not vuln_id:
                            continue

                        # OSV ID 可能是 GHSA-xxx 或 CVE-xxx
                        cve_id = vuln_id
                        aliases = vuln.get("aliases", [])
                        for alias in aliases:
                            if alias.startswith("CVE-"):
                                cve_id = alias
                                break

                        # 检查是否已存在
                        result = await self.db.execute(
                            select(CVEKnowledge).where(CVEKnowledge.cve_id == cve_id)
                        )
                        existing = result.scalar_one_or_none()

                        if existing:
                            # 合并 OSV 数据
                            existing.raw_data = {**existing.raw_data, "osv": vuln}
                            total_updated += 1
                        else:
                            # 新建
                            cve = CVEKnowledge(
                                cve_id=cve_id,
                                title=vuln.get("summary", cve_id),
                                description=vuln.get("details", ""),
                                severity=vuln.get("severity", [])
                                and vuln["severity"][0].get("type") or "UNKNOWN",
                                affected_packages=[{
                                    "ecosystem": ecosystem,
                                    "name": name,
                                    "version": version,
                                }],
                                source="osv",
                                raw_data=vuln,
                                published_at=datetime.fromisoformat(
                                    vuln.get("published", "").replace("Z", "+00:00")
                                ) if vuln.get("published") else None,
                                modified_at=datetime.fromisoformat(
                                    vuln.get("modified", "").replace("Z", "+00:00")
                                ) if vuln.get("modified") else None,
                                sync_status="active",
                                embedding_synced=0,
                            )
                            self.db.add(cve)
                            total_new += 1

                    except Exception as e:
                        logger.error(f"Failed to process OSV vuln: {e}")

                # OSV 没有严格速率限制，但适当延迟
                await asyncio.sleep(0.5)

            await self.db.flush()

            sync_log.status = "success"
            sync_log.total_count = total_new + total_updated
            sync_log.new_count = total_new
            sync_log.updated_count = total_updated

            logger.info(f"OSV sync completed: {total_new} new, {total_updated} updated")

        except Exception as e:
            sync_log.status = "failed"
            sync_log.error_message = str(e)
            logger.error(f"OSV sync failed: {e}")

        await self.db.commit()
        return sync_log

    async def get_cves_for_package(
        self,
        ecosystem: str,
        package_name: str,
        min_severity: Optional[str] = None,
    ) -> List[CVEKnowledge]:
        """
        获取影响特定包的所有 CVE

        Args:
            ecosystem: 包生态系统
            package_name: 包名称
            min_severity: 最小严重程度 (CRITICAL, HIGH, MEDIUM, LOW)
        """
        # 由于 affected_packages 是 JSON 列，这里使用简单查询
        # 实际生产环境可能需要更复杂的 JSON 查询或全文搜索
        result = await self.db.execute(
            select(CVEKnowledge).where(
                CVEKnowledge.affected_packages.contains([{
                    "ecosystem": ecosystem,
                    "name": package_name,
                }])
            )
        )
        cves = result.scalars().all()

        if min_severity:
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
            min_level = severity_order.get(min_severity.upper(), 0)
            cves = [
                cve for cve in cves
                if severity_order.get((cve.severity or "UNKNOWN").upper(), 0) >= min_level
            ]

        # 按 CVSS 分数排序
        cves = sorted(cves, key=lambda x: x.cvss_score or 0, reverse=True)
        return list(cves)

    async def close(self):
        await self.nvd_client.close()
        await self.osv_client.close()
