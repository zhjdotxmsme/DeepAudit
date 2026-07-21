"""
CVE 同步服务
从 NVD、OSV 等外部漏洞库同步 CVE 数据到本地知识库
"""

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, AsyncIterator

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update

from app.models.cve_knowledge import CVEKnowledge, CVESyncLog

try:
    from app.core.config import settings as _settings
except Exception:  # pragma: no cover - 允许无 settings 时使用默认值
    _settings = None

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

    async def fetch_modified_ids(
        self, ecosystem: str
    ) -> List[Dict[str, str]]:
        """
        获取指定生态系统的 modified_id.csv

        Args:
            ecosystem: OSV 生态系统名称 (Maven, npm, PyPI, Go, NuGet, crates.io, RubyGems, Packagist)

        Returns:
            List of {"id": str, "modified_time": str} sorted by modified_time descending
        """
        client = await self._get_client()
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/modified_id.csv"

        try:
            response = await client.get(url)
            response.raise_for_status()
            lines = response.text.strip().split("\n")
            result = []
            for line in lines:
                if not line.strip():
                    continue
                # CSV format: id,modified_time (no header, ISO 8601 timestamps)
                parts = line.split(",", 1)
                if len(parts) == 2:
                    result.append({
                        "id": parts[0].strip(),
                        "modified_time": parts[1].strip(),
                    })
            # Sort by modified_time descending (newest first)
            result.sort(key=lambda x: x["modified_time"], reverse=True)
            return result
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"No modified_id.csv found for ecosystem: {ecosystem}")
                return []
            logger.error(f"OSV storage HTTP error for {ecosystem}: {e.response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Failed to fetch modified_ids for {ecosystem}: {e}")
            return []

    async def query_batch(
        self, vuln_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """
        批量查询漏洞详情

        Args:
            vuln_ids: 漏洞 ID 列表（最多 1000 条）

        Returns:
            漏洞详情列表
        """
        if not vuln_ids:
            return []

        client = await self._get_client()
        url = f"{self.BASE_URL}/querybatch"

        payload = {"queries": [{"id": vid} for vid in vuln_ids]}

        try:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("vulns", [])
        except Exception as e:
            logger.error(f"OSV querybatch failed: {e}")
            return []

    async def get_vuln_detail(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        获取单个漏洞详情

        Args:
            vuln_id: 漏洞 ID

        Returns:
            漏洞详情字典，未找到返回 None
        """
        client = await self._get_client()
        url = f"{self.BASE_URL}/vulns/{vuln_id}"

        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"Vulnerability not found: {vuln_id}")
                return None
            logger.error(f"OSV vulns HTTP error for {vuln_id}: {e.response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Failed to get vuln detail for {vuln_id}: {e}")
            return None

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


class CVEProjectV5Client:
    """CVEProject cvelistV5 本地 Git 镜像客户端

    支持通过 settings.CVELIST_V5_GIT_REPO 配置 GitHub 镜像地址（如 kkgithub / gitclone / ghproxy），
    以便在国内网络受限或 NVD/OSV API 拉不动时，通过 git 直接拉取官方 CVE JSON 仓库作为兜底数据源。
    """

    # 默认地址（可被 settings.CVELIST_V5_GIT_REPO 覆盖）
    DEFAULT_GIT_REPO = "https://github.com/CVEProject/cvelistV5.git"
    CVE_FILE_PATTERN = re.compile(r"^cves/\d{4}/.+/CVE-\d{4}-\d+\.json$")

    def __init__(
        self,
        mirror_path: Optional[str] = None,
        git_repo: Optional[str] = None,
        clone_depth: Optional[int] = None,
    ):
        # 优先级：显式参数 > settings > 默认
        resolved_repo = git_repo or getattr(_settings, "CVELIST_V5_GIT_REPO", None) or self.DEFAULT_GIT_REPO
        resolved_path = mirror_path or getattr(_settings, "CVELIST_V5_MIRROR_PATH", None) or "data/cvelist-v5/"
        resolved_depth = clone_depth if clone_depth is not None else getattr(_settings, "CVELIST_V5_CLONE_DEPTH", 1)

        self.GIT_REPO = resolved_repo
        self.clone_depth = max(1, int(resolved_depth or 1))

        # Resolve relative path from project root (backend/app/services/ → project root)
        project_root = Path(__file__).resolve().parent.parent.parent
        self.mirror_path = str((project_root / resolved_path).resolve())
        self._client: Optional[httpx.AsyncClient] = None

        logger.info(
            f"CVEProjectV5Client init: repo={self.GIT_REPO} depth={self.clone_depth} "
            f"mirror={self.mirror_path}"
        )

    async def _check_git_installed(self) -> bool:
        """Check if git is available"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except FileNotFoundError:
            return False

    async def _init_mirror(self) -> str:
        """
        Clone or pull the mirror. Returns current HEAD hash.
        Raises RuntimeError if git unavailable or operations fail.
        """
        if not await self._check_git_installed():
            raise RuntimeError("git is not installed or not in PATH")

        mirror_dir = Path(self.mirror_path)
        hash_file = mirror_dir / ".last_hash"

        if not mirror_dir.exists() or not (mirror_dir / ".git").exists():
            # Fresh clone
            mirror_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Cloning {self.GIT_REPO} (depth={self.clone_depth}) into {self.mirror_path}")
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", str(self.clone_depth), self.GIT_REPO, self.mirror_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git clone failed: {stderr.decode(errors='replace')}")
        else:
            # Pull latest
            logger.info(f"Updating cvelistV5 mirror at {self.mirror_path}")
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", self.mirror_path, "fetch", "origin",
                "--depth", str(self.clone_depth), "main",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                # Try origin/main fallback
                proc = await asyncio.create_subprocess_exec(
                    "git", "-C", self.mirror_path, "fetch", "origin",
                    "--depth", str(self.clone_depth),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()

            proc = await asyncio.create_subprocess_exec(
                "git", "-C", self.mirror_path, "reset", "--hard", "origin/main",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git reset failed: {stderr.decode()}")

        # Get HEAD hash
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", self.mirror_path, "rev-parse", "HEAD",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        head_hash = stdout.decode().strip()

        # Save hash
        hash_file.write_text(head_hash)
        logger.info(f"cvelistV5 mirror at {head_hash}")
        return head_hash

    async def scan_cve_files(
        self, since_hash: Optional[str] = None
    ) -> AsyncIterator[tuple[str, str]]:
        """
        Walk mirror/cves/YEAR/ directories, yield (filepath, year) pairs.
        If since_hash provided, use git diff --name-only to find changed files only.
        """
        mirror = Path(self.mirror_path)

        if since_hash:
            # Incremental: only files changed since last sync
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", self.mirror_path, "diff", "--name-only", since_hash, "HEAD",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            for line in stdout.decode().splitlines():
                line = line.strip()
                if self.CVE_FILE_PATTERN.match(line):
                    year = line.split("/")[1]
                    yield (str(mirror / line), year)
        else:
            # Full scan: walk cves/ directory tree
            cves_dir = mirror / "cves"
            if not cves_dir.exists():
                return
            for year_dir in sorted(cves_dir.iterdir()):
                if not year_dir.is_dir() or not year_dir.name.isdigit():
                    continue
                year = year_dir.name
                for quarter_dir in sorted(year_dir.iterdir()):
                    if not quarter_dir.is_dir():
                        continue
                    for cve_file in sorted(quarter_dir.iterdir()):
                        if cve_file.is_file() and cve_file.name.endswith(".json"):
                            yield (str(cve_file), year)

    def parse_cve_json(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse a single CVE 5.0 JSON file from disk"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Basic validation
            if not isinstance(data, dict):
                return None
            metadata = data.get("cveMetadata", {})
            if not metadata.get("cveId", "").startswith("CVE-"):
                return None
            return data
        except (json.JSONDecodeError, IOError, OSError) as e:
            logger.warning(f"Failed to parse {filepath}: {e}")
            return None

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


class CVESyncService:
    """CVE 同步服务"""

    # 默认技术栈关键词（Java 生态、Vue2/3、MySQL、Redis、Nacos、XXL-Job）
    DEFAULT_TECH_STACK_KEYWORDS = [
        # Java 生态
        "spring", "spring boot", "spring cloud", "spring security",
        "log4j", "logback", "fastjson", "jackson", "shiro", "struts",
        "tomcat", "jetty", "dubbo", "mybatis", "hibernate",
        # 前端
        "vue", "vue.js", "vue2", "vue3", "element-ui", "element plus",
        "webpack", "vite", "axios",
        # 中间件
        "mysql", "redis", "nacos", "xxl-job", "xxljob",
        "rabbitmq", "kafka", "elasticsearch", "nginx", "zookeeper",
        # JVM / 通用组件
        "openjdk", "netty", "commons", "poi", "xstream",
    ]

    # NVD API 单次查询日期范围限制（120 天），实际使用 90 天窗口保留余量
    NVD_DATE_WINDOW_DAYS = 90

    # OSV 生态系统名称映射
    OSV_ECOSYSTEMS = [
        "Maven", "npm", "PyPI", "Go", "NuGet", "crates.io", "RubyGems", "Packagist",
    ]

    def __init__(self, db: AsyncSession, nvd_api_key: Optional[str] = None):
        self.db = db
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.osv_client = OSVClient()

    async def _upsert_cve_from_nvd(
        self,
        cve_data: Dict[str, Any],
        source_override: str = "nvd",
    ) -> Optional[str]:
        """
        解析并 upsert 单条 NVD CVE，返回 "new" / "updated" / None（失败）

        提取自 sync_nvd 的解析/入库逻辑，供增量同步与技术栈同步复用
        """
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # 描述
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # CVSS
            metrics = cve_data.get("metrics", {})
            cvss_score = None
            severity = None

            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                cvss_dict = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss_dict.get("baseScore")
                severity = cvss_dict.get("baseSeverity", "UNKNOWN")
            else:
                cvss_v30 = metrics.get("cvssMetricV30", [])
                if cvss_v30:
                    cvss_dict = cvss_v30[0].get("cvssData", {})
                    cvss_score = cvss_dict.get("baseScore")
                    severity = cvss_dict.get("baseSeverity", "UNKNOWN")

            # CWE
            weaknesses = cve_data.get("weaknesses", [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_id = desc.get("value", "")
                        if cwe_id.startswith("CWE-"):
                            cwe_ids.append(cwe_id)

            # 影响包 (CPE)
            configurations = cve_data.get("configurations", [])
            affected_packages = []
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            criteria = cpe_match.get("criteria", "")
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                affected_packages.append({
                                    "cpe": criteria,
                                    "vendor": parts[3] if len(parts) > 3 else "",
                                    "product": parts[4] if len(parts) > 4 else "",
                                    "versionStart": cpe_match.get("versionStartExcluding"),
                                    "versionEnd": cpe_match.get("versionEndExcluding"),
                                })

            # 参考链接
            references = []
            for ref in cve_data.get("references", []):
                ref_url = ref.get("url", "")
                if ref_url:
                    references.append({
                        "url": ref_url,
                        "tags": ref.get("tags", []),
                    })

            # 时间
            published = cve_data.get("published")
            modified = cve_data.get("lastModified")
            published_at = (
                datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
            )
            modified_at = (
                datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None
            )

            # Upsert
            result = await self.db.execute(
                select(CVEKnowledge).where(CVEKnowledge.cve_id == cve_id)
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.title = description[:200] if description else cve_id
                existing.description = description
                existing.cvss_score = cvss_score
                existing.severity = severity
                existing.affected_packages = affected_packages
                existing.cwe_ids = cwe_ids
                existing.references = references
                existing.raw_data = cve_data
                existing.modified_at = modified_at
                existing.sync_status = "active"
                return "updated"
            else:
                cve = CVEKnowledge(
                    cve_id=cve_id,
                    title=description[:200] if description else cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    affected_packages=affected_packages,
                    cwe_ids=cwe_ids,
                    references=references,
                    source=source_override,
                    raw_data=cve_data,
                    published_at=published_at,
                    modified_at=modified_at,
                    sync_status="active",
                    embedding_synced=0,
                )
                self.db.add(cve)
                return "new"

        except Exception as e:
            logger.error(f"Failed to upsert CVE: {e}")
            return None

    async def _last_successful_sync_end_date(self, source: str = "nvd") -> Optional[datetime]:
        """查询最近一次成功的同步任务的 end_date，用于增量同步起点"""
        result = await self.db.execute(
            select(CVESyncLog)
            .where(CVESyncLog.source == source)
            .where(CVESyncLog.status == "success")
            .order_by(CVESyncLog.created_at.desc())
            .limit(1)
        )
        last = result.scalar_one_or_none()
        return last.end_date if last else None

    async def _upsert_from_osv(
        self,
        vuln: Dict[str, Any],
        ecosystem: Optional[str] = None,
        package: Optional[str] = None,
    ) -> Optional[str]:
        """
        解析并 upsert 单条 OSV 漏洞，返回 "new" / "updated" / None（失败）

        Args:
            vuln: OSV 漏洞详情字典
            ecosystem: 生态系统名称
            package: 包名称（可选）

        Returns:
            "new" / "updated" / None
        """
        try:
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                return None

            # OSV ID 可能是 GHSA-xxx 或 CVE-xxx，优先使用 CVE ID
            cve_id = vuln_id
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            # 解析描述
            descriptions = vuln.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # 解析严重程度
            severity = None
            cvss_score = None
            severity_list = vuln.get("severity", [])
            if severity_list:
                for sev in severity_list:
                    if sev.get("type") == "CVSS_V3":
                        cvss_score = sev.get("score")
                        severity = sev.get("severity", "UNKNOWN")
                        break

            # 解析影响版本
            affected_packages = []
            for aff in vuln.get("affected", []):
                pkg = {
                    "ecosystem": aff.get("ecosystem", ecosystem),
                    "name": aff.get("package", {}).get("name", ""),
                    "version": aff.get("version"),
                    "ranges": aff.get("ranges", []),
                }
                if package and not pkg["name"]:
                    pkg["name"] = package
                if pkg["name"]:
                    affected_packages.append(pkg)

            # 时间
            published = vuln.get("published")
            modified = vuln.get("modified")
            published_at = (
                datetime.fromisoformat(published.replace("Z", "+00:00"))
                if published else None
            )
            modified_at = (
                datetime.fromisoformat(modified.replace("Z", "+00:00"))
                if modified else None
            )

            # 查询是否已存在
            result = await self.db.execute(
                select(CVEKnowledge).where(CVEKnowledge.cve_id == cve_id)
            )
            existing = result.scalar_one_or_none()

            if existing:
                # 合并 OSV 数据到 raw_data
                existing.raw_data = {**existing.raw_data, "osv": vuln}
                existing.title = description[:200] if description else existing.title
                existing.description = description or existing.description
                existing.severity = severity or existing.severity
                existing.cvss_score = cvss_score or existing.cvss_score
                existing.modified_at = modified_at or existing.modified_at
                existing.sync_status = "active"
                return "updated"
            else:
                cve = CVEKnowledge(
                    cve_id=cve_id,
                    title=description[:200] if description else cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity or "UNKNOWN",
                    affected_packages=affected_packages,
                    source="osv",
                    raw_data={"osv": vuln},
                    published_at=published_at,
                    modified_at=modified_at,
                    sync_status="active",
                    embedding_synced=0,
                )
                self.db.add(cve)
                return "new"

        except Exception as e:
            logger.error(f"Failed to upsert OSV vuln {vuln.get('id', '')}: {e}")
            return None

    async def sync_nvd_incremental(
        self,
        max_results: int = 5000,
        severity_filter: Optional[str] = None,
        fallback_days: int = 1825,  # 5 年
    ) -> CVESyncLog:
        """
        NVD 增量同步：从上一次成功同步的 end_date 开始，拉取到当前

        - 无历史成功记录时回退到 fallback_days（默认 5 年）
        - 大于 90 天的区间会自动分段
        """
        end_date = datetime.utcnow()
        last_end = await self._last_successful_sync_end_date(source="nvd")
        if last_end:
            # 确保 last_end 无时区（NVD API 要求 naive datetime）
            if last_end.tzinfo is not None:
                last_end = last_end.replace(tzinfo=None)
            start_date = last_end
            logger.info(f"NVD incremental: resume from last successful sync end_date={start_date}")
        else:
            start_date = end_date - timedelta(days=fallback_days)
            logger.info(f"NVD incremental: no prior sync, falling back to {fallback_days} days ago")

        return await self._sync_nvd_range(
            start_date=start_date,
            end_date=end_date,
            max_results=max_results,
            severity_filter=severity_filter,
            source_label="nvd",
        )

    async def _sync_nvd_range(
        self,
        start_date: datetime,
        end_date: datetime,
        max_results: int = 5000,
        severity_filter: Optional[str] = None,
        keyword: Optional[str] = None,
        source_label: str = "nvd",
    ) -> CVESyncLog:
        """
        通用 NVD 区间同步，自动分片为 90 天窗口以规避 NVD 120 天限制
        """
        sync_log = CVESyncLog(
            source=source_label,
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
            # 分片：每个窗口 90 天
            window_start = start_date
            window_delta = timedelta(days=self.NVD_DATE_WINDOW_DAYS)

            while window_start < end_date and total_processed < max_results:
                window_end = min(window_start + window_delta, end_date)
                logger.info(
                    f"NVD sync window: {window_start.isoformat()} -> {window_end.isoformat()}"
                    + (f" keyword={keyword!r}" if keyword else "")
                )

                start_index = 0
                results_per_page = 2000

                while total_processed < max_results:
                    data = await self.nvd_client.fetch_cves(
                        start_date=window_start,
                        end_date=window_end,
                        results_per_page=results_per_page,
                        start_index=start_index,
                        keyword=keyword,
                        cvss_v3_severity=severity_filter,
                    )

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break

                    for vuln in vulnerabilities:
                        cve_data = vuln.get("cve", {})
                        outcome = await self._upsert_cve_from_nvd(cve_data)
                        if outcome == "new":
                            total_new += 1
                        elif outcome == "updated":
                            total_updated += 1
                        else:
                            total_failed += 1
                        total_processed += 1
                        if total_processed >= max_results:
                            break

                    total_results = int(data.get("totalResults", 0) or 0)
                    start_index += len(vulnerabilities)
                    if start_index >= total_results or not vulnerabilities:
                        break

                # 中间落库一次，防止长时间事务
                await self.db.flush()
                window_start = window_end

            sync_log.status = "success"
            sync_log.total_count = total_processed
            sync_log.new_count = total_new
            sync_log.updated_count = total_updated
            sync_log.failed_count = total_failed

            logger.info(
                f"NVD sync completed [{source_label}]: {total_processed} processed, "
                f"{total_new} new, {total_updated} updated, {total_failed} failed"
            )

        except Exception as e:
            sync_log.status = "failed"
            sync_log.error_message = str(e)
            sync_log.total_count = total_processed
            sync_log.new_count = total_new
            sync_log.updated_count = total_updated
            sync_log.failed_count = total_failed
            logger.error(f"NVD sync [{source_label}] failed: {e}", exc_info=True)

        await self.db.commit()
        return sync_log

    async def sync_by_tech_stack(
        self,
        keywords: Optional[List[str]] = None,
        years: int = 5,
        severity_filter: Optional[str] = None,
        max_per_keyword: int = 1000,
    ) -> CVESyncLog:
        """
        技术栈历史 CVE 同步：按关键词逐个从 NVD 拉取最近 N 年的漏洞

        Args:
            keywords: 关键词列表，为 None 或空时使用 DEFAULT_TECH_STACK_KEYWORDS
            years: 回溯年数（默认 5）
            severity_filter: 严重程度过滤
            max_per_keyword: 单个关键词的最大结果数
        """
        kws = keywords or self.DEFAULT_TECH_STACK_KEYWORDS
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=years * 365)

        aggregate_log = CVESyncLog(
            source="nvd_tech_stack",
            status="running",
            start_date=start_date,
            end_date=end_date,
        )
        self.db.add(aggregate_log)
        await self.db.flush()

        total_new = 0
        total_updated = 0
        total_failed = 0
        total_processed = 0
        failed_keywords: List[str] = []

        try:
            for kw in kws:
                try:
                    logger.info(f"[tech-stack] syncing keyword={kw!r} years={years}")
                    sub_log = await self._sync_nvd_range(
                        start_date=start_date,
                        end_date=end_date,
                        max_results=max_per_keyword,
                        severity_filter=severity_filter,
                        keyword=kw,
                        source_label=f"nvd_tech_stack:{kw}",
                    )
                    total_new += int(sub_log.new_count or 0)
                    total_updated += int(sub_log.updated_count or 0)
                    total_failed += int(sub_log.failed_count or 0)
                    total_processed += int(sub_log.total_count or 0)
                    if sub_log.status != "success":
                        failed_keywords.append(kw)
                except Exception as e:
                    logger.error(f"[tech-stack] keyword {kw!r} failed: {e}")
                    failed_keywords.append(kw)

            aggregate_log.status = "success" if not failed_keywords else "partial"
            aggregate_log.total_count = total_processed
            aggregate_log.new_count = total_new
            aggregate_log.updated_count = total_updated
            aggregate_log.failed_count = total_failed
            if failed_keywords:
                aggregate_log.error_message = f"failed keywords: {', '.join(failed_keywords)}"

            logger.info(
                f"Tech-stack sync completed: {len(kws)} keywords, "
                f"{total_processed} processed, {total_new} new, {total_updated} updated, "
                f"{len(failed_keywords)} keyword(s) failed"
            )

        except Exception as e:
            aggregate_log.status = "failed"
            aggregate_log.error_message = str(e)
            logger.error(f"Tech-stack sync failed: {e}", exc_info=True)

        await self.db.commit()
        return aggregate_log

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

    async def sync_osv_incremental(
        self,
        ecosystems: Optional[List[str]] = None,
    ) -> CVESyncLog:
        """
        OSV 增量同步：基于 modified_id.csv 获取最近修改的漏洞

        Args:
            ecosystems: 指定生态系统列表，为 None 时使用 OSV_ECOSYSTEMS
        """
        if ecosystems is None:
            ecosystems = self.OSV_ECOSYSTEMS

        end_date = datetime.utcnow()
        last_end = await self._last_successful_sync_end_date(source="osv_incremental")
        if last_end:
            if last_end.tzinfo is not None:
                last_end = last_end.replace(tzinfo=None)
            logger.info(f"OSV incremental: resume from last successful sync end_date={last_end}")
        else:
            # 首次同步，回退到 30 天前
            last_end = end_date - timedelta(days=30)
            logger.info(f"OSV incremental: no prior sync, falling back to 30 days ago")

        sync_log = CVESyncLog(
            source="osv_incremental",
            status="running",
            start_date=last_end,
            end_date=end_date,
        )
        self.db.add(sync_log)
        await self.db.flush()

        total_new = 0
        total_updated = 0
        total_failed = 0
        total_processed = 0

        try:
            for ecosystem in ecosystems:
                logger.info(f"[OSV incremental] Processing ecosystem: {ecosystem}")

                # 获取 modified_id.csv
                modified_ids = await self.osv_client.fetch_modified_ids(ecosystem)
                if not modified_ids:
                    logger.info(f"[OSV incremental] No modified IDs for {ecosystem}, skipping")
                    await asyncio.sleep(0.3)
                    continue

                # 过滤出自上次同步以来修改的 ID
                filtered_ids = []
                for item in modified_ids:
                    try:
                        mod_time = datetime.fromisoformat(item["modified_time"].replace("Z", "+00:00"))
                        if mod_time.tzinfo is not None:
                            mod_time = mod_time.replace(tzinfo=None)
                        if mod_time > last_end:
                            filtered_ids.append(item["id"])
                    except Exception as e:
                        logger.warning(f"Failed to parse modified_time for {item['id']}: {e}")
                        continue

                if not filtered_ids:
                    logger.info(f"[OSV incremental] No new modifications for {ecosystem}")
                    await asyncio.sleep(0.3)
                    continue

                logger.info(f"[OSV incremental] {ecosystem}: {len(filtered_ids)} modified since last sync")

                # 分批查询，每批最多 1000 个 ID
                batch_size = 1000
                for i in range(0, len(filtered_ids), batch_size):
                    batch_ids = filtered_ids[i:i + batch_size]

                    # 批量查询漏洞详情
                    vulns = await self.osv_client.query_batch(batch_ids)
                    returned_ids = {v.get("id") for v in vulns}

                    # 处理返回的漏洞
                    for vuln in vulns:
                        outcome = await self._upsert_from_osv(vuln, ecosystem=ecosystem)
                        if outcome == "new":
                            total_new += 1
                        elif outcome == "updated":
                            total_updated += 1
                        else:
                            total_failed += 1
                        total_processed += 1

                    # 对于批量查询未返回的漏洞，尝试逐个获取详情
                    missing_ids = [vid for vid in batch_ids if vid not in returned_ids]
                    for miss_id in missing_ids:
                        vuln_detail = await self.osv_client.get_vuln_detail(miss_id)
                        if vuln_detail:
                            outcome = await self._upsert_from_osv(vuln_detail, ecosystem=ecosystem)
                            if outcome == "new":
                                total_new += 1
                            elif outcome == "updated":
                                total_updated += 1
                            else:
                                total_failed += 1
                            total_processed += 1
                        else:
                            total_failed += 1
                        # 添加小延迟避免过快请求
                        await asyncio.sleep(0.1)

                # 每个生态系统后添加延迟，避免给 OSV 存储造成压力
                await asyncio.sleep(0.3)

            await self.db.flush()

            sync_log.status = "success"
            sync_log.total_count = total_processed
            sync_log.new_count = total_new
            sync_log.updated_count = total_updated
            sync_log.failed_count = total_failed

            logger.info(
                f"OSV incremental sync completed: {total_processed} processed, "
                f"{total_new} new, {total_updated} updated, {total_failed} failed"
            )

        except Exception as e:
            sync_log.status = "failed"
            sync_log.error_message = str(e)
            sync_log.total_count = total_processed
            sync_log.new_count = total_new
            sync_log.updated_count = total_updated
            sync_log.failed_count = total_failed
            logger.error(f"OSV incremental sync failed: {e}", exc_info=True)

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

    async def _parse_cvelist_v5_record(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse CVE 5.0 JSON format into CVEKnowledge-compatible dict"""
        metadata = data.get("cveMetadata", {})
        cna = data.get("containers", {}).get("cna", {})

        cve_id = metadata.get("cveId")
        if not cve_id:
            return None

        title = cna.get("title", "")
        description = ""
        if cna.get("descriptions"):
            desc = next(
                (d for d in cna["descriptions"] if d.get("lang") == "en"),
                cna["descriptions"][0],
            )
            description = desc.get("value", "")

        severity = "UNKNOWN"
        cvss_score = None
        if cna.get("metrics"):
            for metric_group in cna["metrics"]:
                if "cvssV3_1" in metric_group:
                    severity = metric_group["cvssV3_1"].get("baseSeverity", "UNKNOWN")
                    cvss_score = metric_group["cvssV3_1"].get("baseScore")
                    break
                elif "cvssV3_0" in metric_group:
                    severity = metric_group["cvssV3_0"].get("baseSeverity", "UNKNOWN")
                    cvss_score = metric_group["cvssV3_0"].get("baseScore")
                    break

        affected = []
        for aff in cna.get("affected", []):
            affected.append({
                "vendor": aff.get("vendor", ""),
                "product": aff.get("product", ""),
                "packageName": aff.get("packageName", ""),
                "versions": [
                    {"version": v.get("version"), "status": v.get("status")}
                    for v in aff.get("versions", [])
                ],
            })

        # CWE
        cwe_ids = []
        for problem in cna.get("problemTypes", []):
            for desc in problem.get("descriptions", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("cweId", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_ids.append(cwe_id)

        # References
        references = []
        for ref in cna.get("references", []):
            ref_url = ref.get("url", "")
            if ref_url:
                references.append({
                    "url": ref_url,
                    "tags": ref.get("tags", []),
                })

        # Timestamps
        published_str = metadata.get("datePublished")
        modified_str = metadata.get("dateUpdated")
        published_at = None
        modified_at = None
        if published_str:
            try:
                published_at = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            except ValueError:
                pass
        if modified_str:
            try:
                modified_at = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        return {
            "cve_id": cve_id,
            "title": title or description[:200] if description else cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "affected_packages": affected,
            "cwe_ids": cwe_ids,
            "references": references,
            "source": "cvelist-v5",
            "raw_data": data,
            "published_at": published_at,
            "modified_at": modified_at,
        }

    async def _upsert_from_cvelist_v5(
        self, parsed: Dict[str, Any]
    ) -> Optional[str]:
        """
        Upsert a parsed cvelistV5 record. Returns "new" / "updated" / None.
        """
        try:
            cve_id = parsed["cve_id"]
            result = await self.db.execute(
                select(CVEKnowledge).where(CVEKnowledge.cve_id == cve_id)
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.title = parsed["title"]
                existing.description = parsed["description"]
                existing.cvss_score = parsed.get("cvss_score")
                existing.severity = parsed["severity"]
                existing.affected_packages = parsed["affected_packages"]
                existing.cwe_ids = parsed.get("cwe_ids", [])
                existing.references = parsed.get("references", [])
                existing.raw_data = parsed["raw_data"]
                existing.modified_at = parsed.get("modified_at")
                existing.sync_status = "active"
                return "updated"
            else:
                cve = CVEKnowledge(
                    cve_id=cve_id,
                    title=parsed["title"],
                    description=parsed["description"],
                    cvss_score=parsed.get("cvss_score"),
                    severity=parsed["severity"],
                    affected_packages=parsed["affected_packages"],
                    cwe_ids=parsed.get("cwe_ids", []),
                    references=parsed.get("references", []),
                    source=parsed["source"],
                    raw_data=parsed["raw_data"],
                    published_at=parsed.get("published_at"),
                    modified_at=parsed.get("modified_at"),
                    sync_status="active",
                    embedding_synced=0,
                )
                self.db.add(cve)
                return "new"
        except Exception as e:
            logger.error(f"Failed to upsert CVE from cvelistV5: {e}")
            return None

    async def sync_cvelist_v5(self, force_full: bool = False) -> CVESyncLog:
        """
        Sync CVE records from CVEProject/cvelistV5 Git mirror.

        Args:
            force_full: If True, re-sync all CVEs. If False, only sync changes since last run.
        """
        sync_log = CVESyncLog(
            source="cvelist-v5",
            status="running",
        )
        self.db.add(sync_log)
        await self.db.flush()

        total_new = 0
        total_updated = 0
        total_failed = 0
        total_processed = 0

        try:
            client = CVEProjectV5Client()
            head_hash = await client._init_mirror()

            hash_file = Path(client.mirror_path) / ".last_hash"
            last_hash = None
            if not force_full and hash_file.exists():
                last_hash = hash_file.read_text().strip() or None

            if force_full:
                logger.info("cvelistV5 full sync requested")
            else:
                logger.info(f"cvelistV5 incremental sync since {last_hash or 'initial'}")

            year_stats: Dict[str, int] = {}
            async for filepath, year in client.scan_cve_files(since_hash=last_hash if not force_full else None):
                try:
                    data = await asyncio.to_thread(client.parse_cve_json, filepath)
                    if data is None:
                        total_failed += 1
                        continue

                    parsed = await self._parse_cvelist_v5_record(data)
                    if parsed is None:
                        total_failed += 1
                        continue

                    outcome = await self._upsert_from_cvelist_v5(parsed)
                    if outcome == "new":
                        total_new += 1
                    elif outcome == "updated":
                        total_updated += 1
                    else:
                        total_failed += 1
                    total_processed += 1

                    # Track per-year progress
                    year_stats[year] = year_stats.get(year, 0) + 1

                    # Flush every 500 records to avoid long transactions
                    if total_processed % 500 == 0:
                        await self.db.flush()
                        logger.info(
                            f"cvelistV5 sync progress: {total_processed} processed "
                            f"(new={total_new}, updated={total_updated}, year={year})"
                        )

                except Exception as e:
                    logger.warning(f"Failed to process {filepath}: {e}")
                    total_failed += 1

            # Update hash file only on success
            hash_file.write_text(head_hash)

            await self.db.flush()
            sync_log.status = "success"
            sync_log.total_count = total_processed
            sync_log.new_count = total_new
            sync_log.updated_count = total_updated
            sync_log.failed_count = total_failed

            logger.info(
                f"cvelistV5 sync completed: {total_processed} processed, "
                f"{total_new} new, {total_updated} updated, {total_failed} failed "
                f"(years={list(year_stats.keys())})"
            )

        except RuntimeError as e:
            sync_log.status = "failed"
            sync_log.error_message = str(e)
            logger.error(f"cvelistV5 sync failed: {e}")

        except Exception as e:
            sync_log.status = "failed"
            sync_log.error_message = str(e)
            logger.error(f"cvelistV5 sync failed: {e}", exc_info=True)

        await self.db.commit()
        return sync_log

    async def close(self):
        await self.nvd_client.close()
        await self.osv_client.close()
