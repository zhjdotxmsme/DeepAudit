"""
CVE 查询工具 - 供 Agent 在审计过程中查询已知漏洞
"""

import logging
from typing import Optional

from pydantic import BaseModel, Field

from app.services.agent.tools.base import AgentTool, ToolResult
from app.services.cve_sync_service import CVESyncService

logger = logging.getLogger(__name__)


class CVEQueryInput(BaseModel):
    """CVE 查询输入"""
    package_name: str = Field(
        description="包名称，如 spring-core, lodash, django"
    )
    ecosystem: Optional[str] = Field(
        default=None,
        description="包生态系统: Maven, npm, PyPI, Go, RubyGems, Packagist 等"
    )
    min_severity: Optional[str] = Field(
        default="MEDIUM",
        description="最小严重程度: CRITICAL, HIGH, MEDIUM, LOW"
    )
    max_results: int = Field(
        default=10,
        description="最大返回结果数"
    )


class CVEQueryTool(AgentTool):
    """
    CVE 知识库查询工具

    查询已知 CVE 漏洞信息，帮助 Agent 了解项目依赖中是否存在已知漏洞。
    支持按包名、生态系统、严重程度过滤。
    """

    def __init__(self, db_session=None):
        super().__init__()
        self.db_session = db_session

    @property
    def name(self) -> str:
        return "cve_query"

    @property
    def description(self) -> str:
        return """查询 CVE 漏洞知识库，获取已知漏洞信息。

使用场景:
- 审计项目依赖时，检查是否存在已知 CVE 漏洞
- 发现可疑组件时，查询其安全历史
- 验证工具发现的漏洞是否为已知问题

参数说明:
- package_name: 包名称（必填）
- ecosystem: 包生态系统（可选，如 Maven, npm, PyPI）
- min_severity: 最小严重程度，默认 MEDIUM
- max_results: 最大返回数量，默认 10

示例:
{"package_name": "spring-core", "ecosystem": "Maven", "min_severity": "HIGH"}
{"package_name": "lodash", "ecosystem": "npm"}

返回结果包含:
- CVE ID
- 严重程度 (CRITICAL/HIGH/MEDIUM/LOW)
- CVSS 评分
- 漏洞描述
- 影响版本范围
- 参考链接"""

    @property
    def args_schema(self):
        return CVEQueryInput

    async def _execute(
        self,
        package_name: str,
        ecosystem: Optional[str] = None,
        min_severity: str = "MEDIUM",
        max_results: int = 10,
        **kwargs
    ) -> ToolResult:
        """执行 CVE 查询"""
        if not self.db_session:
            return ToolResult(
                success=False,
                error="数据库会话未初始化，无法查询 CVE 知识库",
                data="CVE 知识库查询需要数据库连接。请在初始化工具时传入 db_session。"
            )

        try:
            service = CVESyncService(db=self.db_session)

            # 如果没有指定 ecosystem，尝试推断
            inferred_ecosystem = ecosystem
            if not inferred_ecosystem:
                # 简单的推断逻辑
                if package_name.startswith("spring-") or package_name.startswith("org."):
                    inferred_ecosystem = "Maven"
                elif package_name in ["lodash", "express", "react", "vue", "axios"]:
                    inferred_ecosystem = "npm"
                elif package_name in ["django", "flask", "requests"]:
                    inferred_ecosystem = "PyPI"

            cves = await service.get_cves_for_package(
                ecosystem=inferred_ecosystem or "",
                package_name=package_name,
                min_severity=min_severity,
            )

            # 限制结果数量
            cves = cves[:max_results]

            if not cves:
                return ToolResult(
                    success=True,
                    data=f"未找到 {package_name} ({inferred_ecosystem or '未知生态'}) 的相关 CVE 漏洞。",
                )

            # 格式化结果
            results = []
            for cve in cves:
                result = {
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "title": cve.title,
                    "description": cve.description[:500] if cve.description else "",
                    "affected_packages": cve.affected_packages,
                    "cwe_ids": cve.cwe_ids,
                    "published_at": cve.published_at.isoformat() if cve.published_at else None,
                    "references": [ref.get("url", "") for ref in (cve.references or [])][:3],
                }
                results.append(result)

            summary = f"找到 {len(results)} 个与 {package_name} 相关的 CVE 漏洞："
            severity_counts = {}
            for cve in cves:
                sev = (cve.severity or "UNKNOWN").upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            for sev, count in sorted(
                severity_counts.items(),
                key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x[0], 0),
                reverse=True
            ):
                summary += f"\n- {sev}: {count}个"

            return ToolResult(
                success=True,
                data={
                    "summary": summary,
                    "package": package_name,
                    "ecosystem": inferred_ecosystem,
                    "cves": results,
                },
            )

        except Exception as e:
            logger.error(f"CVE 查询失败: {e}")
            return ToolResult(
                success=False,
                error=f"CVE 查询失败: {str(e)}",
                data="查询 CVE 知识库时发生错误，请检查数据库连接。"
            )


class CVESyncTool(AgentTool):
    """
    CVE 同步工具（管理用）

    触发 CVE 知识库同步，通常由后台任务或管理员调用。
    """

    def __init__(self, db_session=None, nvd_api_key: Optional[str] = None):
        super().__init__()
        self.db_session = db_session
        self.nvd_api_key = nvd_api_key

    @property
    def name(self) -> str:
        return "cve_sync"

    @property
    def description(self) -> str:
        return "触发 CVE 知识库同步。管理员专用。"

    async def _execute(self, days_back: int = 30, **kwargs) -> ToolResult:
        if not self.db_session:
            return ToolResult(
                success=False,
                error="数据库会话未初始化"
            )

        try:
            service = CVESyncService(db=self.db_session, nvd_api_key=self.nvd_api_key)
            sync_log = await service.sync_nvd(days_back=days_back)

            return ToolResult(
                success=sync_log.status == "success",
                data={
                    "status": sync_log.status,
                    "total": sync_log.total_count,
                    "new": sync_log.new_count,
                    "updated": sync_log.updated_count,
                    "failed": sync_log.failed_count,
                },
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
