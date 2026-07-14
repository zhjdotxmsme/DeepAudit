"""
PoC Runtime Tool - 沙箱PoC执行 + 报告绑定

将agent编写的PoC在沙箱中执行，并把执行证据回写到已创建的漏洞报告上。
不硬编码payload、不做检测——LLM决定PoC逻辑，工具只提供执行+证据固化。

工作流：
1. Agent 通过 create_vulnerability_report 先创建报告，拿到 report_id
2. Agent 编写 PoC 代码
3. Agent 调用 validate_poc(report_id=..., code=..., language=...)
4. 工具在沙箱运行 PoC，捕获 stdout/stderr/exit_code
5. 把结果作为 poc_execution 证据字段写回报告，标记 poc_verified

与 RunCodeTool 区别：
- RunCodeTool: 探索式执行，结果只在对话上下文中
- ValidatePoCTool: 结果被绑定到具体报告，进入最终产物
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from .base import AgentTool, ToolResult
from .sandbox_tool import SandboxManager, SandboxConfig
from .reporting_tool import CreateVulnerabilityReportTool
from .run_code import RunCodeTool

logger = logging.getLogger(__name__)


class ValidatePoCInput(BaseModel):
    """PoC 验证输入"""
    report_id: str = Field(..., description="目标漏洞报告ID（由 create_vulnerability_report 返回）")
    code: str = Field(..., description="PoC 代码，完整可执行")
    language: str = Field(default="python", description="语言: python/php/javascript/ruby/go/java/bash")
    timeout: int = Field(default=60, description="超时秒数")
    expected_evidence: str = Field(
        default="",
        description="预期证据字符串（如 'root:x:0:0'）。若非空且出现在 stdout 中，则视为PoC成功"
    )
    description: str = Field(default="", description="PoC 用途描述")


class ValidatePoCTool(AgentTool):
    """
    沙箱PoC执行 + 报告证据绑定

    与 RunCodeTool 共享沙箱执行能力，但把结果作为不可变证据附加到
    已创建的漏洞报告上，进入最终扫描产物。
    """

    def __init__(
        self,
        sandbox_manager: Optional[SandboxManager] = None,
        project_root: str = "."
    ):
        super().__init__()
        config = SandboxConfig(timeout=120, memory_limit="1g")
        self.sandbox_manager = sandbox_manager or SandboxManager(config)
        self.project_root = project_root
        # 复用 RunCodeTool 的命令构造，避免重复逻辑
        self._runner = RunCodeTool(sandbox_manager=self.sandbox_manager, project_root=project_root)

    @property
    def name(self) -> str:
        return "validate_poc"

    @property
    def description(self) -> str:
        return """🔬 在沙箱中执行PoC并把结果绑定到已创建的漏洞报告

用法：
1. 先用 create_vulnerability_report 创建报告，拿到 report_id
2. 编写完整可执行的 PoC 代码
3. 调用本工具：validate_poc(report_id=..., code=..., language=...)

输入：
- report_id: 漏洞报告ID（必需）
- code: PoC 代码（完整可执行）
- language: python/php/javascript/ruby/go/java/bash
- timeout: 超时秒数（默认60）
- expected_evidence: 预期证据字符串（如 'root:x:0:0'）。若非空且在stdout中，标记PoC成功
- description: PoC 用途说明

产物：
- 报告被追加 poc_execution 字段：{stdout, stderr, exit_code, executed_at, success}
- 报告 is_verified 变为 True（此前只是"格式合规"）
- 严重程度可能被上调（若证据强度足够）

⚠️ 只有 PoC 真正执行成功（找到 expected_evidence 或 exit_code=0 且无异常）才会绑定。
   失败的PoC不会污染报告。"""

    @property
    def args_schema(self):
        return ValidatePoCInput

    async def _execute(
        self,
        report_id: str,
        code: str,
        language: str = "python",
        timeout: int = 60,
        expected_evidence: str = "",
        description: str = "",
        **kwargs
    ) -> ToolResult:
        # 1. 定位报告
        target = None
        for rpt in CreateVulnerabilityReportTool._vulnerability_reports:
            if rpt.get("id") == report_id:
                target = rpt
                break

        if target is None:
            return ToolResult(
                success=False,
                error=f"未找到报告 {report_id}。请先通过 create_vulnerability_report 创建。"
            )

        # 2. 初始化沙箱
        try:
            await self.sandbox_manager.initialize()
        except Exception as e:
            logger.warning(f"[ValidatePoC] Sandbox init failed: {e}")

        if not self.sandbox_manager.is_available:
            return ToolResult(
                success=False,
                error="沙箱不可用（Docker 未运行）",
                data="无法执行PoC。若必须记录，请在报告描述中说明为静态验证。"
            )

        # 3. 构建命令
        language = language.lower().strip()
        command = self._runner._build_command(code, language)
        if command is None:
            return ToolResult(
                success=False,
                error=f"不支持的语言: {language}"
            )

        # 4. 执行
        exec_result = await self.sandbox_manager.execute_command(
            command=command,
            timeout=timeout,
        )

        stdout = exec_result.get("stdout", "") or ""
        stderr = exec_result.get("stderr", "") or ""
        exit_code = exec_result.get("exit_code", -1)

        # 5. 判断PoC是否成功
        evidence_matched = False
        if expected_evidence and expected_evidence in stdout:
            evidence_matched = True
            poc_success = True
        else:
            # 无预期证据时，用 exit_code=0 且无致命 stderr 作为兜底
            poc_success = (exit_code == 0) and (not exec_result.get("error"))

        # 6. 只有成功才绑定到报告
        if poc_success:
            poc_evidence = {
                "language": language,
                "code": code,
                "stdout": stdout[:5000],  # 截断防爆炸
                "stderr": stderr[:2000],
                "exit_code": exit_code,
                "expected_evidence": expected_evidence or None,
                "evidence_matched": evidence_matched,
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "description": description,
            }
            target["poc_execution"] = poc_evidence
            target["is_verified"] = True

            # 若明确匹配到证据串，把置信度拉到 0.95 起
            if evidence_matched:
                target["confidence"] = max(target.get("confidence", 0.8), 0.95)

            logger.info(
                f"[ValidatePoC] ✅ PoC verified for {report_id}: "
                f"exit={exit_code} evidence_matched={evidence_matched}"
            )

            return ToolResult(
                success=True,
                data={
                    "message": f"✅ PoC 已执行并绑定到报告 {report_id}",
                    "report_id": report_id,
                    "exit_code": exit_code,
                    "evidence_matched": evidence_matched,
                    "stdout_preview": stdout[:500],
                },
                metadata=poc_evidence,
            )
        else:
            # 失败不污染报告，只回传诊断
            logger.info(
                f"[ValidatePoC] ❌ PoC failed for {report_id}: "
                f"exit={exit_code} stderr_len={len(stderr)}"
            )
            return ToolResult(
                success=False,
                error="PoC 执行未通过验证",
                data={
                    "report_id": report_id,
                    "exit_code": exit_code,
                    "stdout": stdout[:1000],
                    "stderr": stderr[:1000],
                    "hint": "调整PoC代码后重试，或提供 expected_evidence 显式指定成功判据。"
                          " 未绑定到报告，报告状态未变。"
                }
            )
