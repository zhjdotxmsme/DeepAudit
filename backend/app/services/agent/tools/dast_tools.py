"""
DAST (Dynamic Application Security Testing) 工具

对活的 HTTP 目标做动态扫描：
- NucleiTool: projectdiscovery/nuclei 模板扫描（CVE / 弱口令 / 暴露面）
- PlaywrightProbeTool: 无头浏览器抓取渲染后 DOM、JS 路由、链接、表单

架构：
- 复用 SandboxManager，容器 network_mode="bridge"（DAST 必须联网）
- entrypoint=[] 清空工具镜像的 ENTRYPOINT，走 sh -c 执行组合命令
- 结果结构化解析后返回 ToolResult
"""

from __future__ import annotations

import json
import logging
import os
import shlex
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from .base import AgentTool, ToolResult

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# 共用：URL 校验
# ------------------------------------------------------------------
def _validate_target_url(url: str) -> Optional[str]:
    """
    返回 None 表示合法，否则返回错误信息。
    禁止 file://、javascript:、data: 等非 http(s) 协议。
    """
    if not url or not isinstance(url, str):
        return "target_url 不能为空"
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return f"仅支持 http/https 目标，收到 scheme={parsed.scheme!r}"
    if not parsed.netloc:
        return "target_url 缺少 host"
    return None


# ==================================================================
# NucleiTool
# ==================================================================
class NucleiArgs(BaseModel):
    target_url: str = Field(..., description="待扫描目标 URL, 例如 https://example.com")
    templates: Optional[str] = Field(
        default=None,
        description="Nuclei 模板集，逗号分隔，如 'cves,exposures,misconfiguration'。留空使用默认模板集。",
    )
    severity: Optional[str] = Field(
        default="critical,high,medium",
        description="严重度过滤，逗号分隔：critical,high,medium,low,info",
    )
    tags: Optional[str] = Field(
        default=None,
        description="按 tag 过滤模板，逗号分隔（如 spring,log4j,rce）",
    )
    rate_limit: int = Field(default=50, description="每秒请求数上限")
    timeout: int = Field(default=300, description="扫描超时（秒）")
    max_results: int = Field(default=50, description="最多返回多少条 finding")


class NucleiTool(AgentTool):
    """
    调用 projectdiscovery/nuclei 对活目标做模板化 DAST 扫描。

    ⚠️ 使用前提：
    - 目标必须已授权测试
    - 容器需要出网 (network_mode=bridge)
    """

    NUCLEI_IMAGE = "projectdiscovery/nuclei:latest"

    def __init__(self, sandbox_manager: Any):
        super().__init__()
        self.sandbox_manager = sandbox_manager

    @property
    def name(self) -> str:
        return "nuclei_scan"

    @property
    def description(self) -> str:
        return """使用 Nuclei 对活的 HTTP(S) 目标做模板化 DAST 扫描。

参数:
- target_url (必填): 待扫描 URL, 如 https://target.example.com
- templates: 模板集, 逗号分隔, 常用值 cves,exposures,misconfiguration,vulnerabilities,default-logins
- severity: 严重度过滤, 默认 critical,high,medium
- tags: 按 tag 过滤 (spring,log4j,rce,ssrf,...)
- rate_limit: 每秒请求上限, 默认 50
- timeout: 超时秒数, 默认 300
- max_results: 最多返回条数, 默认 50

使用场景:
- 已知目标 URL, 需要检测已披露 CVE / 错误配置 / 敏感文件泄露
- 补充 SAST 结果, 提供实证性 (真实响应可复现)
- 对 SpringBoot Actuator / Nginx / Nacos 等中间件做暴露面扫描

⚠️ 只能扫描已授权的目标。跳过所有内网/生产未授权 IP。"""

    @property
    def args_schema(self):
        return NucleiArgs

    async def _execute(self, **kwargs) -> ToolResult:
        target_url = kwargs.get("target_url", "").strip()
        err = _validate_target_url(target_url)
        if err:
            return ToolResult(success=False, data=err, error=err)

        templates = kwargs.get("templates") or ""
        severity = kwargs.get("severity") or "critical,high,medium"
        tags = kwargs.get("tags") or ""
        rate_limit = int(kwargs.get("rate_limit") or 50)
        timeout = int(kwargs.get("timeout") or 300)
        max_results = int(kwargs.get("max_results") or 50)

        # 组装 nuclei 命令
        cmd_parts = [
            "nuclei",
            "-u", shlex.quote(target_url),
            "-jsonl",           # 每行一个 JSON, 便于解析
            "-silent",          # 静默进度
            "-no-color",
            "-disable-update-check",
            "-rate-limit", str(rate_limit),
            "-timeout", "10",   # 单请求超时
        ]
        if severity:
            cmd_parts += ["-severity", shlex.quote(severity)]
        if templates:
            cmd_parts += ["-t", shlex.quote(templates)]
        if tags:
            cmd_parts += ["-tags", shlex.quote(tags)]

        command = " ".join(cmd_parts)
        logger.info(f"[Nuclei] target={target_url} cmd={command}")

        # 沙箱执行（DAST 需要出网 → bridge，镜像用 nuclei 官方，entrypoint 清空走 sh -c）
        try:
            result = await self.sandbox_manager.execute_tool_command(
                command=command,
                host_workdir=os.getcwd(),  # nuclei 不需要项目挂载，但 SandboxManager 要求路径存在
                timeout=timeout,
                network_mode="bridge",
                image=self.NUCLEI_IMAGE,
                entrypoint=[""],  # 清空 nuclei 镜像的默认 ENTRYPOINT
            )
        except Exception as e:
            msg = f"Nuclei 执行异常: {e}"
            logger.exception(msg)
            return ToolResult(success=False, data=msg, error=msg)

        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""
        exit_code = result.get("exit_code", -1)

        # nuclei 无 finding 时 exit_code=0 且 stdout 为空；有 finding 也是 exit_code=0
        if exit_code not in (0,) and not stdout:
            error_msg = (stderr[:500] or f"exit_code={exit_code}")
            return ToolResult(
                success=False,
                data=f"Nuclei 执行失败: {error_msg}",
                error=error_msg,
            )

        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(findings) >= max_results:
                break

        if not findings:
            return ToolResult(
                success=True,
                data=f"Nuclei 扫描完成，未发现问题 (target={target_url}, severity={severity})",
                metadata={"findings_count": 0, "target": target_url},
            )

        # 结构化摘要 + 精简展示
        out = [f"🎯 Nuclei DAST 结果 (target={target_url})", f"共 {len(findings)} 条 finding:\n"]
        icon = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}
        summary_findings = []
        for f in findings:
            info = f.get("info") or {}
            sev = (info.get("severity") or "info").lower()
            tid = f.get("template-id") or "unknown"
            name = info.get("name") or tid
            matched = f.get("matched-at") or f.get("host") or ""
            out.append(f"{icon.get(sev, '⚪')} [{sev.upper()}] {name}  ({tid})")
            out.append(f"    命中: {matched}")
            if info.get("description"):
                out.append(f"    描述: {info['description'][:200]}")
            summary_findings.append({
                "template_id": tid,
                "name": name,
                "severity": sev,
                "matched_at": matched,
                "tags": info.get("tags"),
                "cve_ids": (info.get("classification") or {}).get("cve-id"),
                "cwe_ids": (info.get("classification") or {}).get("cwe-id"),
            })

        return ToolResult(
            success=True,
            data="\n".join(out),
            metadata={
                "findings_count": len(findings),
                "target": target_url,
                "findings": summary_findings[:20],
            },
        )


# ==================================================================
# PlaywrightProbeTool
# ==================================================================
class PlaywrightProbeArgs(BaseModel):
    target_url: str = Field(..., description="待探测 URL, 例如 https://example.com")
    timeout: int = Field(default=45, description="页面加载超时秒数")
    wait_ms: int = Field(default=2000, description="load 后额外等待毫秒, 便于 SPA 挂载")
    user_agent: Optional[str] = Field(default=None, description="自定义 UA")
    extract_scripts: bool = Field(default=True, description="是否抓取 <script src> 列表")


class PlaywrightProbeTool(AgentTool):
    """
    Playwright 无头 Chromium 探测：抓渲染后 DOM 摘要、链接、表单、脚本、
    以及 window.__ROUTES__ / vue-router / react-router 常见路由暴露点。
    面向 Vue/React SPA — 弥补 curl 拿不到渲染内容的短板。
    """

    PLAYWRIGHT_IMAGE = "mcr.microsoft.com/playwright:v1.44.0-jammy"

    def __init__(self, sandbox_manager: Any):
        super().__init__()
        self.sandbox_manager = sandbox_manager

    @property
    def name(self) -> str:
        return "playwright_probe"

    @property
    def description(self) -> str:
        return """使用无头 Chromium (Playwright) 访问目标 URL, 抓取:
- 渲染后 DOM 中的 <a href>, <form action>, <script src>
- 常见 SPA 路由表 (vue-router / react-router / window.__ROUTES__)
- 页面标题、meta CSP、cookie 属性
- console.error / uncaught 异常

参数:
- target_url (必填)
- timeout: 页面加载超时秒数, 默认 45
- wait_ms: 加载后额外等待毫秒, 默认 2000 (SPA 挂载)
- user_agent: 自定义 UA
- extract_scripts: 是否抓 script src, 默认 true

使用场景:
- 前端 Vue/React 项目审计, 找 SPA 路由入口
- 找 DOM 上的表单/接口调用做 XSS 面向面
- 抓渲染后的第三方 JS, 交叉 SCA / SBOM

⚠️ 仅在已授权的目标上运行。"""

    @property
    def args_schema(self):
        return PlaywrightProbeArgs

    def _build_probe_script(
        self,
        target_url: str,
        timeout_ms: int,
        wait_ms: int,
        user_agent: Optional[str],
        extract_scripts: bool,
    ) -> str:
        """
        在容器内执行的 Node.js 脚本 (Playwright 已在官方镜像中预装)。
        输出唯一一行 JSON, 便于外部 parse。
        """
        ua_line = f"userAgent: {json.dumps(user_agent)}," if user_agent else ""
        return f"""
const {{ chromium }} = require('playwright');
(async () => {{
  const errors = [];
  const scriptsSrc = [];
  try {{
    const browser = await chromium.launch({{ headless: true, args: ['--no-sandbox'] }});
    const context = await browser.newContext({{ {ua_line} ignoreHTTPSErrors: true }});
    const page = await context.newPage();
    page.on('pageerror', e => errors.push(String(e.message)));
    page.on('console', msg => {{ if (msg.type() === 'error') errors.push(msg.text()); }});
    await page.goto({json.dumps(target_url)}, {{ waitUntil: 'load', timeout: {timeout_ms} }});
    await page.waitForTimeout({wait_ms});

    const data = await page.evaluate(({{ extractScripts }}) => {{
      const q = sel => Array.from(document.querySelectorAll(sel));
      const links = q('a[href]').slice(0, 200).map(a => a.getAttribute('href'));
      const forms = q('form').slice(0, 50).map(f => ({{
        action: f.getAttribute('action') || '',
        method: (f.getAttribute('method') || 'GET').toUpperCase(),
        inputs: Array.from(f.querySelectorAll('input,textarea,select'))
          .map(i => ({{ name: i.getAttribute('name'), type: i.getAttribute('type') }}))
          .slice(0, 30),
      }}));
      const scripts = extractScripts
        ? q('script[src]').slice(0, 100).map(s => s.getAttribute('src'))
        : [];
      const meta = {{}};
      q('meta[http-equiv]').forEach(m => {{
        meta[(m.getAttribute('http-equiv') || '').toLowerCase()] = m.getAttribute('content');
      }});
      // 常见 SPA 路由暴露
      let routes = null;
      try {{
        if (window.__ROUTES__) routes = window.__ROUTES__;
        else if (window.__vue_router && window.__vue_router.options) routes = window.__vue_router.options.routes;
      }} catch (e) {{}}
      return {{
        title: document.title,
        url: location.href,
        cookieHeader: document.cookie,
        links,
        forms,
        scripts,
        metaHttpEquiv: meta,
        routes,
        htmlBytes: document.documentElement.outerHTML.length,
      }};
    }}, {{ extractScripts: {str(extract_scripts).lower()} }});

    data.errors = errors.slice(0, 20);
    console.log('---PROBE_RESULT_BEGIN---');
    console.log(JSON.stringify(data));
    console.log('---PROBE_RESULT_END---');
    await browser.close();
  }} catch (e) {{
    console.log('---PROBE_RESULT_BEGIN---');
    console.log(JSON.stringify({{ error: String(e && e.message || e) }}));
    console.log('---PROBE_RESULT_END---');
    process.exit(1);
  }}
}})();
"""

    async def _execute(self, **kwargs) -> ToolResult:
        target_url = kwargs.get("target_url", "").strip()
        err = _validate_target_url(target_url)
        if err:
            return ToolResult(success=False, data=err, error=err)

        timeout_sec = int(kwargs.get("timeout") or 45)
        wait_ms = int(kwargs.get("wait_ms") or 2000)
        user_agent = kwargs.get("user_agent")
        extract_scripts = bool(kwargs.get("extract_scripts", True))

        script = self._build_probe_script(
            target_url=target_url,
            timeout_ms=timeout_sec * 1000,
            wait_ms=wait_ms,
            user_agent=user_agent,
            extract_scripts=extract_scripts,
        )

        # 写脚本到容器内 /tmp 并执行；用 base64 传递避免 shell 转义
        import base64
        b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        command = (
            f"echo {b64} | base64 -d > /tmp/probe.js && "
            "node /tmp/probe.js"
        )

        try:
            result = await self.sandbox_manager.execute_tool_command(
                command=command,
                host_workdir=os.getcwd(),
                timeout=timeout_sec + 30,
                network_mode="bridge",
                image=self.PLAYWRIGHT_IMAGE,
                entrypoint=[""],
            )
        except Exception as e:
            msg = f"Playwright 探测异常: {e}"
            logger.exception(msg)
            return ToolResult(success=False, data=msg, error=msg)

        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""

        # 从 stdout 提取 JSON 段
        begin_marker = "---PROBE_RESULT_BEGIN---"
        end_marker = "---PROBE_RESULT_END---"
        payload = None
        if begin_marker in stdout and end_marker in stdout:
            raw = stdout.split(begin_marker, 1)[1].split(end_marker, 1)[0].strip()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as e:
                return ToolResult(
                    success=False,
                    data=f"无法解析探测 JSON: {e}",
                    error=str(e),
                    metadata={"stdout_preview": stdout[:500]},
                )

        if payload is None:
            return ToolResult(
                success=False,
                data=f"Playwright 未产生结构化输出\nstderr: {stderr[:500]}",
                error="no probe result",
            )

        if payload.get("error"):
            return ToolResult(
                success=False,
                data=f"Playwright 探测失败: {payload['error']}",
                error=payload["error"],
            )

        # 渲染摘要
        title = payload.get("title") or ""
        links = payload.get("links") or []
        forms = payload.get("forms") or []
        scripts = payload.get("scripts") or []
        routes = payload.get("routes")
        errors = payload.get("errors") or []

        out = [
            f"🌐 Playwright 探测 (final={payload.get('url')})",
            f"标题: {title}",
            f"HTML 大小: {payload.get('htmlBytes')} bytes",
            f"链接数: {len(links)}, 表单数: {len(forms)}, 外链脚本: {len(scripts)}",
        ]
        if forms:
            out.append("\n📝 表单 (前 5 条):")
            for f in forms[:5]:
                out.append(f"  - {f.get('method')} {f.get('action') or '(same-page)'} "
                           f"inputs={[i.get('name') for i in f.get('inputs') or []]}")
        if scripts:
            out.append("\n📜 外链脚本 (前 10 条):")
            for s in scripts[:10]:
                out.append(f"  - {s}")
        if routes:
            out.append(f"\n🧭 检测到 SPA 路由表: {json.dumps(routes)[:500]}")
        if payload.get("metaHttpEquiv"):
            out.append(f"\n🛡️ meta http-equiv: {payload['metaHttpEquiv']}")
        if errors:
            out.append(f"\n⚠️ 页面 console/pageerror: {errors[:5]}")

        return ToolResult(
            success=True,
            data="\n".join(out),
            metadata={
                "target": target_url,
                "final_url": payload.get("url"),
                "title": title,
                "links_count": len(links),
                "forms_count": len(forms),
                "scripts_count": len(scripts),
                "has_spa_routes": routes is not None,
                "errors_count": len(errors),
                "sample": {
                    "forms": forms[:10],
                    "scripts": scripts[:20],
                    "routes": routes,
                },
            },
        )
