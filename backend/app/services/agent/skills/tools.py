"""
Skill Agent Tools - 让 Agent 在运行时列出/查询/搜索 Skill 包
"""

from __future__ import annotations

import logging
from typing import Optional, Type

from pydantic import BaseModel, Field

from ..tools.base import AgentTool, ToolResult
from .loader import SkillLoader, get_default_loader

logger = logging.getLogger(__name__)


def _format_skill_full(skill, max_body: int = 6000) -> str:
    md = skill.metadata
    parts = [
        f"# {md.name} (v{md.version})",
        f"category: {md.category}",
    ]
    if md.description:
        parts.append(f"description: {md.description}")
    if md.targets:
        for k, v in md.targets.items():
            parts.append(f"targets.{k}: {', '.join(v) if isinstance(v, list) else v}")
    if md.cwe_tags:
        parts.append(f"cwe: {', '.join(md.cwe_tags)}")
    if md.severity_focus:
        parts.append(f"severity_focus: {', '.join(md.severity_focus)}")
    if md.tags:
        parts.append(f"tags: {', '.join(md.tags)}")

    ref_files = [f.path for f in skill.files if f.kind == "reference"]
    if ref_files:
        parts.append(f"references: {', '.join(ref_files)}")
    script_files = [f.path for f in skill.files if f.kind == "script"]
    if script_files:
        parts.append(f"scripts: {', '.join(script_files)}")

    parts.append("")
    body = skill.body or ""
    if len(body) > max_body:
        body = body[:max_body] + f"\n... (truncated, total {len(body)} chars)"
    parts.append(body)
    return "\n".join(parts)


class ListSkillsInput(BaseModel):
    category: Optional[str] = Field(
        None,
        description="按 category 过滤，例如 framework / vulnerability / language / general",
    )


class ListSkillsTool(AgentTool):
    """列出所有可用的 Skill 包（可插拔的安全审计知识包）"""

    def __init__(self, loader: Optional[SkillLoader] = None):
        super().__init__()
        self._loader = loader or get_default_loader()

    @property
    def name(self) -> str:
        return "list_skills"

    @property
    def description(self) -> str:
        return (
            "列出所有可用的 Skill 包（可插拔的安全审计知识包）。"
            "每个 Skill 包含针对某个框架 / 漏洞类型 / 语言的专业审计知识。"
            "使用后可用 `get_skill` 拉取完整正文，或用 `search_skills` 按关键词过滤。"
        )

    @property
    def args_schema(self) -> Type[BaseModel]:
        return ListSkillsInput

    async def _execute(self, category: Optional[str] = None) -> ToolResult:
        try:
            skills = self._loader.list_skills(category=category)
            if not skills:
                return ToolResult(
                    success=True,
                    data="当前没有可用的 Skill 包。可在项目根 skills/ 目录添加 SKILL.md 后重启服务。",
                    metadata={"count": 0, "category": category},
                )
            lines = [f"共 {len(skills)} 个 Skill:"]
            for s in skills:
                summary = s.summary()
                targets = summary.get("targets") or {}
                tgt_str = "; ".join(
                    f"{k}={','.join(v) if isinstance(v, list) else v}" for k, v in targets.items()
                )
                lines.append(
                    f"- {summary['name']} (v{summary['version']}, {summary['category']})"
                    f" | {summary['description']}"
                    + (f" | targets: {tgt_str}" if tgt_str else "")
                )
            return ToolResult(
                success=True,
                data="\n".join(lines),
                metadata={
                    "count": len(skills),
                    "category": category,
                    "skills": [s.summary() for s in skills],
                },
            )
        except Exception as e:  # noqa: BLE001
            logger.error("list_skills failed: %s", e)
            return ToolResult(success=False, error=f"list_skills failed: {e}")


class GetSkillInput(BaseModel):
    name: str = Field(..., description="Skill 名称（来自 SKILL.md 的 frontmatter.name）")
    reference: Optional[str] = Field(
        None,
        description="可选：读取该 Skill 中某个 reference 文件的内容（相对路径，如 references/spel-injection.md）",
    )


class GetSkillTool(AgentTool):
    """获取指定 Skill 的完整内容"""

    def __init__(self, loader: Optional[SkillLoader] = None):
        super().__init__()
        self._loader = loader or get_default_loader()

    @property
    def name(self) -> str:
        return "get_skill"

    @property
    def description(self) -> str:
        return (
            "获取指定 Skill 包的完整审计知识（Markdown 正文 + 元数据）。"
            "参数 `reference` 可用于加载 Skill 内的具体参考文档，例如某个 CWE 的详细检测方法。"
        )

    @property
    def args_schema(self) -> Type[BaseModel]:
        return GetSkillInput

    async def _execute(self, name: str, reference: Optional[str] = None) -> ToolResult:
        skill = self._loader.get(name)
        if not skill:
            available = [s.name for s in self._loader.list_skills()]
            return ToolResult(
                success=True,
                data=f"未找到 Skill '{name}'。可用: {', '.join(available) or '(空)'}",
                metadata={"available": available},
            )

        if reference:
            content = skill.read_reference(reference)
            if content is None:
                return ToolResult(
                    success=False,
                    error=f"Skill '{name}' 的引用文件 '{reference}' 不存在或不可读",
                )
            output = f"# {skill.name} :: {reference}\n\n{content}"
            return ToolResult(
                success=True,
                data=output,
                metadata={"skill": skill.summary(), "reference": reference},
            )

        return ToolResult(
            success=True,
            data=_format_skill_full(skill),
            metadata={"skill": skill.summary()},
        )


class SearchSkillsInput(BaseModel):
    keyword: str = Field(..., description="搜索关键词，例如 'springboot' / 'SpEL' / 'v-html'")
    limit: int = Field(5, description="返回结果数量上限", ge=1, le=20)


class SearchSkillsTool(AgentTool):
    """按关键词搜索 Skill 包"""

    def __init__(self, loader: Optional[SkillLoader] = None):
        super().__init__()
        self._loader = loader or get_default_loader()

    @property
    def name(self) -> str:
        return "search_skills"

    @property
    def description(self) -> str:
        return "按关键词搜索 Skill 包（匹配名称 / 描述 / 标签 / 正文）。用于快速找到相关领域知识。"

    @property
    def args_schema(self) -> Type[BaseModel]:
        return SearchSkillsInput

    async def _execute(self, keyword: str, limit: int = 5) -> ToolResult:
        matches = self._loader.search(keyword, limit=limit)
        if not matches:
            return ToolResult(
                success=True,
                data=f"未找到匹配 '{keyword}' 的 Skill。",
                metadata={"keyword": keyword, "count": 0},
            )
        lines = [f"匹配 '{keyword}' 共 {len(matches)} 个 Skill:"]
        for s in matches:
            lines.append(f"- {s.name} ({s.metadata.category}): {s.metadata.description}")
        return ToolResult(
            success=True,
            data="\n".join(lines),
            metadata={
                "keyword": keyword,
                "count": len(matches),
                "skills": [s.summary() for s in matches],
            },
        )
