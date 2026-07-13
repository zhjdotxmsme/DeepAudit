"""
Skills 系统 - 可插拔的安全审计知识包

参考 Strix / Claude Skills 设计，用文件系统承载可插拔的领域知识包。
一个 Skill 是一个目录，包含：
    SKILL.md         - YAML frontmatter + Markdown 正文
    references/      - 可选：详细知识参考文档
    scripts/         - 可选：辅助脚本

Skill 由 SkillLoader 在启动时/按需扫描发现，Agent 通过
`list_skills` / `get_skill` / `search_skills` 三个工具在运行时查询。
"""

from .base import Skill, SkillMetadata, SkillFile, load_skill_from_dir
from .loader import SkillLoader, get_default_loader
from .tools import ListSkillsTool, GetSkillTool, SearchSkillsTool

__all__ = [
    "Skill",
    "SkillMetadata",
    "SkillFile",
    "load_skill_from_dir",
    "SkillLoader",
    "get_default_loader",
    "ListSkillsTool",
    "GetSkillTool",
    "SearchSkillsTool",
]
