"""
Skill 数据模型 + SKILL.md 解析器

一个 Skill 目录形如：
    skills/springboot-audit/
        SKILL.md
        references/
            spel-injection.md
            actuator-exposure.md
        scripts/
            check_actuator.sh

SKILL.md 结构：
    ---
    name: springboot-audit
    version: 1.0.0
    category: framework
    description: Spring Boot 安全审计知识包
    targets:
      languages: [java, kotlin]
      frameworks: [springboot, spring]
    cwe_tags: [CWE-917, CWE-502, CWE-16]
    severity_focus: [critical, high]
    references:
      - references/spel-injection.md
    scripts: []
    ---

    # Spring Boot 安全审计

    正文 Markdown...
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)


@dataclass
class SkillFile:
    """Skill 附带的引用文件或脚本"""

    path: str  # 相对 skill 根目录的路径
    kind: str  # reference | script
    size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SkillMetadata:
    """Skill 元数据（来自 SKILL.md frontmatter）"""

    name: str
    version: str = "0.1.0"
    category: str = "general"
    description: str = ""
    author: str = ""
    targets: Dict[str, List[str]] = field(default_factory=dict)
    cwe_tags: List[str] = field(default_factory=list)
    severity_focus: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SkillMetadata":
        if not data or not data.get("name"):
            raise ValueError("SKILL.md frontmatter must include 'name'")
        return cls(
            name=str(data["name"]).strip(),
            version=str(data.get("version", "0.1.0")),
            category=str(data.get("category", "general")),
            description=str(data.get("description", "")),
            author=str(data.get("author", "")),
            targets=dict(data.get("targets") or {}),
            cwe_tags=list(data.get("cwe_tags") or []),
            severity_focus=list(data.get("severity_focus") or []),
            tags=list(data.get("tags") or []),
            references=list(data.get("references") or []),
            scripts=list(data.get("scripts") or []),
        )


@dataclass
class Skill:
    """一个完整的 Skill 包"""

    metadata: SkillMetadata
    body: str  # SKILL.md frontmatter 之后的 Markdown 正文
    root_dir: Path
    files: List[SkillFile] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.metadata.name

    def summary(self) -> Dict[str, Any]:
        """轻量摘要 - 用于列表接口"""
        return {
            "name": self.metadata.name,
            "version": self.metadata.version,
            "category": self.metadata.category,
            "description": self.metadata.description,
            "targets": self.metadata.targets,
            "cwe_tags": self.metadata.cwe_tags,
            "severity_focus": self.metadata.severity_focus,
            "tags": self.metadata.tags,
            "reference_count": sum(1 for f in self.files if f.kind == "reference"),
            "script_count": sum(1 for f in self.files if f.kind == "script"),
        }

    def to_dict(self, include_body: bool = True) -> Dict[str, Any]:
        data = {
            "metadata": self.metadata.to_dict(),
            "files": [f.to_dict() for f in self.files],
            "root_dir": str(self.root_dir),
        }
        if include_body:
            data["body"] = self.body
        return data

    def read_reference(self, rel_path: str) -> Optional[str]:
        """读取一个引用文件的内容，防目录穿越"""
        target = (self.root_dir / rel_path).resolve()
        try:
            target.relative_to(self.root_dir.resolve())
        except ValueError:
            logger.warning("Skill %s reference escape attempt: %s", self.name, rel_path)
            return None
        if not target.is_file():
            return None
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            logger.warning("Read skill reference failed %s: %s", target, e)
            return None

    def matches(self, keyword: str) -> bool:
        """粗匹配：keyword 命中 metadata / body 任一部分"""
        kw = keyword.lower().strip()
        if not kw:
            return False
        md = self.metadata
        haystack_parts: List[str] = [
            md.name,
            md.description,
            md.category,
            " ".join(md.cwe_tags),
            " ".join(md.tags),
        ]
        for values in md.targets.values():
            haystack_parts.append(" ".join(values))
        haystack_parts.append(self.body)
        haystack = "\n".join(haystack_parts).lower()
        return kw in haystack


def _parse_frontmatter(text: str) -> tuple[Dict[str, Any], str]:
    """从 SKILL.md 抠出 YAML frontmatter + 正文"""
    m = _FRONTMATTER_RE.match(text.lstrip("\ufeff"))
    if not m:
        raise ValueError("SKILL.md missing YAML frontmatter (--- ... ---)")
    fm_raw, body = m.group(1), m.group(2)
    try:
        fm = yaml.safe_load(fm_raw) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"SKILL.md frontmatter YAML parse error: {e}") from e
    if not isinstance(fm, dict):
        raise ValueError("SKILL.md frontmatter must be a YAML mapping")
    return fm, body.strip()


def _collect_skill_files(root: Path) -> List[SkillFile]:
    files: List[SkillFile] = []
    for kind, subdir in (("reference", "references"), ("script", "scripts")):
        sub = root / subdir
        if not sub.is_dir():
            continue
        for p in sub.rglob("*"):
            if not p.is_file():
                continue
            try:
                rel = p.relative_to(root).as_posix()
            except ValueError:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            files.append(SkillFile(path=rel, kind=kind, size=size))
    return files


def load_skill_from_dir(skill_dir: Path) -> Skill:
    """从一个 skill 目录加载 Skill 对象"""
    skill_dir = skill_dir.resolve()
    if not skill_dir.is_dir():
        raise FileNotFoundError(f"Not a skill directory: {skill_dir}")

    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        raise FileNotFoundError(f"Missing SKILL.md in {skill_dir}")

    text = skill_md.read_text(encoding="utf-8", errors="replace")
    fm, body = _parse_frontmatter(text)
    metadata = SkillMetadata.from_dict(fm)
    files = _collect_skill_files(skill_dir)
    return Skill(metadata=metadata, body=body, root_dir=skill_dir, files=files)
