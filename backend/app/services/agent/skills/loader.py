"""
SkillLoader - 扫描一个或多个 skills 根目录，把 Skill 收进内存

搜索顺序（先扫的优先，同名后到覆盖前者）：
    1. 环境变量 DEEPAUDIT_SKILLS_DIR（可用 os.pathsep 分隔多个）
    2. 项目根 `skills/`（相对于 backend/ 的上一级）
    3. 内置 `backend/app/services/agent/skills/builtin/`
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from threading import RLock
from typing import Dict, List, Optional

from .base import Skill, load_skill_from_dir

logger = logging.getLogger(__name__)


def _default_search_dirs() -> List[Path]:
    dirs: List[Path] = []

    env = os.environ.get("DEEPAUDIT_SKILLS_DIR", "").strip()
    if env:
        for part in env.split(os.pathsep):
            part = part.strip()
            if part:
                dirs.append(Path(part))

    # backend/app/services/agent/skills/loader.py -> backend/ = parents[4]
    here = Path(__file__).resolve()
    try:
        backend_dir = here.parents[4]
        repo_root = backend_dir.parent
        dirs.append(repo_root / "skills")
    except IndexError:
        pass

    dirs.append(here.parent / "builtin")
    return dirs


class SkillLoader:
    """
    Skill 加载器。线程安全。惰性初始化 + 手动 reload。
    """

    def __init__(self, search_dirs: Optional[List[Path]] = None):
        self._search_dirs: List[Path] = [
            Path(p) for p in (search_dirs if search_dirs is not None else _default_search_dirs())
        ]
        self._skills: Dict[str, Skill] = {}
        self._loaded = False
        self._lock = RLock()

    @property
    def search_dirs(self) -> List[Path]:
        return list(self._search_dirs)

    def load(self, force: bool = False) -> Dict[str, Skill]:
        with self._lock:
            if self._loaded and not force:
                return dict(self._skills)

            loaded: Dict[str, Skill] = {}
            for root in self._search_dirs:
                if not root.is_dir():
                    logger.debug("Skills dir not found, skip: %s", root)
                    continue
                for entry in sorted(root.iterdir()):
                    if not entry.is_dir():
                        continue
                    if entry.name.startswith((".", "_")):
                        continue
                    if not (entry / "SKILL.md").is_file():
                        continue
                    try:
                        skill = load_skill_from_dir(entry)
                    except Exception as e:  # noqa: BLE001
                        logger.warning("Load skill failed at %s: %s", entry, e)
                        continue
                    if skill.name in loaded:
                        logger.info(
                            "Skill '%s' overridden by %s (previous: %s)",
                            skill.name,
                            skill.root_dir,
                            loaded[skill.name].root_dir,
                        )
                    loaded[skill.name] = skill

            self._skills = loaded
            self._loaded = True
            logger.info(
                "SkillLoader loaded %d skill(s) from %d search dir(s)",
                len(loaded),
                len(self._search_dirs),
            )
            return dict(self._skills)

    def reload(self) -> Dict[str, Skill]:
        return self.load(force=True)

    def list_skills(self, category: Optional[str] = None) -> List[Skill]:
        skills = list(self.load().values())
        if category:
            cat = category.lower()
            skills = [s for s in skills if s.metadata.category.lower() == cat]
        skills.sort(key=lambda s: (s.metadata.category, s.metadata.name))
        return skills

    def get(self, name: str) -> Optional[Skill]:
        return self.load().get(name)

    def search(self, keyword: str, limit: int = 10) -> List[Skill]:
        matches = [s for s in self.load().values() if s.matches(keyword)]
        matches.sort(key=lambda s: (s.metadata.category, s.metadata.name))
        return matches[: max(1, limit)]


_default_loader: Optional[SkillLoader] = None
_default_lock = RLock()


def get_default_loader() -> SkillLoader:
    global _default_loader
    with _default_lock:
        if _default_loader is None:
            _default_loader = SkillLoader()
        return _default_loader
