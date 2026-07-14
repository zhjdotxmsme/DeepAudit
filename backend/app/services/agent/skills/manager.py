"""
SkillManager - 技能包管理（导入、删除、远程同步）

支持：
- 从 Git URL 克隆/更新
- 从 Zip 文件解压导入
- 从远程 Registry 获取索引并安装
- 删除本地 Skill
"""

from __future__ import annotations

import datetime as _dt
import io
import json
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from .base import Skill, load_skill_from_dir
from .loader import SkillLoader, get_default_loader

logger = logging.getLogger(__name__)

# 默认技能仓库 Registry（JSON 索引）
DEFAULT_REGISTRY_URL = "https://raw.githubusercontent.com/deepaudit/skills-registry/main/index.json"


def _now_iso() -> str:
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _write_source_sidecar(skill_dir: Path, source: Dict[str, Any]) -> None:
    """写入 .skill-source.json 侧车（记录来源+时间戳，供后续更新使用）"""
    try:
        (skill_dir / ".skill-source.json").write_text(
            json.dumps(source, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError as e:
        logger.warning("Write skill source sidecar failed at %s: %s", skill_dir, e)


def _get_writable_skills_dir() -> Path:
    """获取可写的 skills 目录（优先使用 DEEPAUDIT_SKILLS_DIR 第一个路径）"""
    env = os.environ.get("DEEPAUDIT_SKILLS_DIR", "").strip()
    if env:
        first = env.split(os.pathsep)[0].strip()
        if first:
            p = Path(first)
            p.mkdir(parents=True, exist_ok=True)
            return p

    # fallback: 项目根 skills/
    try:
        here = Path(__file__).resolve()
        backend_dir = here.parents[4]
        repo_root = backend_dir.parent
        p = repo_root / "skills"
        p.mkdir(parents=True, exist_ok=True)
        return p
    except IndexError:
        pass

    # last resort: builtin 同级 writable
    p = Path(__file__).parent.parent / "skills_writable"
    p.mkdir(parents=True, exist_ok=True)
    return p


class SkillManager:
    """Skill 包管理器：负责外部导入、删除、Registry 查询"""

    def __init__(self, loader: Optional[SkillLoader] = None):
        self.loader = loader or get_default_loader()
        self.skills_dir = _get_writable_skills_dir()

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------
    async def fetch_registry(
        self, registry_url: Optional[str] = None, timeout: float = 30.0
    ) -> List[Dict[str, Any]]:
        """从远程 Registry 拉取可用 Skill 列表"""
        url = registry_url or os.environ.get("SKILL_REGISTRY_URL", DEFAULT_REGISTRY_URL)
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
                skills = data.get("skills", []) if isinstance(data, dict) else []
                logger.info("Fetched %d skills from registry %s", len(skills), url)
                return skills
        except Exception as e:
            logger.warning("Fetch registry failed: %s", e)
            return []

    # ------------------------------------------------------------------
    # Import from Git
    # ------------------------------------------------------------------
    def import_from_git(
        self,
        git_url: str,
        name: Optional[str] = None,
        branch: str = "main",
        subdir: str = "",
    ) -> Skill:
        """从 Git URL 克隆 Skill 包到本地 skills 目录"""
        parsed = urlparse(git_url)
        inferred_name = name or Path(parsed.path).stem.replace(".git", "")
        if not inferred_name:
            raise ValueError("Cannot infer skill name from URL, please provide 'name'")

        target_dir = self.skills_dir / inferred_name

        # 保留旧安装时间戳（如果存在）以便更新时区分 "首次安装" 与 "更新"
        prior_installed_at: Optional[str] = None
        prior_sidecar = target_dir / ".skill-source.json"
        if prior_sidecar.is_file():
            try:
                prior = json.loads(prior_sidecar.read_text(encoding="utf-8"))
                if isinstance(prior, dict):
                    prior_installed_at = prior.get("installed_at")
            except (OSError, json.JSONDecodeError):
                prior_installed_at = None

        # 如果已存在，先删除旧版本
        if target_dir.exists():
            logger.info("Removing existing skill '%s' for update", inferred_name)
            shutil.rmtree(target_dir, ignore_errors=True)

        commit_sha: Optional[str] = None
        with tempfile.TemporaryDirectory() as tmp:
            clone_dir = Path(tmp) / "clone"
            cmd = [
                "git", "clone",
                "--depth", "1",
                "--branch", branch,
                git_url,
                str(clone_dir),
            ]
            logger.info("Cloning skill from %s", git_url)
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                raise RuntimeError(f"git clone failed: {result.stderr}")

            # 记录当前 commit sha 以便 "已是最新" 检测
            try:
                sha_result = subprocess.run(
                    ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
                    capture_output=True, text=True, check=False,
                )
                if sha_result.returncode == 0:
                    commit_sha = sha_result.stdout.strip() or None
            except OSError:
                pass

            src = clone_dir / subdir if subdir else clone_dir
            if not (src / "SKILL.md").is_file():
                raise FileNotFoundError(f"SKILL.md not found in cloned repo (subdir='{subdir}')")

            shutil.copytree(src, target_dir, dirs_exist_ok=True)

        now = _now_iso()
        sidecar = {
            "type": "git",
            "git_url": git_url,
            "branch": branch,
            "subdir": subdir,
            "commit": commit_sha,
            "installed_at": prior_installed_at or now,
            "updated_at": now,
        }
        _write_source_sidecar(target_dir, sidecar)

        skill = load_skill_from_dir(target_dir)
        self.loader.reload()
        logger.info("Imported skill '%s' from git to %s", skill.name, target_dir)
        return skill

    # ------------------------------------------------------------------
    # Import from Zip
    # ------------------------------------------------------------------
    def import_from_zip(self, zip_bytes: bytes, name: Optional[str] = None) -> Skill:
        """从 Zip 字节导入 Skill 包"""
        with tempfile.TemporaryDirectory() as tmp:
            extract_dir = Path(tmp) / "extract"
            extract_dir.mkdir()

            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                zf.extractall(extract_dir)

            # 探测 SKILL.md 位置（可能在根目录或一级子目录）
            skill_md = extract_dir / "SKILL.md"
            if not skill_md.is_file():
                # 尝试找一级子目录
                for sub in extract_dir.iterdir():
                    if sub.is_dir() and (sub / "SKILL.md").is_file():
                        skill_md = sub / "SKILL.md"
                        extract_dir = sub
                        break

            if not skill_md.is_file():
                raise FileNotFoundError("SKILL.md not found in zip archive")

            loaded = load_skill_from_dir(extract_dir)
            final_name = name or loaded.metadata.name
            target_dir = self.skills_dir / final_name

            # 保留旧安装时间
            prior_installed_at: Optional[str] = None
            prior_sidecar = target_dir / ".skill-source.json"
            if prior_sidecar.is_file():
                try:
                    prior = json.loads(prior_sidecar.read_text(encoding="utf-8"))
                    if isinstance(prior, dict):
                        prior_installed_at = prior.get("installed_at")
                except (OSError, json.JSONDecodeError):
                    prior_installed_at = None

            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)

            shutil.copytree(extract_dir, target_dir, dirs_exist_ok=True)

        now = _now_iso()
        _write_source_sidecar(target_dir, {
            "type": "zip",
            "installed_at": prior_installed_at or now,
            "updated_at": now,
        })

        skill = load_skill_from_dir(target_dir)
        self.loader.reload()
        logger.info("Imported skill '%s' from zip to %s", skill.name, target_dir)
        return skill

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------
    def delete_skill(self, name: str) -> bool:
        """删除本地 Skill 包"""
        target_dir = self.skills_dir / name
        if not target_dir.exists():
            # 尝试在其他搜索目录里找并删除
            for root in self.loader.search_dirs:
                candidate = root / name
                if candidate.exists():
                    target_dir = candidate
                    break
            else:
                logger.warning("Skill '%s' not found for deletion", name)
                return False

        shutil.rmtree(target_dir, ignore_errors=True)
        self.loader.reload()
        logger.info("Deleted skill '%s' from %s", name, target_dir)
        return True

    # ------------------------------------------------------------------
    # Update from source
    # ------------------------------------------------------------------
    def update_skill(self, name: str, git_url: Optional[str] = None) -> Skill:
        """更新指定 Skill。优先使用 .skill-source.json 侧车里的来源（一键更新）；缺失时才要求手动传 git_url"""
        skill = self.loader.get(name)
        if not skill:
            raise ValueError(f"Skill '{name}' not found")

        source = skill.source or {}
        source_type = source.get("type")

        # 优先使用侧车里的 git 元数据（一键更新）
        if source_type == "git" and source.get("git_url"):
            return self.import_from_git(
                source["git_url"],
                name=name,
                branch=source.get("branch") or "main",
                subdir=source.get("subdir") or "",
            )

        # 显式传入的 git_url 兜底（历史遗留 skill 无侧车）
        if git_url:
            return self.import_from_git(git_url, name=name)

        raise ValueError(
            f"Skill '{name}' has no recorded git source; "
            "please provide 'git_url' or reimport from git first."
        )

    def check_updates(self) -> List[Dict[str, Any]]:
        """检查所有已安装 Skill 的远端更新（对比 git ls-remote HEAD sha 与本地 commit）"""
        results: List[Dict[str, Any]] = []
        for skill in self.loader.list_skills():
            source = skill.source or {}
            if source.get("type") != "git" or not source.get("git_url"):
                continue
            git_url = source["git_url"]
            branch = source.get("branch") or "main"
            local_commit = source.get("commit")
            entry: Dict[str, Any] = {
                "name": skill.name,
                "git_url": git_url,
                "branch": branch,
                "local_commit": local_commit,
                "remote_commit": None,
                "has_update": False,
                "error": None,
            }
            try:
                r = subprocess.run(
                    ["git", "ls-remote", git_url, f"refs/heads/{branch}"],
                    capture_output=True, text=True, check=False, timeout=30,
                )
                if r.returncode == 0 and r.stdout.strip():
                    remote_commit = r.stdout.strip().split()[0]
                    entry["remote_commit"] = remote_commit
                    entry["has_update"] = bool(local_commit) and remote_commit != local_commit
                else:
                    entry["error"] = r.stderr.strip() or "ls-remote empty"
            except (OSError, subprocess.TimeoutExpired) as e:  # noqa: BLE001
                entry["error"] = str(e)
            results.append(entry)
        return results


# 默认管理器单例
_default_manager: Optional[SkillManager] = None


def get_default_manager() -> SkillManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = SkillManager()
    return _default_manager
