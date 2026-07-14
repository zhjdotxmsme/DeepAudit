"""
Skills API - 可插拔的审计知识包管理端点

Skills 由文件系统承载（skills/{name}/SKILL.md + references/），
本端点提供只读访问 + 手动 reload + 外部导入（Git/Zip/Registry）。
"""

import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from pydantic import BaseModel, Field

from app.api import deps
from app.models.user import User
from app.services.agent.skills import get_default_loader
from app.services.agent.skills.manager import get_default_manager

logger = logging.getLogger(__name__)
router = APIRouter()


class SkillSummary(BaseModel):
    name: str
    version: str
    category: str
    description: str
    targets: dict = {}
    cwe_tags: List[str] = []
    severity_focus: List[str] = []
    tags: List[str] = []
    reference_count: int = 0
    script_count: int = 0
    source: Dict[str, Any] = {}


class SkillDetail(SkillSummary):
    body: str
    references: List[str] = []
    scripts: List[str] = []
    root_dir: str


class SkillReferenceResponse(BaseModel):
    skill: str
    reference: str
    content: str


class ReloadResponse(BaseModel):
    count: int
    skills: List[str]
    search_dirs: List[str]


class ImportFromGitRequest(BaseModel):
    git_url: str = Field(..., description="Git 仓库地址，如 https://github.com/org/skill-name.git")
    name: Optional[str] = Field(None, description="Skill 名称（默认识别自 URL）")
    branch: str = Field("main", description="Git 分支")
    subdir: str = Field("", description="SKILL.md 在仓库中的子目录路径（为空则在根目录）")


class ImportFromRegistryRequest(BaseModel):
    registry_url: Optional[str] = Field(None, description="Registry 索引 URL（默认使用系统配置）")
    name: Optional[str] = Field(None, description="指定安装某个 Skill，为空则列出可用 Skill")


class RegistrySkillItem(BaseModel):
    name: str
    version: str
    description: str
    category: str
    source: str
    author: str = ""
    tags: List[str] = []


class RegistryListResponse(BaseModel):
    source: str
    skills: List[RegistrySkillItem]


class ImportResponse(BaseModel):
    success: bool
    name: str
    version: str
    category: str
    description: str
    root_dir: str


class DeleteResponse(BaseModel):
    success: bool
    name: str
    message: str


# ------------------------------------------------------------------
# 原有端点
# ------------------------------------------------------------------

@router.get("", response_model=List[SkillSummary])
async def list_skills(
    category: Optional[str] = Query(None, description="按 category 过滤"),
    keyword: Optional[str] = Query(None, description="关键词搜索（匹配 name/description/tags/body）"),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """列出所有已加载的 Skill 包"""
    loader = get_default_loader()
    if keyword:
        skills = loader.search(keyword, limit=100)
        if category:
            skills = [s for s in skills if s.metadata.category.lower() == category.lower()]
    else:
        skills = loader.list_skills(category=category)
    return [SkillSummary(**s.summary()) for s in skills]


@router.get("/reload", response_model=ReloadResponse)
async def reload_skills(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """强制重载 skills 目录"""
    loader = get_default_loader()
    loaded = loader.reload()
    return ReloadResponse(
        count=len(loaded),
        skills=sorted(loaded.keys()),
        search_dirs=[str(p) for p in loader.search_dirs],
    )


@router.get("/{name}", response_model=SkillDetail)
async def get_skill(
    name: str,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """获取指定 Skill 的完整内容"""
    loader = get_default_loader()
    skill = loader.get(name)
    if not skill:
        raise HTTPException(status_code=404, detail=f"Skill '{name}' not found")

    summary = skill.summary()
    return SkillDetail(
        **summary,
        body=skill.body,
        references=[f.path for f in skill.files if f.kind == "reference"],
        scripts=[f.path for f in skill.files if f.kind == "script"],
        root_dir=str(skill.root_dir),
    )


@router.get("/{name}/references/{ref_path:path}", response_model=SkillReferenceResponse)
async def get_skill_reference(
    name: str,
    ref_path: str,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """读取 Skill 内某个 reference 文件"""
    loader = get_default_loader()
    skill = loader.get(name)
    if not skill:
        raise HTTPException(status_code=404, detail=f"Skill '{name}' not found")

    rel = ref_path if ref_path.startswith("references/") else f"references/{ref_path}"
    content = skill.read_reference(rel)
    if content is None:
        raise HTTPException(
            status_code=404,
            detail=f"Reference '{ref_path}' not found in skill '{name}'",
        )
    return SkillReferenceResponse(skill=name, reference=rel, content=content)


# ------------------------------------------------------------------
# 新增：外部导入与管理
# ------------------------------------------------------------------

@router.post("/import/git", response_model=ImportResponse)
async def import_skill_from_git(
    req: ImportFromGitRequest,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """从 Git URL 导入 Skill 包"""
    try:
        manager = get_default_manager()
        skill = manager.import_from_git(
            git_url=req.git_url,
            name=req.name,
            branch=req.branch,
            subdir=req.subdir,
        )
        summary = skill.summary()
        return ImportResponse(
            success=True,
            name=skill.name,
            version=summary["version"],
            category=summary["category"],
            description=summary["description"],
            root_dir=str(skill.root_dir),
        )
    except Exception as e:
        logger.error("Import skill from git failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/import/zip", response_model=ImportResponse)
async def import_skill_from_zip(
    file: UploadFile = File(...),
    name: Optional[str] = None,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """从 Zip 文件导入 Skill 包"""
    try:
        contents = await file.read()
        manager = get_default_manager()
        skill = manager.import_from_zip(contents, name=name)
        summary = skill.summary()
        return ImportResponse(
            success=True,
            name=skill.name,
            version=summary["version"],
            category=summary["category"],
            description=summary["description"],
            root_dir=str(skill.root_dir),
        )
    except Exception as e:
        logger.error("Import skill from zip failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/registry/available", response_model=RegistryListResponse)
async def list_registry_skills(
    registry_url: Optional[str] = Query(None, description="自定义 Registry URL"),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """从远程 Registry 拉取可用 Skill 列表"""
    manager = get_default_manager()
    items = await manager.fetch_registry(registry_url=registry_url)
    source = registry_url or os.environ.get("SKILL_REGISTRY_URL", "default")
    skills = [
        RegistrySkillItem(
            name=i.get("name", ""),
            version=i.get("version", ""),
            description=i.get("description", ""),
            category=i.get("category", "general"),
            source=i.get("source", ""),
            author=i.get("author", ""),
            tags=i.get("tags", []),
        )
        for i in items
    ]
    return RegistryListResponse(source=source, skills=skills)


@router.post("/registry/install", response_model=ImportResponse)
async def install_from_registry(
    req: ImportFromRegistryRequest,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """从远程 Registry 安装指定 Skill"""
    if not req.name:
        raise HTTPException(status_code=400, detail="name is required for registry install")

    manager = get_default_manager()
    items = await manager.fetch_registry(registry_url=req.registry_url)

    target = None
    for i in items:
        if i.get("name") == req.name:
            target = i
            break

    if not target:
        raise HTTPException(status_code=404, detail=f"Skill '{req.name}' not found in registry")

    source = target.get("source", "")
    if not source:
        raise HTTPException(status_code=400, detail=f"Registry item '{req.name}' has no source URL")

    try:
        if source.startswith("git:") or source.endswith(".git") or "/" in source:
            skill = manager.import_from_git(git_url=source, name=req.name)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported source type: {source}")

        summary = skill.summary()
        return ImportResponse(
            success=True,
            name=skill.name,
            version=summary["version"],
            category=summary["category"],
            description=summary["description"],
            root_dir=str(skill.root_dir),
        )
    except Exception as e:
        logger.error("Install from registry failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{name}", response_model=DeleteResponse)
async def delete_skill(
    name: str,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """删除本地 Skill 包"""
    manager = get_default_manager()
    ok = manager.delete_skill(name)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Skill '{name}' not found")
    return DeleteResponse(success=True, name=name, message=f"Skill '{name}' deleted")


# ------------------------------------------------------------------
# 更新
# ------------------------------------------------------------------

class SkillUpdateCheckItem(BaseModel):
    name: str
    git_url: str
    branch: str
    local_commit: Optional[str] = None
    remote_commit: Optional[str] = None
    has_update: bool = False
    error: Optional[str] = None


class SkillUpdateCheckResponse(BaseModel):
    count: int
    updates_available: int
    items: List[SkillUpdateCheckItem]


@router.get("/updates/check", response_model=SkillUpdateCheckResponse)
async def check_skill_updates(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """检查所有 git 来源 Skill 是否有远端更新（对比 ls-remote HEAD sha）"""
    manager = get_default_manager()
    items = manager.check_updates()
    return SkillUpdateCheckResponse(
        count=len(items),
        updates_available=sum(1 for i in items if i.get("has_update")),
        items=[SkillUpdateCheckItem(**i) for i in items],
    )


@router.post("/{name}/update", response_model=ImportResponse)
async def update_skill(
    name: str,
    git_url: Optional[str] = None,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """更新指定 Skill。优先使用侧车里的 git 元数据（一键更新），git_url 仅在无侧车时兜底"""
    manager = get_default_manager()
    try:
        skill = manager.update_skill(name, git_url=git_url)
        summary = skill.summary()
        return ImportResponse(
            success=True,
            name=skill.name,
            version=summary["version"],
            category=summary["category"],
            description=summary["description"],
            root_dir=str(skill.root_dir),
        )
    except Exception as e:
        logger.error("Update skill failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))
