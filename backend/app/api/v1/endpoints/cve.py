"""
CVE 知识库 API - 只读列表/详情 + 触发 NVD/OSV 同步 + 同步日志

后端职责:
- GET  /cve           列出 CVE（分页 + severity/keyword 过滤）
- GET  /cve/stats     知识库统计
- GET  /cve/{cve_id}  单条详情
- GET  /cve/sync/logs 同步日志（最近 N 条）
- POST /cve/sync/nvd  触发 NVD 同步（后台任务）
- POST /cve/sync/osv  触发 OSV 同步（后台任务，按包）
"""

from typing import Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func as sql_func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.api import deps
from app.db.session import get_db, AsyncSessionLocal
from app.models.cve_knowledge import CVEKnowledge, CVESyncLog
from app.models.user import User
from app.services.cve_sync_service import CVESyncService
from app.services import tech_stack_presets

router = APIRouter()


# ==================== Schemas ====================

class CVEItem(BaseModel):
    id: str
    cve_id: str
    title: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    cwe_ids: List[str] = []
    source: str = "nvd"
    sync_status: str = "active"
    embedding_synced: int = 0
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CVEDetail(CVEItem):
    affected_packages: List[dict] = []
    references: List[dict] = []
    raw_data: dict = {}


class CVEListResponse(BaseModel):
    total: int
    items: List[CVEItem]
    skip: int
    limit: int


class CVEStats(BaseModel):
    total: int
    by_severity: dict
    by_source: dict
    embedding_synced: int
    embedding_pending: int
    latest_published: Optional[datetime] = None


class SyncLogItem(BaseModel):
    id: str
    source: str
    status: str
    total_count: int = 0
    new_count: int = 0
    updated_count: int = 0
    failed_count: int = 0
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class NVDSyncRequest(BaseModel):
    days_back: int = Field(30, ge=1, le=365, description="回溯天数")
    max_results: int = Field(500, ge=1, le=5000, description="最大同步条数")
    severity_filter: Optional[str] = Field(
        None, description="CRITICAL/HIGH/MEDIUM/LOW，可选"
    )


class NVDIncrementalSyncRequest(BaseModel):
    max_results: int = Field(5000, ge=1, le=50000, description="最大同步条数")
    severity_filter: Optional[str] = Field(
        None, description="CRITICAL/HIGH/MEDIUM/LOW，可选"
    )
    fallback_days: int = Field(
        1825, ge=1, le=3650, description="无历史成功记录时回退的天数（默认 5 年）"
    )


class TechStackSyncRequest(BaseModel):
    keywords: Optional[List[str]] = Field(
        None,
        description="关键词列表，为空时使用默认技术栈（Java/Vue/MySQL/Redis/Nacos/XXL-Job 等）",
    )
    years: int = Field(5, ge=1, le=10, description="回溯年数（默认 5）")
    severity_filter: Optional[str] = Field(
        None, description="CRITICAL/HIGH/MEDIUM/LOW，可选"
    )
    max_per_keyword: int = Field(
        1000, ge=10, le=10000, description="每个关键词最大结果数"
    )


class OSVPackage(BaseModel):
    ecosystem: str = Field(..., description="Maven/npm/PyPI/Go/...")
    name: str
    version: Optional[str] = None


class OSVSyncRequest(BaseModel):
    packages: List[OSVPackage]


class PresetSelection(BaseModel):
    """单个预设选择(生态 + 框架)"""
    ecosystem: str = Field(..., description="Maven/npm/PyPI/Go/NuGet/RubyGems/crates.io/Packagist")
    framework: str = Field(..., description="框架 ID,如 spring-core / django / express")


class PresetSyncRequest(BaseModel):
    """预设同步请求: 多选生态+框架,后端展开为 OSV 包列表"""
    selections: List[PresetSelection] = Field(
        default_factory=list,
        description="选择的预设项列表"
    )
    sync_all: bool = Field(
        default=False,
        description="True = 同步所有预设(忽略 selections)"
    )
    ecosystem: Optional[str] = Field(
        default=None,
        description="sync_all=True 时限定单一生态,如 'Maven'"
    )


class SyncTriggerResponse(BaseModel):
    accepted: bool = True
    message: str


# ==================== List / Detail ====================

@router.get("", response_model=CVEListResponse)
async def list_cves(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
    severity: Optional[str] = Query(None, description="按严重程度过滤"),
    source: Optional[str] = Query(None, description="按来源过滤 nvd/osv/..."),
    keyword: Optional[str] = Query(None, description="cve_id / title / description 关键词"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """列出 CVE 记录"""
    query = select(CVEKnowledge)
    count_query = select(sql_func.count(CVEKnowledge.id))

    conds = []
    if severity:
        conds.append(CVEKnowledge.severity == severity.upper())
    if source:
        conds.append(CVEKnowledge.source == source.lower())
    if keyword:
        like = f"%{keyword}%"
        conds.append(
            or_(
                CVEKnowledge.cve_id.ilike(like),
                CVEKnowledge.title.ilike(like),
                CVEKnowledge.description.ilike(like),
            )
        )
    for c in conds:
        query = query.where(c)
        count_query = count_query.where(c)

    total = (await db.execute(count_query)).scalar_one()

    query = query.order_by(CVEKnowledge.published_at.desc().nullslast()).offset(skip).limit(limit)
    rows = (await db.execute(query)).scalars().all()

    return CVEListResponse(
        total=int(total or 0),
        items=[CVEItem.model_validate(r) for r in rows],
        skip=skip,
        limit=limit,
    )


@router.get("/stats", response_model=CVEStats)
async def cve_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """CVE 知识库统计信息"""
    total = (await db.execute(select(sql_func.count(CVEKnowledge.id)))).scalar_one() or 0

    sev_rows = (
        await db.execute(
            select(CVEKnowledge.severity, sql_func.count(CVEKnowledge.id)).group_by(
                CVEKnowledge.severity
            )
        )
    ).all()
    by_severity = {(k or "UNKNOWN"): int(v) for k, v in sev_rows}

    src_rows = (
        await db.execute(
            select(CVEKnowledge.source, sql_func.count(CVEKnowledge.id)).group_by(
                CVEKnowledge.source
            )
        )
    ).all()
    by_source = {(k or "unknown"): int(v) for k, v in src_rows}

    synced = (
        await db.execute(
            select(sql_func.count(CVEKnowledge.id)).where(CVEKnowledge.embedding_synced == 1)
        )
    ).scalar_one() or 0

    pending = int(total) - int(synced)

    latest = (
        await db.execute(select(sql_func.max(CVEKnowledge.published_at)))
    ).scalar_one()

    return CVEStats(
        total=int(total),
        by_severity=by_severity,
        by_source=by_source,
        embedding_synced=int(synced),
        embedding_pending=max(0, pending),
        latest_published=latest,
    )


@router.get("/sync/logs", response_model=List[SyncLogItem])
async def list_sync_logs(
    limit: int = Query(20, ge=1, le=100),
    source: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """最近的同步日志"""
    query = select(CVESyncLog).order_by(CVESyncLog.created_at.desc()).limit(limit)
    if source:
        query = query.where(CVESyncLog.source == source.lower())
    rows = (await db.execute(query)).scalars().all()
    return [SyncLogItem.model_validate(r) for r in rows]


@router.get("/{cve_id}", response_model=CVEDetail)
async def get_cve(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """获取单条 CVE 详情"""
    result = await db.execute(select(CVEKnowledge).where(CVEKnowledge.cve_id == cve_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found")
    return CVEDetail.model_validate(row)


# ==================== Sync triggers (background) ====================

async def _run_nvd_sync(
    days_back: int, max_results: int, severity_filter: Optional[str]
) -> None:
    async with AsyncSessionLocal() as session:
        svc = CVESyncService(db=session)
        try:
            await svc.sync_nvd(
                days_back=days_back,
                max_results=max_results,
                severity_filter=severity_filter,
            )
        finally:
            await svc.close()


async def _run_osv_sync(packages: List[dict]) -> None:
    async with AsyncSessionLocal() as session:
        svc = CVESyncService(db=session)
        try:
            await svc.sync_osv_for_packages(packages=packages)
        finally:
            await svc.close()


async def _run_nvd_incremental_sync(
    max_results: int, severity_filter: Optional[str], fallback_days: int
) -> None:
    async with AsyncSessionLocal() as session:
        svc = CVESyncService(db=session)
        try:
            await svc.sync_nvd_incremental(
                max_results=max_results,
                severity_filter=severity_filter,
                fallback_days=fallback_days,
            )
        finally:
            await svc.close()


async def _run_tech_stack_sync(
    keywords: Optional[List[str]],
    years: int,
    severity_filter: Optional[str],
    max_per_keyword: int,
) -> None:
    async with AsyncSessionLocal() as session:
        svc = CVESyncService(db=session)
        try:
            await svc.sync_by_tech_stack(
                keywords=keywords,
                years=years,
                severity_filter=severity_filter,
                max_per_keyword=max_per_keyword,
            )
        finally:
            await svc.close()


async def _run_osv_incremental_sync(ecosystems: Optional[List[str]]) -> None:
    async with AsyncSessionLocal() as session:
        svc = CVESyncService(db=session)
        try:
            await svc.sync_osv_incremental(ecosystems=ecosystems)
        finally:
            await svc.close()


async def _run_cvelist_v5_sync(force_full: bool) -> None:
    async with AsyncSessionLocal() as session:
        svc = CVESyncService(db=session)
        try:
            await svc.sync_cvelist_v5(force_full=force_full)
        finally:
            await svc.close()


async def _run_osv_preset_sync(
    packages: List[dict],
    source_label: str,
) -> None:
    """通用 OSV 预设同步 - 与 _run_osv_sync 共享 sync_osv_for_packages,但允许自定义 source 标签"""
    async with AsyncSessionLocal() as session:
        svc = CVESyncService(db=session)
        try:
            log = await svc.sync_osv_for_packages(packages=packages)
            if log is not None and source_label:
                log.source = source_label
                await session.commit()
        finally:
            await svc.close()


@router.post("/sync/nvd", response_model=SyncTriggerResponse)
async def trigger_nvd_sync(
    payload: NVDSyncRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """异步触发 NVD 同步（后台执行，立即返回）"""
    background_tasks.add_task(
        _run_nvd_sync,
        payload.days_back,
        payload.max_results,
        payload.severity_filter,
    )
    return SyncTriggerResponse(
        message=f"NVD sync scheduled (days_back={payload.days_back}, max_results={payload.max_results})"
    )


@router.post("/sync/osv", response_model=SyncTriggerResponse)
async def trigger_osv_sync(
    payload: OSVSyncRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """异步触发 OSV 同步（按包批量查询）"""
    if not payload.packages:
        raise HTTPException(status_code=400, detail="packages 不能为空")
    packages = [p.model_dump() for p in payload.packages]
    background_tasks.add_task(_run_osv_sync, packages)
    return SyncTriggerResponse(
        message=f"OSV sync scheduled for {len(packages)} package(s)"
    )


@router.post("/sync/osv/incremental", response_model=SyncTriggerResponse)
async def trigger_osv_incremental_sync(
    ecosystems: str = Query("", description="逗号分隔的生态系统列表，如 Maven,npm,PyPI 为空则使用全部"),
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    异步触发 OSV 增量同步（基于 modified_id.csv）

    从上一次成功同步的 end_date 开始，获取指定生态系统自该时间以来修改的所有漏洞。
    支持的生态系统：Maven, npm, PyPI, Go, NuGet, crates.io, RubyGems, Packagist
    """
    ecosystem_list: Optional[List[str]] = None
    if ecosystems.strip():
        ecosystem_list = [e.strip() for e in ecosystems.split(",") if e.strip()]

    background_tasks.add_task(_run_osv_incremental_sync, ecosystem_list)
    eco_str = ecosystems or "全部生态系统"
    return SyncTriggerResponse(
        message=f"OSV incremental sync scheduled for {eco_str}"
    )


@router.post("/sync/nvd/incremental", response_model=SyncTriggerResponse)
async def trigger_nvd_incremental_sync(
    payload: NVDIncrementalSyncRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    异步触发 NVD 增量同步

    自动从上一次成功同步的 end_date 开始拉取到当前时间；
    若无历史成功记录，则回退到 fallback_days（默认 5 年）
    """
    background_tasks.add_task(
        _run_nvd_incremental_sync,
        payload.max_results,
        payload.severity_filter,
        payload.fallback_days,
    )
    return SyncTriggerResponse(
        message=(
            f"NVD incremental sync scheduled "
            f"(max_results={payload.max_results}, fallback_days={payload.fallback_days})"
        )
    )


@router.post("/sync/tech-stack", response_model=SyncTriggerResponse)
async def trigger_tech_stack_sync(
    payload: TechStackSyncRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    异步触发技术栈历史 CVE 同步

    按关键词逐个从 NVD 拉取最近 N 年的漏洞。默认关键词覆盖 Java 生态、
    Vue2/3、MySQL、Redis、Nacos、XXL-Job 等常见技术栈。
    """
    kw_count = len(payload.keywords) if payload.keywords else "默认技术栈"
    background_tasks.add_task(
        _run_tech_stack_sync,
        payload.keywords,
        payload.years,
        payload.severity_filter,
        payload.max_per_keyword,
    )
    return SyncTriggerResponse(
        message=(
            f"Tech-stack sync scheduled "
            f"(keywords={kw_count}, years={payload.years}, "
            f"severity={payload.severity_filter or 'ALL'})"
        )
    )


@router.post("/sync/cvelist-v5", response_model=SyncTriggerResponse)
async def trigger_cvelist_v5_sync(
    force_full: bool = Query(False, description="强制全量同步，忽略增量"),
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    异步触发 CVEProject cvelistV5 Git 镜像同步

    首次全量同步，之后增量同步（只处理自上次同步以来变更的 CVE 文件）。
    """
    background_tasks.add_task(_run_cvelist_v5_sync, force_full)
    mode = "full" if force_full else "incremental"
    return SyncTriggerResponse(
        message=f"cvelistV5 {mode} sync scheduled"
    )


# ==================== 预设同步 (Tech Stack Presets) ====================
# 提供按生态/语言/框架的多选,避免手写 ecosystem:name 文本

@router.get("/sync/osv/presets")
async def get_osv_presets(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    返回 OSV 同步预设列表(按生态分组),供前端多选 UI 使用

    格式:
    [
      {
        "ecosystem": "Maven",
        "label": "Java / JVM",
        "frameworks": [
          {"id": "spring-core", "label": "Spring Framework (核心)", "count": 6},
          ...
        ]
      },
      ...
    ]

    额外字段: `stats` 包含总生态/框架/包数
    """
    return {
        "presets": tech_stack_presets.list_presets(),
        "stats": tech_stack_presets.get_stats(),
    }


@router.post("/sync/osv/presets", response_model=SyncTriggerResponse)
async def trigger_osv_preset_sync(
    payload: PresetSyncRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    异步触发 OSV 预设同步

    工作流:
    1. 前端提交 selections=[{ecosystem, framework}, ...] 或 sync_all=True
    2. 后端展开为 OSV 包列表(去重)
    3. 调用 sync_osv_for_packages 入库

    限制: 最多 500 个包,超过报错
    """
    if payload.sync_all:
        packages = tech_stack_presets.expand_all(ecosystem=payload.ecosystem)
    else:
        selections = [s.model_dump() for s in payload.selections]
        packages = tech_stack_presets.expand_selection(selections)

    if not packages:
        raise HTTPException(
            status_code=400,
            detail="选择无效:没有匹配的预设包",
        )

    # 去重
    seen = set()
    unique = []
    for p in packages:
        key = (p["ecosystem"], p["name"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
    packages = unique

    if len(packages) > 500:
        raise HTTPException(
            status_code=400,
            detail=f"包数量过多 ({len(packages)} > 500),请缩小选择范围或使用 sync_osv_incremental 全量增量",
        )

    source_label = "osv_preset"
    if payload.sync_all:
        source_label = f"osv_preset_all:{payload.ecosystem or 'all'}"

    background_tasks.add_task(_run_osv_preset_sync, packages, source_label)

    return SyncTriggerResponse(
        message=(
            f"OSV preset sync scheduled for {len(packages)} package(s) "
            f"from {len(set(p['ecosystem'] for p in packages))} ecosystem(s)"
        )
    )
