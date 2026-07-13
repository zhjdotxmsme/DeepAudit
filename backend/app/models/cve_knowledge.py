"""
CVE 知识库模型
存储从 NVD、OSV 等来源同步的漏洞知识
"""

import uuid
from sqlalchemy import Column, String, Text, DateTime, Float, JSON, Integer
from sqlalchemy.sql import func
from app.db.base import Base


class CVEKnowledge(Base):
    """CVE 知识库表"""
    __tablename__ = "cve_knowledge"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # CVE 标识符
    cve_id = Column(String(50), nullable=False, index=True, unique=True)

    # 漏洞标题
    title = Column(Text, nullable=True)

    # 漏洞描述
    description = Column(Text, nullable=True)

    # CVSS v3 评分
    cvss_score = Column(Float, nullable=True)

    # CVSS v3 严重程度
    severity = Column(String(20), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW

    # 影响的包信息
    # [{"ecosystem": "Maven", "name": "spring-core", "versions": "<5.3.18", "fixed": "5.3.18"}]
    affected_packages = Column(JSON, default=list)

    # CWE 分类
    cwe_ids = Column(JSON, default=list)

    # 参考链接
    references = Column(JSON, default=list)

    # 数据来源: nvd, osv, github_advisory, cnvd
    source = Column(String(50), default="nvd")

    # 原始数据（完整 JSON）
    raw_data = Column(JSON, default=dict)

    # 发布日期
    published_at = Column(DateTime(timezone=True), nullable=True)

    # 最后修改日期
    modified_at = Column(DateTime(timezone=True), nullable=True)

    # 同步状态
    sync_status = Column(String(20), default="active")  # active, deprecated, duplicate

    # 嵌入向量是否已生成
    embedding_synced = Column(Integer, default=0)  # 0=未同步, 1=已同步

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class CVESyncLog(Base):
    """CVE 同步日志表"""
    __tablename__ = "cve_sync_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # 同步来源
    source = Column(String(50), nullable=False)

    # 同步状态: success, partial, failed
    status = Column(String(20), nullable=False)

    # 同步数量
    total_count = Column(Integer, default=0)
    new_count = Column(Integer, default=0)
    updated_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)

    # 时间范围
    start_date = Column(DateTime(timezone=True), nullable=True)
    end_date = Column(DateTime(timezone=True), nullable=True)

    # 错误信息
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
