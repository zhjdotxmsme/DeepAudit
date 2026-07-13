"""Add CVE knowledge and sync log tables

Revision ID: 009_add_cve_tables
Revises: 008_add_files_with_findings
Create Date: 2025-07-13

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '009_add_cve_tables'
down_revision = '008_add_files_with_findings'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create cve_knowledge table
    op.create_table(
        'cve_knowledge',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('cve_id', sa.String(50), nullable=False),
        sa.Column('title', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=True),
        sa.Column('affected_packages', sa.JSON(), nullable=True),
        sa.Column('cwe_ids', sa.JSON(), nullable=True),
        sa.Column('references', sa.JSON(), nullable=True),
        sa.Column('source', sa.String(50), server_default='nvd', nullable=True),
        sa.Column('raw_data', sa.JSON(), nullable=True),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('modified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sync_status', sa.String(20), server_default='active', nullable=True),
        sa.Column('embedding_synced', sa.Integer(), server_default='0', nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cve_id')
    )
    op.create_index(op.f('ix_cve_knowledge_cve_id'), 'cve_knowledge', ['cve_id'], unique=False)

    # Create cve_sync_logs table
    op.create_table(
        'cve_sync_logs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('source', sa.String(50), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('total_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('new_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('updated_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('failed_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('start_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('end_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('cve_sync_logs')
    op.drop_index(op.f('ix_cve_knowledge_cve_id'), table_name='cve_knowledge')
    op.drop_table('cve_knowledge')
