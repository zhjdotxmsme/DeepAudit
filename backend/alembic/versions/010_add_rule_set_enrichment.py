"""Add skill and CVE enrichment columns to audit_rule_sets

Revision ID: 010_add_rule_set_enrichment
Revises: 009_add_cve_tables
Create Date: 2025-07-13

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '010_add_rule_set_enrichment'
down_revision = '009_add_cve_tables'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('audit_rule_sets', sa.Column('skill_names', sa.Text(), nullable=True))
    op.add_column('audit_rule_sets', sa.Column('enable_skill_enrichment', sa.Boolean(), server_default='false', nullable=True))
    op.add_column('audit_rule_sets', sa.Column('cve_min_severity', sa.String(20), server_default='HIGH', nullable=True))
    op.add_column('audit_rule_sets', sa.Column('cve_sources', sa.Text(), nullable=True))
    op.add_column('audit_rule_sets', sa.Column('enable_cve_enrichment', sa.Boolean(), server_default='false', nullable=True))


def downgrade() -> None:
    op.drop_column('audit_rule_sets', 'enable_cve_enrichment')
    op.drop_column('audit_rule_sets', 'cve_sources')
    op.drop_column('audit_rule_sets', 'cve_min_severity')
    op.drop_column('audit_rule_sets', 'enable_skill_enrichment')
    op.drop_column('audit_rule_sets', 'skill_names')
