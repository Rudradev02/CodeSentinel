"""Phase 10 initial schema: repositories, analysis snapshots, findings, health, components

Revision ID: 0001_phase10
Revises: 
Create Date: 2026-09-22 18:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0001_phase10'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Repositories catalog
    op.create_table(
        'repositories',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('path', sa.String(length=1024), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_repositories_path', 'repositories', ['path'], unique=True)

    # 2. Immutable Analysis Snapshots
    op.create_table(
        'analysis_snapshots',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('repository_id', sa.String(length=36), sa.ForeignKey('repositories.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('commit_hash', sa.String(length=64), nullable=True),
        sa.Column('branch', sa.String(length=255), nullable=True),
        sa.Column('is_dirty', sa.Boolean(), nullable=True),
        sa.Column('analyzer_version', sa.String(length=32), nullable=False, server_default='0.1.0'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='COMPLETED'),
        sa.Column('duration_seconds', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('total_files', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_loc', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('configuration', sa.JSON(), nullable=True),
        sa.Column('overall_score', sa.Float(), nullable=False, server_default='100.0'),
        sa.Column('overall_grade', sa.String(length=8), nullable=False, server_default='A'),
        sa.Column('architecture_score', sa.Float(), nullable=False, server_default='100.0'),
        sa.Column('architecture_grade', sa.String(length=8), nullable=False, server_default='A'),
        sa.Column('security_score', sa.Float(), nullable=False, server_default='100.0'),
        sa.Column('security_grade', sa.String(length=8), nullable=False, server_default='A'),
        sa.Column('total_deductions_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('health_summary', sa.Text(), nullable=True),
        sa.Column('total_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('critical_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('medium_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('low_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('info_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('circular_dependencies_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('circular_components_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('diagnostics_payload', sa.JSON(), nullable=True),
    )
    op.create_index('ix_analysis_snapshots_repository_id', 'analysis_snapshots', ['repository_id'])
    op.create_index('ix_analysis_snapshots_created_at', 'analysis_snapshots', ['created_at'])

    # 3. Finding Snapshots
    op.create_table(
        'finding_snapshots',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('snapshot_id', sa.String(length=36), sa.ForeignKey('analysis_snapshots.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_uuid', sa.String(length=36), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('rule_name', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('confidence', sa.String(length=16), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('remediation', sa.Text(), nullable=False),
        sa.Column('file_path', sa.String(length=1024), nullable=False),
        sa.Column('line_start', sa.Integer(), nullable=False),
        sa.Column('line_end', sa.Integer(), nullable=True),
        sa.Column('column_start', sa.Integer(), nullable=True),
        sa.Column('column_end', sa.Integer(), nullable=True),
        sa.Column('snippet', sa.Text(), nullable=False),
        sa.Column('language', sa.String(length=32), nullable=False, server_default='plaintext'),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('cwe_id', sa.String(length=32), nullable=True),
        sa.Column('owasp_category', sa.String(length=64), nullable=True),
        sa.Column('ai_validation_status', sa.String(length=32), nullable=True),
    )
    op.create_index('ix_finding_snapshots_snapshot_id', 'finding_snapshots', ['snapshot_id'])
    op.create_index('ix_finding_snapshots_finding_uuid', 'finding_snapshots', ['finding_uuid'])
    op.create_index('ix_finding_snapshots_rule_id', 'finding_snapshots', ['rule_id'])

    # 4. Health Deduction Snapshots
    op.create_table(
        'health_deduction_snapshots',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('snapshot_id', sa.String(length=36), sa.ForeignKey('analysis_snapshots.id', ondelete='CASCADE'), nullable=False),
        sa.Column('category', sa.String(length=32), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('points_deducted', sa.Float(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=True),
        sa.Column('item_count', sa.Integer(), nullable=False, server_default='1'),
    )
    op.create_index('ix_health_deduction_snapshots_snapshot_id', 'health_deduction_snapshots', ['snapshot_id'])

    # 5. Component Snapshots
    op.create_table(
        'component_snapshots',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('snapshot_id', sa.String(length=36), sa.ForeignKey('analysis_snapshots.id', ondelete='CASCADE'), nullable=False),
        sa.Column('component_id', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('path', sa.String(length=1024), nullable=False),
        sa.Column('layer', sa.String(length=64), nullable=True),
        sa.Column('afferent_coupling', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('efferent_coupling', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('instability', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('total_loc', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('file_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('files', sa.JSON(), nullable=True),
    )
    op.create_index('ix_component_snapshots_snapshot_id', 'component_snapshots', ['snapshot_id'])

    # 6. Component Edge Snapshots
    op.create_table(
        'component_edge_snapshots',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('snapshot_id', sa.String(length=36), sa.ForeignKey('analysis_snapshots.id', ondelete='CASCADE'), nullable=False),
        sa.Column('edge_id', sa.String(length=128), nullable=False),
        sa.Column('source_component_id', sa.String(length=255), nullable=False),
        sa.Column('target_component_id', sa.String(length=255), nullable=False),
        sa.Column('weight', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('is_circular', sa.Boolean(), nullable=False, server_default='false'),
    )
    op.create_index('ix_component_edge_snapshots_snapshot_id', 'component_edge_snapshots', ['snapshot_id'])


def downgrade() -> None:
    op.drop_table('component_edge_snapshots')
    op.drop_table('component_snapshots')
    op.drop_table('health_deduction_snapshots')
    op.drop_table('finding_snapshots')
    op.drop_table('analysis_snapshots')
    op.drop_table('repositories')
