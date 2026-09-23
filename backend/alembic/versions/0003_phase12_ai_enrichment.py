"""Phase 12 schema: ai_enrichments table for bounded context AI triage and remediation.

Revision ID: 0003_phase12
Revises: 0002_phase11
Create Date: 2026-09-23 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0003_phase12'
down_revision: Union[str, None] = '0002_phase11'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ai_enrichments',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('finding_id', sa.String(length=36), sa.ForeignKey('finding_snapshots.id', ondelete='CASCADE'), nullable=False),
        sa.Column('snapshot_id', sa.String(length=36), sa.ForeignKey('analysis_snapshots.id', ondelete='CASCADE'), nullable=False),
        sa.Column('repository_id', sa.String(length=36), sa.ForeignKey('repositories.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='QUEUED'),
        sa.Column('provider', sa.String(length=64), nullable=False),
        sa.Column('model', sa.String(length=128), nullable=False),
        sa.Column('prompt_version', sa.String(length=16), nullable=False, server_default='v1'),
        sa.Column('is_likely_true_positive', sa.Boolean(), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('risk_summary', sa.Text(), nullable=True),
        sa.Column('technical_reasoning', sa.Text(), nullable=True),
        sa.Column('assumptions_limitations', sa.JSON(), nullable=True),
        sa.Column('prescribed_remediation', sa.Text(), nullable=True),
        sa.Column('proposed_patch', sa.JSON(), nullable=True),
        sa.Column('raw_response', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('finding_id', 'provider', 'model', 'prompt_version', name='uq_ai_enrichments_finding_model'),
    )
    op.create_index('ix_ai_enrichments_finding_id', 'ai_enrichments', ['finding_id'])
    op.create_index('ix_ai_enrichments_snapshot_id', 'ai_enrichments', ['snapshot_id'])
    op.create_index('ix_ai_enrichments_repository_id', 'ai_enrichments', ['repository_id'])
    op.create_index('ix_ai_enrichments_status', 'ai_enrichments', ['status'])


def downgrade() -> None:
    op.drop_index('ix_ai_enrichments_status', table_name='ai_enrichments')
    op.drop_index('ix_ai_enrichments_repository_id', table_name='ai_enrichments')
    op.drop_index('ix_ai_enrichments_snapshot_id', table_name='ai_enrichments')
    op.drop_index('ix_ai_enrichments_finding_id', table_name='ai_enrichments')
    op.drop_table('ai_enrichments')
