"""Phase 11 schema: analysis_jobs table for asynchronous worker task orchestration.

Revision ID: 0002_phase11
Revises: 0001_phase10
Create Date: 2026-09-23 15:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0002_phase11'
down_revision: Union[str, None] = '0001_phase10'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'analysis_jobs',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('repository_id', sa.String(length=36), sa.ForeignKey('repositories.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='QUEUED'),
        sa.Column('celery_task_id', sa.String(length=255), nullable=True),
        sa.Column('snapshot_id', sa.String(length=36), sa.ForeignKey('analysis_snapshots.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('progress_percent', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('progress_stage', sa.String(length=64), nullable=True),
        sa.Column('progress_message', sa.String(length=512), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('configuration', sa.JSON(), nullable=True),
    )
    op.create_index('ix_analysis_jobs_repository_id', 'analysis_jobs', ['repository_id'])
    op.create_index('ix_analysis_jobs_status', 'analysis_jobs', ['status'])
    op.create_index('ix_analysis_jobs_snapshot_id', 'analysis_jobs', ['snapshot_id'])


def downgrade() -> None:
    op.drop_index('ix_analysis_jobs_snapshot_id', table_name='analysis_jobs')
    op.drop_index('ix_analysis_jobs_status', table_name='analysis_jobs')
    op.drop_index('ix_analysis_jobs_repository_id', table_name='analysis_jobs')
    op.drop_table('analysis_jobs')
