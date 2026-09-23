"""Phase 14 schema: add trend performance indexes.

Revision ID: 0005_phase14
Revises: 0004_phase13
Create Date: 2026-09-23 21:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0005_phase14"
down_revision: Union[str, None] = "0004_phase13"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_analysis_snapshots_repo_created",
        "analysis_snapshots",
        ["repository_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_analysis_snapshots_repo_branch_created",
        "analysis_snapshots",
        ["repository_id", "branch", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_finding_snapshots_snapshot_severity",
        "finding_snapshots",
        ["snapshot_id", "severity"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_finding_snapshots_snapshot_severity", table_name="finding_snapshots")
    op.drop_index("ix_analysis_snapshots_repo_branch_created", table_name="analysis_snapshots")
    op.drop_index("ix_analysis_snapshots_repo_created", table_name="analysis_snapshots")
