"""Phase 15 schema: add call_graph_summary column to analysis_snapshots.

Revision ID: 0006_phase15
Revises: 0005_phase14
Create Date: 2026-09-24 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0006_phase15"
down_revision: Union[str, None] = "0005_phase14"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "analysis_snapshots",
        sa.Column("call_graph_summary", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analysis_snapshots", "call_graph_summary")
