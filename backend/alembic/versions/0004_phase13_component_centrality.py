"""Phase 13 schema: add component centrality metrics to component_snapshots.

Revision ID: 0004_phase13
Revises: 0003_phase12
Create Date: 2026-09-23 20:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0004_phase13'
down_revision: Union[str, None] = '0003_phase12'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'component_snapshots',
        sa.Column('betweenness_centrality', sa.Float(), nullable=False, server_default='0.0')
    )
    op.add_column(
        'component_snapshots',
        sa.Column('in_degree_centrality', sa.Float(), nullable=False, server_default='0.0')
    )
    op.add_column(
        'component_snapshots',
        sa.Column('out_degree_centrality', sa.Float(), nullable=False, server_default='0.0')
    )


def downgrade() -> None:
    op.drop_column('component_snapshots', 'out_degree_centrality')
    op.drop_column('component_snapshots', 'in_degree_centrality')
    op.drop_column('component_snapshots', 'betweenness_centrality')
