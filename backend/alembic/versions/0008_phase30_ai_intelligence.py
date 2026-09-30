"""Phase 30 schema: AI intelligence tables for triage feedback, prioritization, refactoring, and NL policy proposals.

Revision ID: 0008_phase30
Revises: 0007_phase28
Create Date: 2026-09-30 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008_phase30"
down_revision: Union[str, None] = "0007_phase28"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create finding_triage_feedbacks table
    op.create_table(
        "finding_triage_feedbacks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("finding_snapshots.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("finding_fingerprint", sa.String(64), nullable=False, index=True),
        sa.Column(
            "snapshot_id",
            sa.String(36),
            sa.ForeignKey("analysis_snapshots.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "repository_id",
            sa.String(36),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("rule_id", sa.String(64), nullable=False, index=True),
        sa.Column("label", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("reviewer_id", sa.String(255), nullable=False),
        sa.Column("feature_snapshot", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. Create ai_prioritizations table
    op.create_table(
        "ai_prioritizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("finding_snapshots.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "snapshot_id",
            sa.String(36),
            sa.ForeignKey("analysis_snapshots.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("priority_score", sa.Float(), nullable=False),
        sa.Column("priority_band", sa.String(16), nullable=False),
        sa.Column("exploitability_score", sa.Float(), nullable=False),
        sa.Column("contributing_factors", sa.JSON(), nullable=True),
        sa.Column("reasoning_summary", sa.Text(), nullable=False),
        sa.Column("context_hash", sa.String(64), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. Create ai_refactoring_proposals table
    op.create_table(
        "ai_refactoring_proposals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.String(36),
            sa.ForeignKey("analysis_snapshots.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "repository_id",
            sa.String(36),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("target_rule_id", sa.String(64), nullable=False),
        sa.Column("target_finding_ids", sa.JSON(), nullable=True),
        sa.Column("refactoring_type", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("problem_statement", sa.Text(), nullable=False),
        sa.Column("proposed_design", sa.Text(), nullable=False),
        sa.Column("affected_components", sa.JSON(), nullable=True),
        sa.Column("affected_files", sa.JSON(), nullable=True),
        sa.Column("hypothetical_edge_mutations", sa.JSON(), nullable=True),
        sa.Column("simulated_metric_deltas", sa.JSON(), nullable=True),
        sa.Column("simulation_status", sa.String(32), nullable=False, server_default="PROPOSAL_ONLY"),
        sa.Column("status", sa.String(32), nullable=False, server_default="PROPOSAL_ONLY"),
        sa.Column("context_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. Create ai_policy_proposals table
    op.create_table(
        "ai_policy_proposals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("policy_id", sa.String(100), nullable=False, unique=True),
        sa.Column("natural_language_prompt", sa.Text(), nullable=False),
        sa.Column("generated_policy_json", sa.JSON(), nullable=False),
        sa.Column("validation_status", sa.String(32), nullable=False, server_default="VALIDATED_CANDIDATE"),
        sa.Column("validation_diagnostics", sa.JSON(), nullable=True),
        sa.Column("author_id", sa.String(255), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ai_policy_proposals")
    op.drop_table("ai_refactoring_proposals")
    op.drop_table("ai_prioritizations")
    op.drop_table("finding_triage_feedbacks")
