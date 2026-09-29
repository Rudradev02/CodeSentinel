"""Phase 28 schema: Multi-repository workspaces, organizations, centralized governance, and workspace snapshots.

Revision ID: 0007_phase28
Revises: 0006_phase15
Create Date: 2026-09-29 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0007_phase28"
down_revision: Union[str, None] = "0006_phase15"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create organizations table
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"])

    # 2. Create workspaces table
    op.create_table(
        "workspaces",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("manifest_path", sa.String(1024), nullable=False),
        sa.Column("config_payload", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "slug", name="uq_workspaces_org_slug"),
    )
    op.create_index("ix_workspaces_org_id", "workspaces", ["organization_id"])

    # 3. Create workspace_repositories association table
    op.create_table(
        "workspace_repositories",
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("repository_id", sa.String(36), sa.ForeignKey("repositories.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role", sa.String(32), server_default="INTERNAL_SERVICE", nullable=False),
        sa.Column("criticality", sa.String(16), server_default="MEDIUM", nullable=False),
        sa.Column("depends_on", sa.JSON(), nullable=True),
    )

    # 4. Create workspace_snapshots table
    op.create_table(
        "workspace_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("composite_health_score", sa.Float(), nullable=False),
        sa.Column("composite_grade", sa.String(8), nullable=False),
        sa.Column("total_findings", sa.Integer(), server_default="0", nullable=False),
        sa.Column("critical_findings", sa.Integer(), server_default="0", nullable=False),
        sa.Column("high_findings", sa.Integer(), server_default="0", nullable=False),
        sa.Column("merkle_workspace_root", sa.String(64), nullable=False),
        sa.Column("attestation_envelope", sa.JSON(), nullable=True),
        sa.Column("compliance_suite", sa.JSON(), nullable=True),
        sa.Column("repository_snapshot_ids", sa.JSON(), nullable=False),
    )
    op.create_index("ix_workspace_snapshots_workspace_id", "workspace_snapshots", ["workspace_id"])
    op.create_index("ix_workspace_snapshots_created_at", "workspace_snapshots", ["created_at"])

    # 5. Add workspace and compliance columns to analysis_snapshots
    op.add_column(
        "analysis_snapshots",
        sa.Column("workspace_snapshot_id", sa.String(36), sa.ForeignKey("workspace_snapshots.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_analysis_snapshots_workspace_snapshot_id", "analysis_snapshots", ["workspace_snapshot_id"])
    op.add_column(
        "analysis_snapshots",
        sa.Column("compliance_suite", sa.JSON(), nullable=True),
    )
    op.add_column(
        "analysis_snapshots",
        sa.Column("attestation_envelope", sa.JSON(), nullable=True),
    )

    # 6. Create centralized_rule_packs table
    op.create_table(
        "centralized_rule_packs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pack_id", sa.String(100), nullable=False),
        sa.Column("version", sa.String(32), server_default="1.0.0", nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("pack_yaml", sa.Text(), nullable=False),
        sa.Column("pack_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "pack_id", "version", name="uq_central_rule_packs"),
    )
    op.create_index("ix_central_rule_packs_org_id", "centralized_rule_packs", ["organization_id"])

    # 7. Create centralized_suppressions table
    op.create_table(
        "centralized_suppressions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.String(32), nullable=False),
        sa.Column("target_repo_id", sa.String(36), server_default="*", nullable=False),
        sa.Column("target_file_pattern", sa.String(255), server_default="*", nullable=False),
        sa.Column("fingerprint_hash", sa.String(64), nullable=True),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("compensating_control", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=False),
        sa.Column("ticket_reference", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_central_suppressions_org_id", "centralized_suppressions", ["organization_id"])
    op.create_index("ix_central_suppressions_rule_id", "centralized_suppressions", ["rule_id"])


def downgrade() -> None:
    op.drop_table("centralized_suppressions")
    op.drop_table("centralized_rule_packs")
    op.drop_index("ix_analysis_snapshots_workspace_snapshot_id", table_name="analysis_snapshots")
    op.drop_column("analysis_snapshots", "attestation_envelope")
    op.drop_column("analysis_snapshots", "compliance_suite")
    op.drop_column("analysis_snapshots", "workspace_snapshot_id")
    op.drop_table("workspace_snapshots")
    op.drop_table("workspace_repositories")
    op.drop_table("workspaces")
    op.drop_table("organizations")
