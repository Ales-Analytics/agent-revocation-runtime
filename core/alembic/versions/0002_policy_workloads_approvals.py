"""policy documents, workloads, grants, delegations, approvals

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-13 00:00:00
"""
import sqlalchemy as sa
from alembic import op

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('policy_documents',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('policy_id', sa.String(length=255), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('document', sa.JSON(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'policy_id', 'version', name='uq_policy_version')
    )
    op.create_index('ix_policy_tenant_active', 'policy_documents', ['tenant_id', 'active'], unique=False)
    op.create_table('workloads',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('workload_id', sa.String(length=255), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('display_name', sa.String(length=255), nullable=False),
    sa.Column('capabilities', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'workload_id', name='uq_workload')
    )
    op.create_table('workload_grants',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('principal_id', sa.String(length=255), nullable=False),
    sa.Column('workload_id', sa.String(length=255), nullable=False),
    sa.Column('granted_by', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'principal_id', 'workload_id', name='uq_workload_grant')
    )
    op.create_table('delegations',
    sa.Column('delegation_id', sa.String(length=64), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('from_workload', sa.String(length=255), nullable=False),
    sa.Column('to_workload', sa.String(length=255), nullable=False),
    sa.Column('purposes', sa.JSON(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('delegation_id')
    )
    op.create_index('ix_delegations_pair', 'delegations', ['tenant_id', 'from_workload', 'to_workload'], unique=False)
    op.create_table('approvals',
    sa.Column('seq', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('approval_id', sa.String(length=64), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('decision_context', sa.JSON(), nullable=False),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('decided_by', sa.String(length=255), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('seq'),
    sa.UniqueConstraint('approval_id')
    )
    op.create_index('ix_approvals_fp', 'approvals', ['tenant_id', 'fingerprint'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_approvals_fp', table_name='approvals')
    op.drop_table('approvals')
    op.drop_index('ix_delegations_pair', table_name='delegations')
    op.drop_table('delegations')
    op.drop_table('workload_grants')
    op.drop_table('workloads')
    op.drop_index('ix_policy_tenant_active', table_name='policy_documents')
    op.drop_table('policy_documents')
