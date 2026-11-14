"""lifecycle value layer: transformations, rebuild_jobs, session_exposures, session_states, derivative tag

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-14 02:00:00
"""
import sqlalchemy as sa
from alembic import op

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('context_objects') as batch:
        batch.add_column(sa.Column('transformation_id', sa.String(length=255), nullable=True))
        batch.add_column(sa.Column('transformation_version', sa.String(length=64), nullable=True))

    op.create_table(
        'transformations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('transformation_id', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=64), nullable=False),
        sa.Column('input_kinds', sa.JSON(), nullable=False),
        sa.Column('output_kind', sa.String(length=32), nullable=False),
        sa.Column('implementation_ref', sa.String(length=512), nullable=False),
        sa.Column('idempotent', sa.Boolean(), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'transformation_id', 'version', name='uq_transformation'),
    )

    op.create_table(
        'rebuild_jobs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('superseded_context_id', sa.String(length=64), nullable=False),
        sa.Column('superseded_version', sa.String(length=255), nullable=False),
        sa.Column('derivative_context_id', sa.String(length=64), nullable=False),
        sa.Column('derivative_version', sa.String(length=255), nullable=False),
        sa.Column('transformation_id', sa.String(length=255), nullable=False),
        sa.Column('transformation_version', sa.String(length=64), nullable=False),
        sa.Column('inputs', sa.JSON(), nullable=False),
        sa.Column('inputs_key', sa.String(length=64), nullable=False),
        sa.Column('state', sa.String(length=16), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('lease_token', sa.String(length=64), nullable=True),
        sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('available_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('result_context_id', sa.String(length=64), nullable=True),
        sa.Column('result_version', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'inputs_key', name='uq_rebuild_inputs'),
    )
    op.create_index('ix_rebuild_due', 'rebuild_jobs', ['state', 'available_at'], unique=False)
    op.create_index('ix_rebuild_tenant', 'rebuild_jobs', ['tenant_id', 'id'], unique=False)

    op.create_table(
        'session_exposures',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('session_id', sa.String(length=255), nullable=False),
        sa.Column('context_id', sa.String(length=255), nullable=False),
        sa.Column('object_version', sa.String(length=255), nullable=False),
        sa.Column('generation', sa.Integer(), nullable=False),
        sa.Column('principal_type', sa.String(length=16), nullable=False),
        sa.Column('principal_id', sa.String(length=255), nullable=False),
        sa.Column('workload', sa.String(length=255), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'tenant_id', 'session_id', 'context_id', 'object_version', 'generation', 'principal_id',
            name='uq_session_exposure',
        ),
    )
    op.create_index('ix_session_exposures_ctx', 'session_exposures', ['tenant_id', 'context_id'], unique=False)
    op.create_index('ix_session_exposures_expiry', 'session_exposures', ['expires_at'], unique=False)

    op.create_table(
        'session_states',
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('session_id', sa.String(length=255), nullable=False),
        sa.Column('generation', sa.Integer(), nullable=False),
        sa.Column('needs_reset', sa.Boolean(), nullable=False),
        sa.Column('flagged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('flag_reason', sa.String(length=255), nullable=True),
        sa.Column('last_reset_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('tenant_id', 'session_id'),
    )
    op.create_index('ix_session_states_expiry', 'session_states', ['expires_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_session_states_expiry', table_name='session_states')
    op.drop_table('session_states')
    op.drop_index('ix_session_exposures_expiry', table_name='session_exposures')
    op.drop_index('ix_session_exposures_ctx', table_name='session_exposures')
    op.drop_table('session_exposures')
    op.drop_index('ix_rebuild_tenant', table_name='rebuild_jobs')
    op.drop_index('ix_rebuild_due', table_name='rebuild_jobs')
    op.drop_table('rebuild_jobs')
    op.drop_table('transformations')
    with op.batch_alter_table('context_objects') as batch:
        batch.drop_column('transformation_version')
        batch.drop_column('transformation_id')
