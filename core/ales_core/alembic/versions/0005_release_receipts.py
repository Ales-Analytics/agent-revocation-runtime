"""v0.4: release_receipts (release gate receipts for audit/debug)

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-14 01:00:00
"""
import sqlalchemy as sa
from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'release_receipts',
        sa.Column('receipt_id', sa.String(length=64), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('request_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('decision', sa.String(length=16), nullable=False),
        sa.Column('detail', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('receipt_id'),
    )
    op.create_index(
        'ix_release_receipts_tenant_created', 'release_receipts', ['tenant_id', 'created_at'], unique=False
    )


def downgrade() -> None:
    op.drop_index('ix_release_receipts_tenant_created', table_name='release_receipts')
    op.drop_table('release_receipts')
