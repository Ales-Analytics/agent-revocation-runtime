"""approvals: record who requested (separation of duties)

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-13 00:00:01
"""
import sqlalchemy as sa
from alembic import op

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('approvals') as batch:
        batch.add_column(sa.Column('requested_by_principal', sa.String(length=255), nullable=True))
        batch.add_column(sa.Column('requested_actor', sa.String(length=255), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('approvals') as batch:
        batch.drop_column('requested_actor')
        batch.drop_column('requested_by_principal')
