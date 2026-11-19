"""v0.4: successor_of columns, unified scope semantics (null = unrestricted, [] = nobody)

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-14 00:00:00

Data migration: before v0.4 an empty stored scope list meant "unrestricted". From v0.4 an empty list
means "nobody" and unrestricted is JSON ``null``. Every pre-existing ``[]`` is therefore rewritten to
JSON ``null`` so that already-registered objects keep their old (unrestricted) meaning.
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("context_objects") as batch:
        batch.add_column(sa.Column("successor_context_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("successor_version", sa.String(length=255), nullable=True))
        batch.create_index(
            "ix_context_objects_successor",
            ["tenant_id", "successor_context_id", "successor_version"],
            unique=False,
        )
        batch.create_index("ix_context_objects_issuer_key", ["tenant_id", "issuer_key_id"], unique=False)

    bind = op.get_bind()
    t = sa.table(
        "context_objects",
        sa.column("context_id", sa.String),
        sa.column("object_version", sa.String),
        sa.column("principal_scope", sa.JSON(none_as_null=False)),
        sa.column("purpose_scope", sa.JSON(none_as_null=False)),
    )
    rows = bind.execute(
        sa.select(t.c.context_id, t.c.object_version, t.c.principal_scope, t.c.purpose_scope)
    ).all()
    for cid, ver, ps, pu in rows:
        values: dict[str, list | None] = {}
        if ps == []:
            values["principal_scope"] = None
        if pu == []:
            values["purpose_scope"] = None
        if values:
            bind.execute(
                sa.update(t).where(t.c.context_id == cid, t.c.object_version == ver).values(**values)
            )


def downgrade() -> None:
    # Reverse the data rewrite first (null -> []), so older code reads the same meaning.
    bind = op.get_bind()
    t = sa.table(
        "context_objects",
        sa.column("context_id", sa.String),
        sa.column("object_version", sa.String),
        sa.column("principal_scope", sa.JSON(none_as_null=False)),
        sa.column("purpose_scope", sa.JSON(none_as_null=False)),
    )
    rows = bind.execute(
        sa.select(t.c.context_id, t.c.object_version, t.c.principal_scope, t.c.purpose_scope)
    ).all()
    for cid, ver, ps, pu in rows:
        values: dict[str, list | None] = {}
        if ps is None:
            values["principal_scope"] = []
        if pu is None:
            values["purpose_scope"] = []
        if values:
            bind.execute(
                sa.update(t).where(t.c.context_id == cid, t.c.object_version == ver).values(**values)
            )
    with op.batch_alter_table("context_objects") as batch:
        batch.drop_index("ix_context_objects_issuer_key")
        batch.drop_index("ix_context_objects_successor")
        batch.drop_column("successor_version")
        batch.drop_column("successor_context_id")
