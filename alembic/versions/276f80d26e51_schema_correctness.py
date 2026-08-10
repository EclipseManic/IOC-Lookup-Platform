"""schema_correctness

Revision ID: 276f80d26e51
Revises: 4fc26d31c6d5
Create Date: 2026-07-30 19:53:53.390472

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '276f80d26e51'
down_revision: Union[str, Sequence[str], None] = '4fc26d31c6d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(op.f("ix_investigation_iocs_investigation_id"), "investigation_iocs", ["investigation_id"], unique=False)
    op.create_index(op.f("ix_investigation_iocs_ioc_id"), "investigation_iocs", ["ioc_id"], unique=False)
    op.create_index(op.f("ix_lookup_results_ioc_id"), "lookup_results", ["ioc_id"], unique=False)
    op.create_index("ix_lookup_results_ioc_task", "lookup_results", ["ioc_id", "task_id"], unique=False)

    with op.batch_alter_table("investigation_iocs") as batch_op:
        batch_op.create_unique_constraint("uq_investigation_ioc", ["investigation_id", "ioc_id"])

    with op.batch_alter_table("iocs") as batch_op:
        batch_op.create_unique_constraint("uq_ioc_value", ["value"])


def downgrade() -> None:
    op.drop_index("ix_lookup_results_ioc_task", table_name="lookup_results")
    op.drop_index(op.f("ix_lookup_results_ioc_id"), table_name="lookup_results")
    op.drop_index(op.f("ix_investigation_iocs_ioc_id"), table_name="investigation_iocs")
    op.drop_index(op.f("ix_investigation_iocs_investigation_id"), table_name="investigation_iocs")

    with op.batch_alter_table("iocs") as batch_op:
        batch_op.drop_constraint("uq_ioc_value", type_="unique")

    with op.batch_alter_table("investigation_iocs") as batch_op:
        batch_op.drop_constraint("uq_investigation_ioc", type_="unique")
