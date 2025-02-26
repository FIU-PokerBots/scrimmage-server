"""Add more values to enum

Revision ID: 4b3121fe5023
Revises: 44ee25bd682b
Create Date: 2019-01-21 19:42:37.230599

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '4b3121fe5023'
down_revision = '44ee25bd682b'
branch_labels = None
depends_on = None


def upgrade():
    if op.get_bind().engine.name == 'postgresql':
        op.execute('ALTER TYPE tournamentstatus RENAME TO tournamentstatus_old;')
        tournamentstatus = postgresql.ENUM('created', 'spawned', 'spawning', 'done', name='tournamentstatus')
        tournamentstatus.create(op.get_bind())
        op.alter_column('tournaments', column_name='status', 
                        type_=sa.Enum('created', 'spawned', 'spawning', 'done', name='tournamentstatus'),
                        postgresql_using='status::text::tournamentstatus')
        op.execute('DROP TYPE tournamentstatus_old;')


def downgrade():
    pass
