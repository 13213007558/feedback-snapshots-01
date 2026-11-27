"""service_activity

Revision ID: 8c7df0f5b1a4
Revises: ff1860e38070
Create Date: 2026-11-27 12:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = '8c7df0f5b1a4'
down_revision = 'f460b0348206'
branch_labels = None
depends_on = None

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.create_table(
        'service_activity',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('service_id', sa.Integer(), nullable=False),
        sa.Column('activity_id', sa.Unicode(length=255), nullable=False),
        sa.Column('last_activity', sa.DateTime(), nullable=False),
        sa.Column('recorded_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'service_id', 'activity_id', name='service_activity_unique'
        ),
    )
    op.create_index(
        op.f('ix_service_activity_last_activity'),
        'service_activity',
        ['last_activity'],
        unique=False,
    )


def downgrade():
    op.drop_index(
        op.f('ix_service_activity_last_activity'), table_name='service_activity'
    )
    op.drop_table('service_activity')
