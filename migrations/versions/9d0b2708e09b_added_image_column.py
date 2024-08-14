"""added image column

Revision ID: 9d0b2708e09b
Revises: f5c3f0a6a755
Create Date: 2024-08-12 21:56:11.549969

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9d0b2708e09b'
down_revision = 'f5c3f0a6a755'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('complaints', schema=None) as batch_op:
        batch_op.add_column(sa.Column('image_path', sa.String(length=200), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('complaints', schema=None) as batch_op:
        batch_op.drop_column('image_path')

    # ### end Alembic commands ###
