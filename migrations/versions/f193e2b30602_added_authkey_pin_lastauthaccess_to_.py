"""added authkey, pin, lastauthaccess to managedhost; removed picture from manager

Revision ID: f193e2b30602
Revises: 
Create Date: 2020-04-18 20:42:58.902869

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f193e2b30602'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('managedhost', sa.Column('authkey', sa.String(length=256), nullable=True))
    op.add_column('managedhost', sa.Column('authkey_trycount', sa.Integer(), nullable=True))
    op.add_column('managedhost', sa.Column('lastauthaccess', sa.DateTime(), nullable=True))
    op.add_column('managedhost', sa.Column('pin', sa.String(length=6), nullable=True))
    op.add_column('managedhost', sa.Column('pin_trycount', sa.Integer(), nullable=True))
    op.add_column('managedhost', sa.Column('pin_whenset', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('managedhost', 'pin_whenset')
    op.drop_column('managedhost', 'pin_trycount')
    op.drop_column('managedhost', 'pin')
    op.drop_column('managedhost', 'lastauthaccess')
    op.drop_column('managedhost', 'authkey_trycount')
    op.drop_column('managedhost', 'authkey')
    # ### end Alembic commands ###
