"""sdffggf

Revision ID: 653e11cd2983
Revises: 
Create Date: 2021-10-23 16:05:39.537238

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '653e11cd2983'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('Admin',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('username', sa.String(length=250), nullable=True),
    sa.Column('password', sa.String(length=2500), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_Admin_id'), 'Admin', ['id'], unique=False)
    op.create_index(op.f('ix_Admin_password'), 'Admin', ['password'], unique=False)
    op.create_index(op.f('ix_Admin_username'), 'Admin', ['username'], unique=False)
    op.create_table('Books',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('book_name', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_Books_book_name'), 'Books', ['book_name'], unique=False)
    op.create_index(op.f('ix_Books_id'), 'Books', ['id'], unique=False)
    op.create_table('Otp',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('email', sa.String(length=259), nullable=True),
    sa.Column('otp', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=259), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_Otp_email'), 'Otp', ['email'], unique=False)
    op.create_index(op.f('ix_Otp_id'), 'Otp', ['id'], unique=False)
    op.create_index(op.f('ix_Otp_otp'), 'Otp', ['otp'], unique=False)
    op.create_index(op.f('ix_Otp_status'), 'Otp', ['status'], unique=False)
    op.create_table('User',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=True),
    sa.Column('name', sa.String(length=200), nullable=True),
    sa.Column('number', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=250), nullable=False),
    sa.Column('address', sa.String(length=250), nullable=False),
    sa.Column('password', sa.String(length=2500), nullable=True),
    sa.PrimaryKeyConstraint('email')
    )
    op.create_index(op.f('ix_User_address'), 'User', ['address'], unique=False)
    op.create_index(op.f('ix_User_email'), 'User', ['email'], unique=False)
    op.create_index(op.f('ix_User_id'), 'User', ['id'], unique=False)
    op.create_index(op.f('ix_User_name'), 'User', ['name'], unique=False)
    op.create_index(op.f('ix_User_number'), 'User', ['number'], unique=False)
    op.create_index(op.f('ix_User_password'), 'User', ['password'], unique=False)
    op.create_table('BookwithUser',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_email', sa.String(length=250), nullable=True),
    sa.Column('book_name', sa.String(length=250), nullable=True),
    sa.Column('owner_email', sa.String(length=250), nullable=True),
    sa.ForeignKeyConstraint(['owner_email'], ['User.email'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_BookwithUser_book_name'), 'BookwithUser', ['book_name'], unique=False)
    op.create_index(op.f('ix_BookwithUser_id'), 'BookwithUser', ['id'], unique=False)
    op.create_index(op.f('ix_BookwithUser_user_email'), 'BookwithUser', ['user_email'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_BookwithUser_user_email'), table_name='BookwithUser')
    op.drop_index(op.f('ix_BookwithUser_id'), table_name='BookwithUser')
    op.drop_index(op.f('ix_BookwithUser_book_name'), table_name='BookwithUser')
    op.drop_table('BookwithUser')
    op.drop_index(op.f('ix_User_password'), table_name='User')
    op.drop_index(op.f('ix_User_number'), table_name='User')
    op.drop_index(op.f('ix_User_name'), table_name='User')
    op.drop_index(op.f('ix_User_id'), table_name='User')
    op.drop_index(op.f('ix_User_email'), table_name='User')
    op.drop_index(op.f('ix_User_address'), table_name='User')
    op.drop_table('User')
    op.drop_index(op.f('ix_Otp_status'), table_name='Otp')
    op.drop_index(op.f('ix_Otp_otp'), table_name='Otp')
    op.drop_index(op.f('ix_Otp_id'), table_name='Otp')
    op.drop_index(op.f('ix_Otp_email'), table_name='Otp')
    op.drop_table('Otp')
    op.drop_index(op.f('ix_Books_id'), table_name='Books')
    op.drop_index(op.f('ix_Books_book_name'), table_name='Books')
    op.drop_table('Books')
    op.drop_index(op.f('ix_Admin_username'), table_name='Admin')
    op.drop_index(op.f('ix_Admin_password'), table_name='Admin')
    op.drop_index(op.f('ix_Admin_id'), table_name='Admin')
    op.drop_table('Admin')
    # ### end Alembic commands ###