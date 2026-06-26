"""create_initial_tables

Revision ID: 2fc3b08883ec
Revises: 
Create Date: 2026-06-14 09:50:51.286109

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '2fc3b08883ec'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Determine the dialect of the current connection
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    # Define dynamic JSON and ARRAY types to support SQLite
    json_type = sa.JSON if is_sqlite else postgresql.JSONB
    array_type = sa.JSON if is_sqlite else sa.ARRAY(sa.Text())

    op.create_table('users',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('hashed_password', sa.String(length=255), nullable=False),
    sa.Column('full_name', sa.String(length=100), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('scans_today', sa.Integer(), nullable=True),
    sa.Column('scans_reset_at', sa.TIMESTAMP(), nullable=True),
    sa.Column('created_at', sa.TIMESTAMP(), nullable=True),
    sa.Column('updated_at', sa.TIMESTAMP(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    
    op.create_table('refresh_tokens',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('token_hash', sa.String(length=255), nullable=False),
    sa.Column('expires_at', sa.TIMESTAMP(), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.TIMESTAMP(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    
    op.create_table('scans',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('server_name', sa.String(length=200), nullable=True),
    sa.Column('target_url', sa.Text(), nullable=False),
    sa.Column('scan_type', sa.String(length=20), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('progress', sa.Integer(), nullable=True),
    sa.Column('current_attack', sa.String(length=100), nullable=True),
    sa.Column('attacks_total', sa.Integer(), nullable=True),
    sa.Column('attacks_done', sa.Integer(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('celery_task_id', sa.String(length=255), nullable=True),
    sa.Column('started_at', sa.TIMESTAMP(), nullable=True),
    sa.Column('completed_at', sa.TIMESTAMP(), nullable=True),
    sa.Column('duration_seconds', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.TIMESTAMP(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    
    op.create_table('reports',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('scan_id', sa.UUID(), nullable=True),
    sa.Column('risk_score', sa.Integer(), nullable=False),
    sa.Column('risk_level', sa.String(length=20), nullable=False),
    sa.Column('total_critical', sa.Integer(), nullable=True),
    sa.Column('total_high', sa.Integer(), nullable=True),
    sa.Column('total_medium', sa.Integer(), nullable=True),
    sa.Column('total_low', sa.Integer(), nullable=True),
    sa.Column('total_passed', sa.Integer(), nullable=True),
    sa.Column('raw_data', json_type, nullable=False),
    sa.Column('pdf_s3_key', sa.String(length=500), nullable=True),
    sa.Column('pdf_url', sa.Text(), nullable=True),
    sa.Column('share_token', sa.String(length=100), nullable=True),
    sa.Column('share_enabled', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.TIMESTAMP(), nullable=True),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id'),
    sa.UniqueConstraint('share_token')
    )
    
    op.create_table('vulnerabilities',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('report_id', sa.UUID(), nullable=True),
    sa.Column('attack_id', sa.String(length=10), nullable=False),
    sa.Column('attack_name', sa.String(length=100), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=True),
    sa.Column('cvss_score', sa.DECIMAL(precision=3, scale=1), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('evidence', sa.Text(), nullable=True),
    sa.Column('fix_suggestion', sa.Text(), nullable=True),
    sa.Column('references', array_type, nullable=True),
    sa.Column('execution_time', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.TIMESTAMP(), nullable=True),
    sa.ForeignKeyConstraint(['report_id'], ['reports.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('vulnerabilities')
    op.drop_table('reports')
    op.drop_table('scans')
    op.drop_table('refresh_tokens')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
