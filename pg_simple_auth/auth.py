from typing import Optional, Dict, Any
import jwt
from datetime import datetime, timedelta
import uuid
import asyncpg
from passlib.hash import argon2
import re
from dataclasses import dataclass

@dataclass
class AuthConfig:
    jwt_expiration: int = 3600  # 1 hour
    jwt_algorithm: str = 'HS256'
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True
    verification_expiration: int = 86400  # 24 hours
    reset_expiration: int = 3600  # 1 hour
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15 minutes

# Global variables
db_pool: Optional[asyncpg.Pool] = None
secret_key: str = ""
table_name: str = ""
config: AuthConfig = AuthConfig()

async def initialize(pool: asyncpg.Pool, key: str, table: str = "users", auth_config: AuthConfig = AuthConfig()):
    global db_pool, secret_key, table_name, config
    db_pool = pool
    secret_key = key
    table_name = table
    config = auth_config
    await _lazy_migration()

async def _lazy_migration():
    async with db_pool.acquire() as conn:
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id SERIAL PRIMARY KEY
            )
        """)

        columns_to_add = {
            'reset_token': 'VARCHAR(255)',
            'reset_token_expires': 'TIMESTAMP WITH TIME ZONE',
            'verification_token': 'VARCHAR(255)',
            'verification_token_expires': 'TIMESTAMP WITH TIME ZONE',
            'verified': 'BOOLEAN DEFAULT FALSE',
            'failed_login_attempts': 'INT DEFAULT 0',
            'last_failed_login': 'TIMESTAMP WITH TIME ZONE',
            'email': 'VARCHAR(255) UNIQUE NOT NULL',
            'password_hash': 'VARCHAR(255) NOT NULL',
            'created_at': 'TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP'
        }

        existing_columns = await conn.fetch(f"""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = '{table_name}'
        """)
        existing_columns = [col['column_name'] for col in existing_columns]

        for col, type in columns_to_add.items():
            if col not in existing_columns:
                await conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {col} {type}")

def check_password_strength(password: str) -> bool:
    if len(password) < config.password_min_length:
        return False
    if config.password_require_uppercase and not re.search(r"[A-Z]", password):
        return False
    if config.password_require_lowercase and not re.search(r"[a-z]", password):
        return False
    if config.password_require_digit and not re.search(r"\d", password):
        return False
    if config.password_require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

async def signup(email: str, password: str) -> Dict[str, Any]:
    if not check_password_strength(password):
        raise ValueError("Password does not meet strength requirements")
    
    hashed_password = argon2.hash(password)
    async with db_pool.acquire() as conn:
        user_id = await conn.fetchval(
            f"INSERT INTO {table_name} (email, password_hash) VALUES ($1, $2) RETURNING id",
            email, hashed_password
        )
    verification_token = await generate_verification_token(user_id)
    return {"id": user_id, "email": email, "verification_token": verification_token}

async def login(email: str, password: str) -> Optional[Dict[str, Any]]:
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow(
            f"SELECT id, email, password_hash, verified, failed_login_attempts, last_failed_login FROM {table_name} WHERE email = $1",
            email
        )
        
        if user:
            if user['failed_login_attempts'] >= config.max_login_attempts:
                if user['last_failed_login'] + timedelta(seconds=config.lockout_duration) > datetime.utcnow():
                    return {"error": "Account temporarily locked"}
            
            if argon2.verify(password, user['password_hash']):
                if not user['verified']:
                    return {"error": "Email not verified"}
                
                await conn.execute(
                    f"UPDATE {table_name} SET failed_login_attempts = 0 WHERE id = $1",
                    user['id']
                )
                
                token = _generate_jwt(user['id'], email)
                return {"user": {"id": user['id'], "email": email}, "token": token}
            else:
                await conn.execute(
                    f"UPDATE {table_name} SET failed_login_attempts = failed_login_attempts + 1, last_failed_login = $1 WHERE id = $2",
                    datetime.utcnow(), user['id']
                )
    
    return None

async def generate_verification_token(user_id: int) -> str:
    token = str(uuid.uuid4())
    expires = datetime.utcnow() + timedelta(seconds=config.verification_expiration)
    async with db_pool.acquire() as conn:
        await conn.execute(
            f"UPDATE {table_name} SET verification_token = $1, verification_token_expires = $2 WHERE id = $3",
            token, expires, user_id
        )
    return token

async def verify(token: str) -> bool:
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow(
            f"SELECT id FROM {table_name} WHERE verification_token = $1 AND verification_token_expires > $2",
            token, datetime.utcnow()
        )
        if user:
            await conn.execute(
                f"UPDATE {table_name} SET verified = TRUE, verification_token = NULL, verification_token_expires = NULL WHERE id = $1",
                user['id']
            )
            return True
    return False

async def forgot_password(email: str) -> Optional[str]:
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow(f"SELECT id FROM {table_name} WHERE email = $1", email)
        if user:
            reset_token = str(uuid.uuid4())
            expires = datetime.utcnow() + timedelta(seconds=config.reset_expiration)
            await conn.execute(
                f"UPDATE {table_name} SET reset_token = $1, reset_token_expires = $2 WHERE id = $3",
                reset_token, expires, user['id']
            )
            return reset_token
    return None

async def reset_password(token: str, new_password: str) -> bool:
    if not check_password_strength(new_password):
        raise ValueError("New password does not meet strength requirements")
    
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow(
            f"SELECT id FROM {table_name} WHERE reset_token = $1 AND reset_token_expires > $2",
            token, datetime.utcnow()
        )
        if user:
            new_hash = argon2.hash(new_password)
            await conn.execute(
                f"UPDATE {table_name} SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2",
                new_hash, user['id']
            )
            return True
    return False

async def change_password(user_id: int, old_password: str, new_password: str) -> bool:
    if not check_password_strength(new_password):
        raise ValueError("New password does not meet strength requirements")
    
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow(f"SELECT password_hash FROM {table_name} WHERE id = $1", user_id)
        if user and argon2.verify(old_password, user['password_hash']):
            new_hash = argon2.hash(new_password)
            await conn.execute(
                f"UPDATE {table_name} SET password_hash = $1 WHERE id = $2",
                new_hash, user_id
            )
            return True
    return False

async def get_user(email: str) -> Optional[Dict[str, Any]]:
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT id, email, verified FROM {table_name} WHERE email = $1",
            email
        )
    return dict(row) if row else None

async def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT id, email, verified FROM {table_name} WHERE id = $1",
            user_id
        )
    return dict(row) if row else None

def _generate_jwt(user_id: int, email: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(seconds=config.jwt_expiration)
    }
    return jwt.encode(payload, secret_key, algorithm=config.jwt_algorithm)

def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, secret_key, algorithms=[config.jwt_algorithm])
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

# Additional utility functions
async def set_verified(user_id: int, verified: bool = True) -> bool:
    async with db_pool.acquire() as conn:
        await conn.execute(
            f"UPDATE {table_name} SET verified = $1 WHERE id = $2",
            verified, user_id
        )
    return True
