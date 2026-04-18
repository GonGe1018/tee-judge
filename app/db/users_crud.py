"""User DB operations."""

from __future__ import annotations

import sqlite3
from typing import Optional


def get_user_by_username(
    conn: sqlite3.Connection, username: str
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_user(conn: sqlite3.Connection, username: str, password_hash: str) -> int:
    cursor = conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    conn.commit()
    return cursor.lastrowid


def get_enclave_public_key(conn: sqlite3.Connection, user_id: int) -> Optional[str]:
    row = conn.execute(
        "SELECT enclave_public_key FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return row["enclave_public_key"] if row else None


def set_user_enclave_key(
    conn: sqlite3.Connection, user_id: int, public_key: str
) -> None:
    conn.execute(
        "UPDATE users SET enclave_public_key = ? WHERE id = ?",
        (public_key, user_id),
    )
    conn.commit()
