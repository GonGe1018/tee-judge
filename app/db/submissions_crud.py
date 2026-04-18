import sqlite3
from typing import Optional


def create_submission(
    conn: sqlite3.Connection,
    user_id: int,
    problem_id: int,
    language: str,
    code: str,
    code_hash: str,
) -> int:
    cursor = conn.execute(
        "INSERT INTO submissions (user_id, problem_id, language, code, code_hash, status) VALUES (?, ?, ?, ?, ?, 'PENDING')",
        (user_id, problem_id, language, code, code_hash),
    )
    return cursor.lastrowid


def get_submission_by_id(
    conn: sqlite3.Connection, submission_id: int
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM submissions WHERE id = ?", (submission_id,)
    ).fetchone()


def update_submission_status(
    conn: sqlite3.Connection,
    submission_id: int,
    status: str,
    nonce: Optional[str] = None,
) -> None:
    if nonce is None:
        conn.execute(
            "UPDATE submissions SET status = ? WHERE id = ?", (status, submission_id)
        )
    else:
        conn.execute(
            "UPDATE submissions SET status = ?, nonce = ? WHERE id = ?",
            (status, nonce, submission_id),
        )


def get_pending_submission_for_user(
    conn: sqlite3.Connection, user_id: int
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM submissions WHERE status = 'PENDING' AND user_id = ? ORDER BY id LIMIT 1",
        (user_id,),
    ).fetchone()
