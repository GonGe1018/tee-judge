"""Result DB operations."""

from __future__ import annotations

import sqlite3
from typing import Optional


def get_result_by_submission_id(
    conn: sqlite3.Connection, submission_id: int
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM results WHERE submission_id = ?", (submission_id,)
    ).fetchone()


def get_result_with_submission(
    conn: sqlite3.Connection, submission_id: int
) -> Optional[sqlite3.Row]:
    return conn.execute(
        """
        SELECT s.id as submission_id, s.problem_id, r.verdict, r.time_ms, r.memory_kb,
               r.test_passed, r.test_total, r.attestation_verified, r.nonce, r.judged_at
        FROM submissions s
        JOIN results r ON r.submission_id = s.id
        WHERE s.id = ?
        """,
        (submission_id,),
    ).fetchone()


def insert_result(
    conn: sqlite3.Connection,
    submission_id: int,
    verdict: str,
    time_ms: int,
    memory_kb: int,
    test_passed: int,
    test_total: int,
    attestation_quote: str,
    attestation_verified: bool,
    verdict_signature: str,
    nonce: str,
) -> int:
    cursor = conn.execute(
        """INSERT INTO results
           (submission_id, verdict, time_ms, memory_kb, test_passed, test_total,
            attestation_quote, attestation_verified, verdict_signature, nonce)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            submission_id,
            verdict,
            time_ms,
            memory_kb,
            test_passed,
            test_total,
            attestation_quote,
            int(attestation_verified),
            verdict_signature,
            nonce,
        ),
    )
    conn.commit()
    return cursor.lastrowid
