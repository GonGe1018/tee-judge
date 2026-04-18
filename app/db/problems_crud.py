import sqlite3
from typing import List, Optional


def list_problems(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT id, title, time_limit_ms, memory_limit_kb FROM problems ORDER BY id"
    ).fetchall()


def get_problem_by_id(
    conn: sqlite3.Connection, problem_id: int
) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM problems WHERE id = ?", (problem_id,)).fetchone()


def get_testcases_for_problem(conn: sqlite3.Connection, problem_id: int):
    return conn.execute(
        "SELECT order_num, input_data, expected_output FROM testcases WHERE problem_id = ? ORDER BY order_num",
        (problem_id,),
    ).fetchall()
