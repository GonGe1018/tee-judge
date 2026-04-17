"""Database connection and initialization."""

import sqlite3
from contextlib import contextmanager

from app.core.config import settings


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_conn():
    """Context manager for safe DB connection handling."""
    conn = get_db()
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            enclave_public_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS problems (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            input_desc TEXT,
            output_desc TEXT,
            sample_input TEXT,
            sample_output TEXT,
            time_limit_ms INTEGER DEFAULT 2000,
            memory_limit_kb INTEGER DEFAULT 262144,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS testcases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            problem_id INTEGER NOT NULL,
            input_data TEXT NOT NULL,
            expected_output TEXT NOT NULL,
            order_num INTEGER NOT NULL,
            FOREIGN KEY (problem_id) REFERENCES problems(id)
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            problem_id INTEGER NOT NULL,
            language TEXT NOT NULL,
            code TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            nonce TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (problem_id) REFERENCES problems(id)
        );

        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL UNIQUE,
            verdict TEXT NOT NULL,
            time_ms INTEGER,
            memory_kb INTEGER,
            test_passed INTEGER,
            test_total INTEGER,
            attestation_quote BLOB,
            attestation_verified BOOLEAN DEFAULT 0,
            verdict_signature BLOB,
            nonce TEXT,
            judged_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (submission_id) REFERENCES submissions(id)
        );
    """)
    conn.commit()
    _seed_problems(conn)
    conn.close()


def _seed_problems(conn: sqlite3.Connection):
    """Insert all problems if not exists."""
    PROBLEMS = [
        {
            "id": 1000,
            "title": "A+B",
            "description": "두 정수 A와 B를 입력받은 다음, A+B를 출력하는 프로그램을 작성하시오.",
            "input_desc": "첫째 줄에 A와 B가 주어진다. (0 <= A, B <= 1000000)",
            "output_desc": "첫째 줄에 A+B를 출력한다.",
            "sample_input": "1 2",
            "sample_output": "3",
        },
        {
            "id": 1001,
            "title": "A-B",
            "description": "두 정수 A와 B를 입력받은 다음, A-B를 출력하는 프로그램을 작성하시오.",
            "input_desc": "첫째 줄에 A와 B가 주어진다. (0 <= A, B <= 1000000)",
            "output_desc": "첫째 줄에 A-B를 출력한다.",
            "sample_input": "3 1",
            "sample_output": "2",
        },
        {
            "id": 1002,
            "title": "A*B",
            "description": "두 정수 A와 B를 입력받은 다음, A*B를 출력하는 프로그램을 작성하시오.",
            "input_desc": "첫째 줄에 A와 B가 주어진다. (0 <= A, B <= 100000)",
            "output_desc": "첫째 줄에 A*B를 출력한다.",
            "sample_input": "1 2",
            "sample_output": "2",
        },
        {
            "id": 1003,
            "title": "최댓값",
            "description": "N개의 정수가 주어졌을 때, 그 중 최댓값을 구하는 프로그램을 작성하시오.",
            "input_desc": "첫째 줄에 정수의 개수 N (1 <= N <= 100)이 주어진다. 둘째 줄에 N개의 정수가 공백으로 구분되어 주어진다. 각 정수는 -1000000 이상 1000000 이하이다.",
            "output_desc": "첫째 줄에 최댓값을 출력한다.",
            "sample_input": "5\n1 2 3 4 5",
            "sample_output": "5",
        },
        {
            "id": 1004,
            "title": "합계",
            "description": "N개의 정수가 주어졌을 때, 그 합을 구하는 프로그램을 작성하시오.",
            "input_desc": "첫째 줄에 정수의 개수 N (1 <= N <= 100)이 주어진다. 둘째 줄에 N개의 정수가 공백으로 구분되어 주어진다. 각 정수는 -1000000 이상 1000000 이하이다.",
            "output_desc": "첫째 줄에 합계를 출력한다.",
            "sample_input": "5\n1 2 3 4 5",
            "sample_output": "15",
        },
    ]

    for p in PROBLEMS:
        row = conn.execute(
            "SELECT id FROM problems WHERE id = ?", (p["id"],)
        ).fetchone()
        if row:
            continue

        conn.execute(
            """INSERT INTO problems (id, title, description, input_desc, output_desc,
               sample_input, sample_output, time_limit_ms, memory_limit_kb)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                p["id"],
                p["title"],
                p["description"],
                p["input_desc"],
                p["output_desc"],
                p["sample_input"],
                p["sample_output"],
                2000,
                262144,
            ),
        )

        problem_dir = settings.PROBLEMS_DIR / str(p["id"])
        if problem_dir.exists():
            i = 1
            while (problem_dir / f"{i}.in").exists() and (
                problem_dir / f"{i}.out"
            ).exists():
                input_data = (
                    (problem_dir / f"{i}.in").read_text(encoding="utf-8").strip()
                )
                expected = (
                    (problem_dir / f"{i}.out").read_text(encoding="utf-8").strip()
                )
                conn.execute(
                    "INSERT INTO testcases (problem_id, input_data, expected_output, order_num) VALUES (?, ?, ?, ?)",
                    (p["id"], input_data, expected, i),
                )
                i += 1

    conn.commit()
