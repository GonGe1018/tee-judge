"""Generate testcases for problems 1001-1004"""

import random
import os
from pathlib import Path

random.seed(123)

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent


def write_cases(problem_id, cases):
    base = PROJECT_DIR / "data" / "problems" / str(problem_id)
    base.mkdir(parents=True, exist_ok=True)
    base = str(base)
    for i, (inp, out) in enumerate(cases, 1):
        with open(os.path.join(base, f"{i}.in"), "w") as f:
            f.write(inp + "\n")
        with open(os.path.join(base, f"{i}.out"), "w") as f:
            f.write(out + "\n")
    print(f"Problem {problem_id}: {len(cases)} testcases")


# === 1001: A-B ===
cases = []
cases.append(("3 1", "2"))
cases.append(("0 0", "0"))
cases.append(("1000000 0", "1000000"))
cases.append(("0 1000000", "-1000000"))
cases.append(("1000000 1000000", "0"))
cases.append(("1 1000000", "-999999"))
cases.append(("500000 250000", "250000"))
cases.append(("999999 1", "999998"))
cases.append(("100 200", "-100"))
cases.append(("7 3", "4"))
for _ in range(20):
    a = random.randint(0, 1000000)
    b = random.randint(0, 1000000)
    cases.append((f"{a} {b}", str(a - b)))
write_cases(1001, cases)

# === 1002: A*B ===
cases = []
cases.append(("1 2", "2"))
cases.append(("0 0", "0"))
cases.append(("0 999999", "0"))
cases.append(("1 1", "1"))
cases.append(("1000 1000", "1000000"))
cases.append(("10000 10000", "100000000"))
cases.append(("99999 1", "99999"))
cases.append(("12345 6789", "83810205"))
cases.append(("100000 100000", "10000000000"))
cases.append(("3 7", "21"))
for _ in range(20):
    a = random.randint(0, 100000)
    b = random.randint(0, 100000)
    cases.append((f"{a} {b}", str(a * b)))
write_cases(1002, cases)

# === 1003: Max of N numbers ===
cases = []
cases.append(("5\n1 2 3 4 5", "5"))
cases.append(("1\n42", "42"))
cases.append(("3\n-1 -2 -3", "-1"))
cases.append(("4\n0 0 0 0", "0"))
cases.append(("5\n1000000 999999 999998 999997 999996", "1000000"))
cases.append(("3\n-1000000 0 1000000", "1000000"))
cases.append(("2\n-500000 -500001", "-500000"))
cases.append(("6\n1 1 1 1 1 1", "1"))
cases.append(("3\n100 200 150", "200"))
cases.append(("4\n-10 -20 -5 -15", "-5"))
for _ in range(20):
    n = random.randint(1, 100)
    nums = [random.randint(-1000000, 1000000) for _ in range(n)]
    inp = str(n) + "\n" + " ".join(map(str, nums))
    out = str(max(nums))
    cases.append((inp, out))
write_cases(1003, cases)

# === 1004: Sum of N numbers ===
cases = []
cases.append(("5\n1 2 3 4 5", "15"))
cases.append(("1\n0", "0"))
cases.append(("3\n1000000 1000000 1000000", "3000000"))
cases.append(("4\n-1 -2 -3 -4", "-10"))
cases.append(("2\n1000000 -1000000", "0"))
cases.append(("1\n999999", "999999"))
cases.append(("5\n0 0 0 0 0", "0"))
cases.append(("3\n100 200 300", "600"))
cases.append(("6\n1 -1 2 -2 3 -3", "0"))
cases.append(("2\n500000 500000", "1000000"))
for _ in range(20):
    n = random.randint(1, 100)
    nums = [random.randint(-1000000, 1000000) for _ in range(n)]
    inp = str(n) + "\n" + " ".join(map(str, nums))
    out = str(sum(nums))
    cases.append((inp, out))
write_cases(1004, cases)

print("\nDone!")
