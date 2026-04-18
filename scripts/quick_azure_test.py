"""Quick test on Azure."""

import requests, time

HOST = "http://172.192.154.85"

# Login
r = requests.post(
    f"{HOST}/api/auth/login", json={"username": "demo", "password": "demoPass1234"}
)
token = r.json()["token"]
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Submit correct A+B
code = '#include <stdio.h>\nint main(){int a,b;scanf("%d %d",&a,&b);printf("%d",a+b);return 0;}'
r = requests.post(
    f"{HOST}/api/submit",
    json={"problem_id": 1000, "language": "c", "code": code},
    headers=headers,
)
sid = r.json()["submission_id"]
print(f"Submitted #{sid}")

for i in range(20):
    time.sleep(2)
    r = requests.get(f"{HOST}/api/result/{sid}", headers=headers)
    if r.status_code == 200 and r.json().get("verdict"):
        d = r.json()
        print(
            f"Result: {d['verdict']} ({d['test_passed']}/{d['test_total']}) attestation={d['attestation_verified']}"
        )
        break
    print(f"  Waiting... ({i + 1})")
else:
    print("Timeout")
