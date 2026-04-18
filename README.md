# TEE-Judge

Intel SGX 기반 온라인 저지 시스템. 채점을 사용자 PC의 SGX Enclave 안에서 수행하고, DCAP Attestation + Azure MAA로 결과 무결성을 하드웨어 수준에서 보장합니다.

## 아키텍처

```
[브라우저]                    [사용자 PC (Ubuntu + Intel SGX)]
  - 문제 보기                   - Judge Client (Python)
  - 코드 제출                   - SGX Enclave (libtcc로 코드 컴파일+실행)
  - 결과 확인                   - DCAP Attestation Quote 생성
       |                              |
       |         HTTPS                |  HTTPS
       +-------> [서버 (Azure)] <-----+
                 FastAPI + SQLite
                 - 문제/테스트케이스 관리
                 - Attestation 검증 (Azure MAA)
                 - 서버 측 verdict 판정
                 - 결과 저장/표시
```

## 채점 흐름 (v4)

```
1. 사용자가 웹에서 C/C++ 코드 제출
2. 서버가 DB에 저장 (PENDING), 테스트케이스 입력만 Judge Client에 전송
3. Judge Client가 작업 폴링
4. [SGX Enclave] libtcc로 코드 컴파일 + 각 테스트케이스 실행 (subprocess 없음)
5. [SGX Enclave] 출력 해시 + ECDSA 서명 + DCAP Attestation Quote 생성
6. Judge Client가 actual_outputs + 서명 + Quote를 서버에 전송
7. 서버가 actual vs expected 비교 → verdict 판정
8. 서버가 ECDSA 서명 + Azure MAA로 Quote 검증
9. 브라우저에서 결과 표시 (AC/WA/TLE/CE + Attestation 상태)
```

**핵심 보안 특성:**
- 서버가 expected_output을 클라이언트에 절대 전송하지 않음 → 정답 유출 차단
- 코드 실행이 SGX Enclave 안에서만 이루어짐 → 호스트가 입출력 조작 불가
- DCAP Attestation으로 "이 코드가 진짜 SGX에서 실행됐음"을 하드웨어 수준에서 증명

## 빠른 시작

### 서버 실행 (Docker)

```bash
git clone https://github.com/GonGe1018/tee-judge.git
cd tee-judge

# 환경변수 설정 (.env 파일 생성)
cat > .env << EOF
TEE_JUDGE_SECRET=<랜덤 시크릿>
TEE_JUDGE_JUDGE_KEY=<Judge Client 인증 키>
TEE_JUDGE_MAA_ENDPOINT=https://<your-maa>.attest.azure.net
TEE_JUDGE_CORS_ORIGINS=https://your-domain.com
EOF

docker compose up -d
```

브라우저에서 `http://서버IP:8000` 접속.

### Judge Client 설치 (Ubuntu + Intel SGX)

```bash
curl -fsSL https://raw.githubusercontent.com/GonGe1018/tee-judge/main/install-client.sh | bash
```

설치 후 실행:

```bash
TEE_JUDGE_SERVER=https://your-server.com \
TEE_JUDGE_JUDGE_KEY=<Judge Client 인증 키> \
tee-judge
```

## 프로젝트 구조

```
tee-judge/
├── app/                        # 서버 (FastAPI)
│   ├── api/
│   │   ├── judge/
│   │   │   ├── router.py       # Judge Client API (poll/report)
│   │   │   └── dto.py          # JudgeTask, JudgeResultRequest
│   │   ├── submissions/
│   │   │   ├── router.py       # 제출/결과 API
│   │   │   └── dto.py
│   │   ├── users/
│   │   │   ├── router.py       # 인증 API
│   │   │   └── dto.py
│   │   ├── problems/
│   │   │   ├── router.py       # 문제 API
│   │   │   └── dto.py
│   │   └── ws/router.py        # WebSocket (실시간 결과 알림)
│   ├── core/
│   │   ├── config.py           # pydantic-settings 설정
│   │   ├── auth.py             # JWT + bcrypt
│   │   ├── quote_verify.py     # SGX Quote 파싱 + Azure MAA 검증
│   │   └── security.py         # Rate limiting
│   └── db/
│       ├── database.py         # SQLite 연결 + 스키마
│       ├── users_crud.py       # User CRUD
│       ├── submissions_crud.py # Submission CRUD
│       ├── problems_crud.py    # Problem/Testcase CRUD
│       └── results_crud.py     # Result CRUD
├── client/                     # Judge Client
│   ├── daemon.py               # WebSocket + HTTP 폴링 데몬
│   ├── enclave_judge.py        # Enclave 실행 + ECDSA 서명 + Attestation
│   ├── enclave_entry.py        # Gramine enclave 진입점
│   ├── enclave_keys.py         # ECDSA P-256 키쌍 관리
│   └── tcc_runner.py           # libtcc ctypes 래퍼 (enclave 내 C 실행)
├── frontend/                   # 웹 UI (HTML/CSS/JS)
├── data/problems/              # 테스트케이스 (문제별 .in/.out 파일)
├── deploy/gramine/             # Gramine manifest 템플릿
├── docker-compose.yml
├── Dockerfile
├── install-client.sh
└── test_e2e.py                 # E2E 테스트 (12개)
```

## 보안 모델

| 위협 | 방어 |
|------|------|
| 정답 유출 | 서버가 expected_output을 클라이언트에 전송하지 않음 |
| 출력 위조 | SGX Enclave 안에서 libtcc로 실행 → 호스트 접근 불가 |
| 서명 위조 | ECDSA P-256 + DCAP Attestation Quote 바인딩 |
| 재생 공격 | 제출마다 fresh nonce 발급 |
| Debug Enclave | Azure MAA에서 `x-ms-sgx-is-debuggable` 거부 |
| 다른 Enclave | MRENCLAVE 검증 (선택적) |

## 환경변수

| 변수 | 필수 | 설명 |
|------|------|------|
| `TEE_JUDGE_SECRET` | 프로덕션 필수 | JWT 서명 시크릿 |
| `TEE_JUDGE_JUDGE_KEY` | 프로덕션 필수 | Judge Client 인증 키 |
| `TEE_JUDGE_MAA_ENDPOINT` | SGX 필수 | Azure MAA 엔드포인트 |
| `TEE_JUDGE_ENV` | 선택 | `dev` / `production` (기본: `production`) |
| `TEE_JUDGE_ALLOW_MOCK` | 선택 | `true` — dev 환경에서만 mock attestation 허용 |
| `TEE_JUDGE_MRENCLAVE` | 선택 | 기대 MRENCLAVE 값 (빈 값이면 검증 스킵) |
| `TEE_JUDGE_CORS_ORIGINS` | 선택 | 허용 CORS origin (쉼표 구분) |

## 기술 스택

| 컴포넌트 | 기술 |
|---------|------|
| 서버 | Python 3.11, FastAPI, SQLite |
| 프론트엔드 | HTML, CSS, Vanilla JS |
| Judge Client | Python 3.11, libtcc (C 코드 인메모리 컴파일+실행) |
| SGX 런타임 | Gramine 1.8, Intel SGX DCAP |
| Attestation | Azure MAA (Microsoft Azure Attestation) |
| 배포 | Docker, Docker Compose, Azure DCsv3 VM |

## 문제 목록

| ID | 제목 | 테스트케이스 |
|----|------|------------|
| 1000 | A+B | 30개 |
| 1001 | A-B | 30개 |
| 1002 | A*B | 30개 |
| 1003 | 최댓값 | 30개 |
| 1004 | 합계 | 30개 |

## 요구 사항

### 서버
- Docker 또는 Python 3.11+
- Azure VM (SGX 검증 시 Azure MAA 필요)

### Judge Client
- Ubuntu 20.04+ (x86_64)
- Intel SGX 지원 CPU + DCAP 드라이버
- Gramine 1.8
- libtcc (`apt install tcc`)

## 라이선스

MIT
