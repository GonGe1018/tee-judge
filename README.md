# TEE-Judge

Intel SGX 기반 온라인 저지 시스템. 채점을 TEE(Trusted Execution Environment) 안에서 수행하여 채점 결과의 무결성을 하드웨어 수준에서 보장합니다.

## 아키텍처

```
[브라우저]                         [사용자 PC (Ubuntu + Intel SGX)]
  - 문제 보기                        - Judge Client (Docker)
  - 코드 제출                        - SGX Enclave (채점 검증)
  - 결과 확인                        - DCAP Attestation
       |                                  |
       |          HTTPS                   |  HTTPS
       +---------> [서버] <---------------+
                  (Docker)
                  - 문제/테스트케이스 관리
                  - Attestation 검증
                  - 결과 저장/표시
```

## 빠른 시작

### 서버 실행 (Docker)

```bash
git clone https://github.com/GonGe1018/tee-judge.git
cd tee-judge
docker compose up -d
```

브라우저에서 `http://서버IP:8000` 접속.
API 문서: `http://서버IP:8000/docs`

### 서버 실행 (직접)

```bash
pip install -r server-requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Judge Client 설치 (Ubuntu)

SGX 하드웨어가 있는 Ubuntu 머신에서:

```bash
curl -fsSL https://raw.githubusercontent.com/GonGe1018/tee-judge/main/install-client.sh | bash
```

설치 후 실행:

```bash
# 로컬 서버에 연결
tee-judge

# 원격 서버에 연결
TEE_JUDGE_SERVER=http://서버IP:8000 tee-judge
```

SGX 하드웨어가 없으면 자동으로 mock 모드로 동작합니다.

## 사용 방법

1. 브라우저에서 서버에 접속
2. 문제 목록에서 문제 선택
3. C/C++ 코드를 작성하고 제출
4. Judge Client가 자동으로 채점 (SGX Enclave에서 검증)
5. 브라우저에서 결과 확인 (AC/WA/TLE/CE + Attestation 상태)

## 프로젝트 구조

```
tee-judge/
├── app/                    # 서버 애플리케이션
│   ├── api/                # API 라우터
│   │   ├── problems/       # 문제 관리 API
│   │   ├── submissions/    # 제출/결과 API
│   │   └── judge/          # Judge Client 통신 API
│   ├── core/               # 설정, 스키마
│   └── db/                 # 데이터베이스
├── client/                 # Judge Client
│   ├── daemon.py           # 자동 폴링 데몬
│   └── enclave_judge.py    # 2-phase 채점 (host + enclave)
├── frontend/               # 웹 UI
├── data/                   # 테스트케이스
├── deploy/                 # 배포 설정 (Gramine manifest)
├── Dockerfile              # 서버 Docker 이미지
├── Dockerfile.client       # Judge Client Docker 이미지
├── docker-compose.yml      # 서버 배포
└── install-client.sh       # Judge Client 설치 스크립트
```

## 채점 흐름

```
1. 사용자가 웹에서 코드 제출
2. 서버가 DB에 저장 (PENDING)
3. Judge Client가 작업을 폴링
4. [Phase 1 - Host] GCC로 컴파일 + 테스트케이스 실행
5. [Phase 2 - SGX Enclave] 결과 검증 + DCAP Attestation Quote 생성 + 서명
6. Judge Client가 서버에 결과 보고
7. 서버가 Attestation 검증 후 결과 저장
8. 브라우저에서 결과 표시
```

## 보안

- DCAP Attestation: 실제 SGX 하드웨어에서 생성된 Quote로 enclave 무결성 검증
- Nonce 바인딩: 매 세션마다 fresh nonce로 재생 공격 방지
- 결과 서명: enclave 내부에서 verdict에 서명, 외부 위변조 탐지
- Host/Enclave 분리: host는 정답(expected)에 접근 불가, enclave만 검증 수행

## 기술 스택

| 컴포넌트 | 기술 |
|---------|------|
| 서버 | Python, FastAPI, SQLite |
| 프론트엔드 | HTML, CSS, JavaScript |
| Judge Client | Python, GCC/G++ |
| SGX 런타임 | Gramine 1.8, Intel SGX DCAP |
| 배포 | Docker, Docker Compose |

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

### Judge Client
- Ubuntu 20.04+ (x86_64)
- Docker
- Intel SGX 지원 CPU (선택 — 없으면 mock 모드)

## 라이선스

MIT
