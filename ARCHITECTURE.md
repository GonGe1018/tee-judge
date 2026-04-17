# TEE-Judge: TEE 기반 온라인 저지 시스템 - 아키텍처 및 구현 설계서

## 1. 개요

### 1.1 프로젝트 목표
TEE(Trusted Execution Environment) 기반으로 온라인 저지의 채점을 SGX Enclave 내부에서 수행하고,
서버는 Attestation 검증만 담당하는 시스템을 설계 및 구현한다.

### 1.2 배경
- 백준 온라인 저지(BOJ)가 2026년 4월 28일 서비스 종료 발표
- 원인: 서버 비용, DDoS 공격, 1인 운영의 한계
- 기존 구조: 서버가 모든 제출 코드를 컴파일+실행+채점 -> 서버 부하 집중
- 제안: 채점을 클라이언트 TEE로 오프로딩하여 서버 부하를 극적으로 감소

### 1.3 핵심 아이디어
- 서버: 코드 수신, 컴파일, 테스트케이스 보관, Attestation 검증, 최종 판정
- 클라이언트 TEE(Enclave): 바이너리 실행, 테스트케이스 비교, 결과 서명
- 서버는 Enclave가 생성한 서명된 결과(verdict)만 검증

## 2. 시스템 아키텍처

### 2.1 전체 구성도

```
+------------------+       HTTPS        +------------------------+
|                  | <----------------> |                        |
|   Web Frontend   |                    |   Backend Server       |
|   (HTML/CSS/JS)  |                    |   (Python + FastAPI)   |
|                  |                    |                        |
|  - 문제 보기      |                    |  - 문제/테스트케이스 관리 |
|  - 결과 확인      |                    |  - Attestation 검증     |
|                  |                    |  - 결과 저장/표시       |
+------------------+                    +-----+------------------+
                                              |
                                              | HTTPS (RA-TLS)
                                              |
+------------------+                    +-----v------------------+
|                  |    RA-TLS 채널      |                        |
|  사용자 PC        | <----------------> |   SQLite Database      |
|                  |                    |  - problems            |
|  Judge Client    |                    |  - testcases           |
|  (C/C++ CLI)     |                    |  - submissions         |
|                  |                    |  - results             |
|  +-------------+ |                    +------------------------+
|  | SGX Enclave | |
|  | - 채점 실행  | |
|  | - 출력 비교  | |
|  | - 결과 서명  | |
|  | - Quote 생성 | |
|  +-------------+ |
+------------------+
```

### 2.2 컴포넌트 상세

| 컴포넌트 | 기술 | 역할 |
|---------|------|------|
| Web Frontend | 순수 HTML/CSS/JS (프레임워크 없음) | 코드 제출 폼, 결과 표시 |
| Backend Server | Python + FastAPI (경량 HTTP 서버) | REST API, 컴파일 오케스트레이션, Enclave 통신 |
| SGX Enclave | C/C++ + Gramine | 채점 실행, 결과 검증, Attestation, 결과 서명 |
| Database | SQLite (임베디드) | 문제/테스트케이스/제출/결과 저장 |
| Infrastructure | Azure DCsv3 VM (Ubuntu 22.04) | SGX 하드웨어 + DCAP Attestation |

## 3. 디렉토리 구조

```
tee-judge/
├── ARCHITECTURE.md          # 본 설계 문서
├── README.md                # 프로젝트 소개
├── Makefile                 # 빌드 스크립트
├── gramine-manifest.toml    # Gramine SGX 매니페스트
│
├── frontend/                # 웹 프론트엔드
│   ├── index.html           # 메인 페이지 (문제 목록)
│   ├── submit.html          # 코드 제출 페이지
│   ├── result.html          # 결과 확인 페이지
│   ├── style.css            # 스타일시트
│   └── app.js               # API 호출 로직
│
├── server/                  # 백엔드 서버
│   ├── main.c               # 서버 진입점 (FastAPI)
│   ├── api.c                # REST API 핸들러
│   ├── api.h
│   ├── compiler.c           # GCC 컴파일 래퍼
│   ├── compiler.h
│   ├── db.c                 # SQLite 접근 레이어
│   ├── db.h
│   ├── enclave_iface.c      # Enclave ECALL/OCALL 인터페이스
│   ├── enclave_iface.h
│   └── 
│
├── enclave/                 # SGX Enclave 코드
│   ├── judge.c              # 채점 로직 (입출력 비교, 시간 측정)
│   ├── judge.h
│   ├── attestation.c        # Attestation Quote 생성 및 검증
│   ├── attestation.h
│   ├── crypto.c             # 결과 서명 (HMAC/ECDSA)
│   ├── crypto.h
│   ├── sandbox.c            # 바이너리 실행 샌드박스
│   └── sandbox.h
│
├── data/                    # 데이터
│   ├── judge.db             # SQLite 데이터베이스 파일
│   └── problems/            # 문제별 테스트케이스
│       └── 1000/            # 문제 ID
│           ├── 1.in         # 테스트케이스 입력
│           ├── 1.out        # 테스트케이스 정답
│           ├── 2.in
│           └── 2.out
│
├── scripts/                 # 유틸리티 스크립트
│   ├── setup-azure.sh       # Azure VM 초기 세팅
│   ├── setup-sgx.sh         # SGX/Gramine 설치
│   └── run-attacks.sh       # 보안 검증 공격 시뮬레이션
│
└── docs/                    # 논문 관련
    ├── paper.tex            # KCC 논문 원고
    └── figures/             # 논문용 다이어그램
```

## 4. 데이터 흐름 (End-to-End)

### 4.1 8단계 채점 흐름

**1단계: 코드 제출**
- 사용자가 웹 UI에서 C/C++ 코드를 작성하고 제출
- Frontend -> POST /api/submit (code, problem_id, language)
- Backend: submission 레코드를 DB에 저장, 상태를 PENDING으로 설정

**2단계: 컴파일**
- Backend가 GCC로 코드를 컴파일 (Enclave 밖에서 수행)
- 명령: gcc -O2 -o /tmp/submissions/{id}/a.out source.c
- 컴파일 에러 시: 상태를 CE(Compilation Error)로 설정하고 종료
- 성공 시: 실행 파일 경로를 기록

**3단계: Attestation 핸드셰이크**
- Backend -> Enclave: fresh nonce 발급 (32바이트 랜덤)
- Enclave: DCAP Quote 생성 (MRENCLAVE + nonce 포함)
- Quote에 포함되는 정보:
  - MRENCLAVE: Enclave 코드의 SHA-256 해시 (지문)
  - MRSIGNER: Enclave 서명자의 해시
  - nonce: 서버가 발급한 일회용 난수
  - CPU SVN, QE Identity 등 하드웨어 정보

**4단계: Quote 검증**
- Backend가 DCAP Quote Verification Library(QVL)로 검증:
  - MRENCLAVE == 기대값 (우리가 빌드한 judge enclave의 해시)
  - nonce == 방금 발급한 값 (재생 공격 방지)
  - Quote 서명 체인이 Intel Root CA까지 유효
  - TCB(Trusted Computing Base) 상태가 UpToDate
- 검증 실패 시: 채점 거부, 에러 반환

**5단계: 테스트케이스 전달**
- 검증 통과 후 RA-TLS 암호화 채널 수립
- Backend -> Enclave: 테스트케이스 (입력값 + 정답)를 암호화 채널로 전송
- 테스트케이스는 Enclave 메모리 안에서만 평문으로 존재
- 호스트 OS, 다른 프로세스에서 접근 불가 (CPU 하드웨어가 암호화)

**6단계: Enclave 내 실행**
- Enclave가 각 테스트케이스에 대해:
  - 컴파일된 바이너리를 샌드박스에서 실행
  - stdin으로 테스트 입력 전달
  - stdout 캡처
  - 시간 제한(Time Limit) 및 메모리 제한 적용
  - 시간 초과 시 프로세스 강제 종료

**7단계: 채점 + 결과 서명**
- Enclave 내부에서 각 테스트케이스의 출력과 정답을 비교:
  - 일치: AC (Accepted)
  - 불일치: WA (Wrong Answer)
  - 시간 초과: TLE (Time Limit Exceeded)
  - 런타임 에러: RE (Runtime Error)
- 최종 verdict 결정 (하나라도 실패하면 해당 상태)
- 결과에 암호화 서명 생성:
  - 서명 대상: submission_id + problem_id + verdict + 각 테스트 결과 + nonce
  - 서명 키: Enclave 내부에서만 접근 가능한 세션 키
- 서명된 verdict blob을 Backend로 반환

**8단계: 결과 반환 + 표시**
- Backend: verdict 서명 검증 (위변조 확인)
- DB에 결과 저장 (verdict, 각 테스트 결과, 실행 시간)
- Frontend: GET /api/result/{id}로 결과 조회
- 화면에 표시: verdict + Attestation 검증 상태

### 4.2 시퀀스 다이어그램

```
  Browser              Backend Server           SGX Enclave            Intel DCAP
     |                      |                       |                      |
     |  POST /api/submit    |                       |                      |
     |--------------------->|                       |                      |
     |                      |  gcc compile          |                      |
     |                      |----+                  |                      |
     |                      |    | (컴파일)          |                      |
     |                      |<---+                  |                      |
     |                      |                       |                      |
     |                      |  generate nonce       |                      |
     |                      |----+                  |                      |
     |                      |<---+                  |                      |
     |                      |                       |                      |
     |                      |  ECALL: get_quote(n)  |                      |
     |                      |---------------------->|                      |
     |                      |                       |  generate DCAP Quote |
     |                      |                       |----+                 |
     |                      |                       |<---+                 |
     |                      |  Quote + MRENCLAVE    |                      |
     |                      |<----------------------|                      |
     |                      |                       |                      |
     |                      |  verify_quote(quote)  |                      |
     |                      |--------------------------------------------->|
     |                      |  verification result  |                      |
     |                      |<---------------------------------------------|
     |                      |                       |                      |
     |                      |  [RA-TLS 채널 수립]    |                      |
     |                      |<======================|                      |
     |                      |                       |                      |
     |                      |  ECALL: run_judge     |                      |
     |                      |  (binary, testcases)  |                      |
     |                      |---------------------->|                      |
     |                      |                       |  실행 + 채점          |
     |                      |                       |  결과 서명 생성       |
     |                      |                       |----+                 |
     |                      |                       |<---+                 |
     |                      |  signed verdict       |                      |
     |                      |<----------------------|                      |
     |                      |                       |                      |
     |                      |  verify signature     |                      |
     |                      |----+                  |                      |
     |                      |<---+                  |                      |
     |                      |                       |                      |
     |                      |  save to DB           |                      |
     |                      |----+                  |                      |
     |                      |<---+                  |                      |
     |                      |                       |                      |
     |  GET /api/result/id  |                       |                      |
     |--------------------->|                       |                      |
     |  { verdict, ... }    |                       |                      |
     |<---------------------|                       |                      |
```

## 5. Attestation 흐름 상세

### 5.1 DCAP Attestation이란
- DCAP (Data Center Attestation Primitives): Intel이 제공하는 ECDSA 기반 원격 증명 방식
- 기존 EPID 방식과 달리 Intel IAS(Intel Attestation Service)에 의존하지 않음
- 로컬에서 Quote를 생성하고, DCAP QVL(Quote Verification Library)로 검증
- Azure DCsv3 VM은 DCAP를 기본 지원 (Azure Attestation Service 연동 가능)

### 5.2 RA-TLS 동작 원리
- RA-TLS = Remote Attestation + TLS
- TLS 인증서 안에 SGX Attestation Quote를 임베딩
- TLS 핸드셰이크 과정에서 자동으로 Enclave 신원 검증
- Gramine이 RA-TLS를 내장 지원 (ra_tls_attest.c, ra_tls_verify.c)
- 효과: Attestation과 암호화 채널 수립을 한 번에 처리

### 5.3 단계별 Attestation 흐름

```
1. 서버 -> Enclave: nonce 발급
   - 서버가 32바이트 cryptographically secure random nonce 생성
   - nonce를 DB에 저장 (세션 ID와 매핑)
   - ECALL을 통해 Enclave에 nonce 전달

2. Enclave -> 서버: Quote 생성
   - Enclave가 REPORT 구조체 생성:
     - MRENCLAVE: Enclave 바이너리의 SHA-256 측정값
     - MRSIGNER: Enclave 서명 키의 해시
     - REPORTDATA: nonce + 추가 사용자 데이터 (64바이트)
   - Quoting Enclave(QE)가 REPORT를 ECDSA로 서명하여 Quote 생성
   - Quote를 서버로 반환

3. 서버: Quote 검증 (DCAP QVL)
   - DCAP Quote Verification Library 호출
   - 검증 항목:
     a) MRENCLAVE == 기대값 (빌드 시 생성된 해시와 비교)
     b) MRSIGNER == 기대값 (서명자 신원 확인)
     c) REPORTDATA 내 nonce == 서버가 발급한 nonce (재생 방지)
     d) Quote 서명이 Intel Root CA 체인으로 유효
     e) TCB 상태: UpToDate / SWHardeningNeeded 등 확인
   - 검증 실패 시: 채점 거부

4. 검증 통과 -> RA-TLS 채널 수립
   - Enclave가 RA-TLS 인증서 생성 (Quote 임베딩)
   - 서버와 Enclave 사이에 TLS 1.3 암호화 채널 수립
   - 이후 모든 데이터(테스트케이스, 결과)는 이 채널을 통해 전송
```

### 5.4 MRENCLAVE와 MRSIGNER

| 필드 | 설명 | 용도 |
|------|------|------|
| MRENCLAVE | Enclave 빌드 시 생성되는 256비트 해시. Enclave 코드+데이터+힙+스택 레이아웃의 측정값 | 이 Enclave가 우리가 만든 judge 코드인지 확인 |
| MRSIGNER | Enclave 서명에 사용된 키의 해시 | 이 Enclave를 누가 서명했는지 확인 (우리 팀인지) |

- MRENCLAVE가 다르면: Enclave 코드가 변조되었거나 다른 프로그램
- MRSIGNER가 다르면: 다른 사람이 서명한 Enclave

### 5.5 Nonce를 통한 재생 공격 방지

```
정상 흐름:
  세션 A: 서버 nonce=abc123 -> Enclave Quote(nonce=abc123) -> 검증 통과

재생 공격 시도:
  세션 B: 서버 nonce=xyz789 -> 해커가 세션 A의 Quote(nonce=abc123) 재전송
  -> 서버 검증: nonce abc123 != xyz789 -> 거부

핵심: 매 세션마다 새로운 nonce를 발급하므로,
이전 세션의 Quote는 재사용 불가
```

## 6. Enclave 경계 설계

### 6.1 Trusted (Enclave 내부)

| 기능 | 설명 |
|------|------|
| 테스트케이스 복호화 | RA-TLS 채널로 수신한 암호화된 테스트케이스를 Enclave 내부에서 복호화 |
| 바이너리 실행 | 컴파일된 사용자 코드를 샌드박스 환경에서 실행 |
| stdout 캡처 | 실행 결과(표준 출력)를 Enclave 내부 버퍼에 저장 |
| 출력 비교 | 캡처된 출력과 정답을 바이트 단위로 비교 |
| 시간/메모리 측정 | 실행 시간 및 메모리 사용량 측정, 제한 초과 시 강제 종료 |
| 결과 서명 생성 | verdict + metadata를 ECDSA/HMAC으로 서명 |
| Attestation Quote 생성 | DCAP Quote 생성 (MRENCLAVE + nonce 포함) |

### 6.2 Untrusted (Enclave 외부 - Host)

| 기능 | 설명 |
|------|------|
| HTTP 서버 | FastAPI 기반 REST API 서빙 |
| 코드 컴파일 | GCC를 이용한 사용자 코드 컴파일 (컴파일러가 너무 커서 Enclave에 못 넣음) |
| DB 접근 | SQLite 읽기/쓰기 (문제, 테스트케이스, 제출, 결과) |
| 웹 UI 서빙 | 정적 HTML/CSS/JS 파일 서빙 |
| Attestation 검증 | DCAP QVL을 이용한 Quote 검증 (서버 측) |
| 결과 서명 검증 | Enclave가 생성한 서명의 유효성 확인 |

### 6.3 ECALL/OCALL 인터페이스

```c
// === ECALL (Host -> Enclave 호출) ===

// Enclave 초기화
int ecall_init_enclave(void);

// Attestation Quote 생성
// nonce: 서버가 발급한 32바이트 난수
// quote_out: 생성된 Quote 데이터
// quote_size: Quote 크기
int ecall_get_attestation_quote(
    const uint8_t* nonce, size_t nonce_len,
    uint8_t* quote_out, size_t* quote_size
);

// 채점 실행
// binary_path: 컴파일된 실행 파일 경로
// testcases: 암호화된 테스트케이스 데이터
// num_tests: 테스트케이스 수
// verdict_out: 서명된 채점 결과
int ecall_run_judge(
    const char* binary_path,
    const uint8_t* testcases, size_t testcases_len,
    int num_tests,
    uint8_t* verdict_out, size_t* verdict_size
);

// === OCALL (Enclave -> Host 호출) ===

// 바이너리 실행 (샌드박스)
// input: stdin으로 전달할 데이터
// output: stdout 캡처 결과
// time_ms: 실행 시간 (밀리초)
int ocall_exec_binary(
    const char* binary_path,
    const uint8_t* input, size_t input_len,
    uint8_t* output, size_t* output_len,
    int time_limit_ms, int* time_ms
);

// 로그 메시지 출력 (디버깅용)
void ocall_log_message(const char* msg);
```

참고: Gramine 사용 시 ECALL/OCALL 대신 Gramine의 호스트-엔클레이브 통신 메커니즘을 사용.
Gramine은 일반 Linux 시스템 콜을 투명하게 처리하므로, 위 인터페이스는 논리적 경계를 나타냄.

## 7. 보안 모델

### 7.1 위협 모델

**신뢰 경계 정의:**

| 구성 요소 | 신뢰 여부 | 이유 |
|-----------|----------|------|
| Intel CPU (SGX 하드웨어) | 신뢰 | 하드웨어 수준 격리, Intel Root of Trust |
| SGX Enclave 내부 코드 | 신뢰 | MRENCLAVE로 무결성 검증됨 |
| 호스트 OS (Ubuntu) | 비신뢰 | 공격자가 root 권한을 가질 수 있음 |
| Backend 서버 프로세스 | 비신뢰 | 호스트 OS 위에서 실행, 변조 가능 |
| 네트워크 | 비신뢰 | 중간자 공격 가능 |
| 사용자 (제출자) | 비신뢰 | 악의적 코드 제출, 시스템 공격 시도 가능 |

**공격자 능력 가정:**
- 호스트 OS의 root 권한 보유 가능
- 네트워크 트래픽 감청 및 변조 가능
- Enclave 외부 메모리 읽기/쓰기 가능
- 이전 세션의 데이터 보유 가능 (재생 공격)
- 다수의 제출을 통한 정보 수집 가능 (사이드 채널)
- 단, CPU 하드웨어 자체의 물리적 공격은 범위 밖 (논문에서 명시)

### 7.2 Attestation 정상 동작 검증

**검증 항목 및 방법:**

| 검증 항목 | 방법 | 성공 기준 |
|-----------|------|----------|
| MRENCLAVE 일치 | 빌드 시 기록된 해시와 Quote 내 MRENCLAVE 비교 | 정확히 일치 |
| nonce freshness | 서버가 발급한 nonce와 Quote 내 REPORTDATA 비교 | 정확히 일치 |
| Quote 서명 유효성 | DCAP QVL로 서명 체인 검증 (Intel Root CA까지) | 체인 전체 유효 |
| TCB 상태 | QVL 반환값 확인 | UpToDate 또는 SWHardeningNeeded |

**검증 시연 방법:**
1. 정상 케이스: 올바른 Enclave로 채점 -> Attestation 통과 -> 채점 완료
2. 변조 케이스: Enclave 바이너리를 수정 후 재실행 -> MRENCLAVE 불일치 -> 거부
3. 로그 출력: 각 검증 단계의 성공/실패를 상세 로그로 기록

### 7.3 공격 시나리오 및 방어

#### A. 재생 공격 (Replay Attack)

**공격 설명:**
이전에 성공한 Attestation Quote를 저장해두었다가,
다른 제출(오답 코드)에 대해 이전의 정답 결과를 재전송

**시뮬레이션 방법:**
```bash
# 1. 정상 제출로 정답 획득, Quote와 verdict를 파일로 저장
curl -X POST /api/submit -d '{"code":"correct_code"}' > saved_response.json

# 2. 오답 코드 제출 시, 저장된 Quote와 verdict를 주입
# (서버-Enclave 통신을 가로채서 이전 응답으로 교체)
python3 scripts/replay_attack.py --saved saved_response.json --new-submission wrong_code.c
```

**방어 메커니즘:**
- 매 제출마다 서버가 새로운 nonce 발급
- Quote의 REPORTDATA에 nonce가 포함됨
- 서버가 현재 세션의 nonce와 Quote 내 nonce를 비교
- 불일치 시 즉시 거부

**검증 방법:**
- 이전 세션의 Quote를 새 세션에 전송 -> nonce 불일치로 거부됨을 확인
- 로그에 "nonce mismatch: expected=xxx, got=yyy" 출력 확인

#### B. 결과 위변조 (Result Tampering)

**공격 설명:**
Enclave가 WA(오답)를 반환했는데, 호스트에서 이를 AC(정답)로 변조

**시뮬레이션 방법:**
```bash
# Enclave -> Host 통신을 가로채서 verdict를 변조
# verdict blob에서 "WA"를 "AC"로 변경
python3 scripts/tamper_attack.py --intercept --change-verdict WA AC
```

**방어 메커니즘:**
- Enclave 내부에서 verdict에 ECDSA 서명 생성
- 서명 대상: submission_id + problem_id + verdict + test_results + nonce
- 서버가 서명 검증 -> verdict가 1비트라도 변경되면 서명 불일치

**검증 방법:**
- 정상 verdict의 서명 검증 -> 통과
- verdict 내용을 변조 후 서명 검증 -> 실패
- 로그에 "signature verification failed" 출력 확인

#### C. 테스트케이스 추출 (Test Case Extraction)

**공격 설명:**
호스트 OS에서 Enclave 메모리를 읽어 테스트케이스를 추출 시도

**시뮬레이션 방법:**
```bash
# 1. /proc/[pid]/mem을 통해 Enclave 프로세스 메모리 읽기 시도
cat /proc//mem > memory_dump.bin

# 2. 메모리 덤프에서 테스트케이스 패턴 검색
grep -a "expected_test_pattern" memory_dump.bin
```

**방어 메커니즘:**
- SGX 하드웨어가 Enclave 메모리를 CPU 수준에서 암호화
- /proc/[pid]/mem으로 읽어도 암호화된 데이터만 보임
- Enclave 외부에서는 복호화 키에 접근 불가 (키는 CPU 내부에만 존재)

**검증 방법:**
- 메모리 덤프 시도 -> 테스트케이스 평문이 발견되지 않음을 확인
- Enclave 내부에서는 정상적으로 테스트케이스 접근 가능함을 동시에 확인

#### D. 타이밍 공격 (Timing Attack)

**공격 설명:**
여러 번 제출하면서 실행 시간 패턴을 분석하여 테스트케이스 입력값을 추론

**시뮬레이션 방법:**
```bash
# 다양한 코드를 제출하면서 실행 시간을 수집
for i in ; do
  curl -s -X POST /api/submit -d "{\"code\":\"variant_\"}" | jq '.time_ms'
done > timing_data.csv

# 통계 분석으로 테스트케이스 특성 추론 시도
python3 scripts/timing_analysis.py timing_data.csv
```

**방어 메커니즘:**
- Enclave 내부에서 실행 시간을 고정 패딩 (항상 time_limit까지 대기 후 응답)
- 외부에 노출되는 시간 정보를 최소화

**검증 방법:**
- 다양한 입력에 대해 응답 시간이 일정함을 통계적으로 확인
- 타이밍 분석으로 테스트케이스 추론이 불가능함을 보임

#### E. 출력 기반 역추론 (Output-based Inference)

**공격 설명:**
입력을 그대로 출력하는 코드를 제출하여 테스트케이스 입력값을 알아냄

**시뮬레이션 방법:**
```c
// echo 코드 제출
#include <stdio.h>
int main() {
    char buf[10000];
    while(fgets(buf, sizeof(buf), stdin))
        printf("%s", buf);
    return 0;
}
```

**방어 메커니즘:**
- 결과를 AC/WA/TLE/RE만 표시 (어떤 테스트에서 틀렸는지 미공개)
- 사용자 코드의 stdout을 외부로 반환하지 않음
- 문제당 제출 횟수 제한 + 쿨다운 적용

**검증 방법:**
- echo 코드 제출 -> WA만 표시되고 실제 출력은 노출되지 않음을 확인
- 제출 횟수 제한 초과 시 거부됨을 확인

### 7.4 사이드 채널 한계 및 완화

**정직한 한계 인정:**
TEE는 테스트케이스의 직접 접근을 하드웨어 수준에서 차단하지만,
사이드 채널(타이밍, 출력 패턴)을 통한 간접 유출은 온라인 저지 시스템의 근본적 한계로 남는다.
이는 기존 백준/Codeforces 등 모든 온라인 저지에 동일하게 적용되는 문제이다.

**완화 조치 요약:**

| 사이드 채널 | 완화 조치 | 구현 난이도 |
|------------|----------|------------|
| 타이밍 패턴 | 고정 시간 패딩 (time_limit까지 대기) | 쉬움 |
| 출력 역추론 | AC/WA/TLE만 표시, stdout 미공개 | 쉬움 |
| 브루트포스 | 제출 횟수 제한 + 쿨다운 | 쉬움 |
| 에러 메시지 유출 | stderr를 Enclave 밖으로 미전송 | 쉬움 |

## 8. API 설계

### 8.1 엔드포인트 목록

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | /api/problems | 문제 목록 조회 |
| GET | /api/problems/:id | 문제 상세 조회 |
| POST | /api/submit | 코드 제출 |
| GET | /api/status/:id | 채점 상태 조회 |
| GET | /api/result/:id | 채점 결과 조회 |

### 8.2 요청/응답 형식

**POST /api/submit**
```json
// 요청
{
  "problem_id": 1000,
  "language": "c",
  "code": "#include <stdio.h>\nint main() { int a,b; scanf(\"%d %d\",&a,&b); printf(\"%d\",a+b); }"
}

// 응답
{
  "submission_id": 42,
  "status": "PENDING",
  "message": "제출 완료. 채점 중..."
}
```

**GET /api/status/:id**
```json
// 응답
{
  "submission_id": 42,
  "status": "JUDGING",
  "progress": "3/5",
  "attestation_verified": true
}
```

**GET /api/result/:id**
```json
// 응답
{
  "submission_id": 42,
  "problem_id": 1000,
  "verdict": "AC",
  "time_ms": 12,
  "memory_kb": 1024,
  "test_count": 5,
  "attestation": {
    "verified": true,
    "mrenclave": "a1b2c3d4...",
    "nonce": "x9y8z7...",
    "timestamp": "2026-05-01T12:00:00Z"
  }
}
```

**GET /api/problems**
```json
// 응답
{
  "problems": [
    {
      "id": 1000,
      "title": "A+B",
      "time_limit_ms": 2000,
      "memory_limit_kb": 262144
    }
  ]
}
```

**GET /api/problems/:id**
```json
// 응답
{
  "id": 1000,
  "title": "A+B",
  "description": "두 정수 A와 B를 입력받은 다음, A+B를 출력하는 프로그램을 작성하시오.",
  "input_desc": "첫째 줄에 A와 B가 주어진다. (0 < A, B < 10)",
  "output_desc": "첫째 줄에 A+B를 출력한다.",
  "sample_input": "1 2",
  "sample_output": "3",
  "time_limit_ms": 2000,
  "memory_limit_kb": 262144
}
```

## 9. 데이터베이스 스키마

### 9.1 ERD 개요

```
problems 1---N testcases
problems 1---N submissions
submissions 1---1 results
```

### 9.2 테이블 정의

**problems**

| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PRIMARY KEY | 문제 ID (예: 1000) |
| title | TEXT NOT NULL | 문제 제목 |
| description | TEXT NOT NULL | 문제 설명 |
| input_desc | TEXT | 입력 설명 |
| output_desc | TEXT | 출력 설명 |
| sample_input | TEXT | 예제 입력 |
| sample_output | TEXT | 예제 출력 |
| time_limit_ms | INTEGER DEFAULT 2000 | 시간 제한 (밀리초) |
| memory_limit_kb | INTEGER DEFAULT 262144 | 메모리 제한 (KB) |
| created_at | DATETIME DEFAULT CURRENT_TIMESTAMP | 생성 시각 |

**testcases**

| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PRIMARY KEY | 테스트케이스 ID |
| problem_id | INTEGER NOT NULL | 문제 ID (FK -> problems.id) |
| input_data | BLOB NOT NULL | 테스트 입력 (암호화 저장) |
| expected_output | BLOB NOT NULL | 정답 출력 (암호화 저장) |
| order_num | INTEGER NOT NULL | 테스트케이스 순서 |

**submissions**

| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PRIMARY KEY | 제출 ID |
| problem_id | INTEGER NOT NULL | 문제 ID (FK -> problems.id) |
| language | TEXT NOT NULL | 언어 (c / cpp) |
| code | TEXT NOT NULL | 소스 코드 |
| code_hash | TEXT NOT NULL | 코드의 SHA-256 해시 |
| status | TEXT DEFAULT 'PENDING' | 상태: PENDING / COMPILING / JUDGING / DONE / CE |
| created_at | DATETIME DEFAULT CURRENT_TIMESTAMP | 제출 시각 |

**results**

| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PRIMARY KEY | 결과 ID |
| submission_id | INTEGER NOT NULL UNIQUE | 제출 ID (FK -> submissions.id) |
| verdict | TEXT NOT NULL | 최종 결과: AC / WA / TLE / RE / CE |
| time_ms | INTEGER | 최대 실행 시간 (밀리초) |
| memory_kb | INTEGER | 최대 메모리 사용량 (KB) |
| test_passed | INTEGER | 통과한 테스트 수 |
| test_total | INTEGER | 전체 테스트 수 |
| attestation_quote | BLOB | Attestation Quote 원본 |
| attestation_verified | BOOLEAN DEFAULT 0 | Attestation 검증 통과 여부 |
| verdict_signature | BLOB | Enclave가 생성한 결과 서명 |
| nonce | TEXT | 해당 세션의 nonce |
| judged_at | DATETIME DEFAULT CURRENT_TIMESTAMP | 채점 완료 시각 |

### 9.3 SQL 스키마

```sql
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
    input_data BLOB NOT NULL,
    expected_output BLOB NOT NULL,
    order_num INTEGER NOT NULL,
    FOREIGN KEY (problem_id) REFERENCES problems(id)
);

CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    problem_id INTEGER NOT NULL,
    language TEXT NOT NULL,
    code TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
```

## 10. 기술 스택 상세

### 10.1 SGX 런타임: Gramine 선택 근거

| 옵션 | 장점 | 단점 | 적합도 |
|------|------|------|--------|
| Gramine | unmodified Linux 바이너리 실행 가능, RA-TLS 내장, 문서 풍부 | LibOS 오버헤드 | 최적 |
| Occlum | 멀티프로세스 지원, 성능 우수 | 설정 복잡, Rust 의존성 | 보통 |
| Intel SGX SDK (raw) | 최대 제어, 최소 오버헤드 | ECALL/OCALL 직접 구현, 학습 곡선 높음 | 비추천 |

**Gramine 선택 이유:**
- 기존 C/C++ 바이너리를 수정 없이 Enclave에서 실행 가능
- RA-TLS를 라이브러리로 제공 -> Attestation 구현 부담 최소화
- 매니페스트 파일(TOML)로 Enclave 설정 -> 코드 변경 없이 SGX 적용
- 학부 1학년이 접근하기 가장 쉬운 옵션
- v1.9 (2025) 기준 활발히 유지보수 중

### 10.2 HTTP 서버: FastAPI 선택 근거

| 옵션 | 장점 | 단점 |
|------|------|------|
| FastAPI | 타입 힌트 기반 자동 문서, async 지원, Pydantic 검증 | Python 런타임 필요 |
| Flask | 간단, 자료 풍부 | 동기 처리, 자동 문서 없음 |
| Go net/http | 빠름, 단일 바이너리 | 새 언어 학습 필요 |

**FastAPI 선택 이유:**
- uvicorn + FastAPI로 서버 즉시 실행
- Python 프로젝트에 자연스럽게 통합
- 정적 파일 서빙 + REST API + 자동 Swagger 문서를 하나의 프로세스에서 처리
- MVP에 충분한 성능, Flask보다 빠름

### 10.3 데이터베이스: SQLite 선택 근거

**SQLite 선택 이유:**
- 별도 서버 프로세스 불필요 (임베디드)
- 단일 파일 DB -> 배포/백업 간단
- C API 직접 사용 가능
- MVP 규모(문제 1개, 제출 수십 건)에 완벽히 적합
- 설치/설정 제로

### 10.4 프론트엔드: 순수 HTML/JS 선택 근거

**프레임워크 미사용 이유:**
- React/Vue 등은 학습 비용이 높음 (비전공 1학년)
- 페이지 2-3개, API 호출 몇 개 수준 -> 프레임워크 불필요
- fetch() API + DOM 조작만으로 충분
- 빌드 도구(webpack, vite 등) 불필요 -> 복잡도 최소화

## 11. MVP 범위

### 11.1 최소 구현 범위

| 항목 | MVP 범위 | 비고 |
|------|---------|------|
| 문제 수 | 1개 (A+B) | 테스트케이스 3-5개 |
| 지원 언어 | C, C++ | GCC로 컴파일 |
| 웹 UI | 제출 폼 + 결과 페이지 | 2-3 페이지 |
| Attestation | DCAP end-to-end | nonce + MRENCLAVE 검증 |
| 보안 검증 | 재생 공격 + 결과 위변조 시연 | 최소 2개 공격 시나리오 |
| 벤치마크 | 네이티브 vs Enclave 실행 시간 비교 | 그래프 1-2개 |

### 11.2 논문 신뢰성을 위한 필수 포함 항목

- Attestation end-to-end 동작 시연 (스크린샷 + 로그)
- MRENCLAVE 검증 성공/실패 케이스
- 최소 2개 공격 시나리오의 방어 시연
- 네이티브 vs Enclave 성능 비교 데이터
- 시스템 아키텍처 다이어그램

### 11.3 생략 가능 항목 (시간 부족 시)

- 다중 문제 지원 (1개로 충분)
- 사용자 인증/로그인
- 제출 이력 페이지
- 메모리 사용량 측정
- 테스트케이스 암호화 저장 (Sealed Storage)
- 타이밍 공격 방어 시연 (논문에서 설계만 기술)

## 12. 비용 및 인프라

### 12.1 Azure DCsv3 VM 사양

| 항목 | 값 |
|------|-----|
| VM 시리즈 | DCsv3 (Standard_DC2s_v3) |
| vCPU | 2 |
| RAM | 16 GB |
| EPC 메모리 | ~8 GB (SGX Enclave용) |
| OS | Ubuntu 22.04 LTS |
| 시간당 비용 | 약 $ .17/hr (미국 동부 리전 기준) |

### 12.2 비용 예측 ($100 크레딧)

| 용도 | 예상 시간 | 비용 |
|------|----------|------|
| 환경 세팅 + SGX 테스트 | 20시간 | $3.40 |
| 개발 중 테스트 (간헐적) | 40시간 | $6.80 |
| 통합 테스트 + 디버깅 | 30시간 | $5.10 |
| 보안 검증 실험 | 10시간 | $1.70 |
| 벤치마크 측정 | 5시간 | $ .85 |
| 디스크 스토리지 (30일) | - | $3.00 |
| 합계 | 약 105시간 | 약 $21 |

여유 크레딧: 약 $79 (예상치 못한 상황 대비)

### 12.3 비용 절감 전략

1. **VM 시작/중지**: 사용하지 않을 때 반드시 VM 중지 (중지 시 컴퓨팅 비용 0)
2. **로컬 개발**: 대부분의 개발은 로컬에서 Gramine-direct(시뮬레이션)로 수행
3. **Azure는 실제 SGX 테스트만**: Attestation, 보안 검증, 벤치마크 측정 시에만 VM 사용
4. **작은 VM 사이즈**: DC2s_v3 (2 vCPU)로 충분, 더 큰 VM 불필요
5. **리전 선택**: 가장 저렴한 리전 선택 (미국 동부 권장)

### 12.4 개발 환경 구성

```
[로컬 PC (Windows/Linux)]
  - Gramine-direct 모드로 개발/테스트
  - SGX 없이 Enclave 로직 디버깅
  - 웹 UI 개발
  - 단위 테스트

[Azure DCsv3 VM (Ubuntu)]
  - 실제 SGX Enclave 실행
  - DCAP Attestation 테스트
  - 보안 검증 (공격 시뮬레이션)
  - 성능 벤치마크 측정
  - 최종 통합 테스트
```

## 13. 구현 로드맵 (4-6주)

### 1주차: 환경 구축 + Hello World Enclave

**목표:** Azure VM에서 SGX Enclave가 동작하는 것을 확인

**작업 내용:**
- Azure DCsv3 VM 생성 (Ubuntu 22.04)
- SGX 드라이버 + DCAP 라이브러리 설치
- Gramine 설치 및 설정
- Hello World Enclave 작성 및 실행
- DCAP Attestation Quote 생성 테스트

**산출물:**
- 동작하는 Azure VM 환경
- Hello World Enclave 실행 스크린샷
- Attestation Quote 생성 로그

**리스크:** SGX 드라이버 호환성 문제, Azure 리전 가용성
**대응:** Azure 공식 문서의 Confidential Computing 가이드 참조

### 2주차: 백엔드 서버 + DB + 컴파일 파이프라인

**목표:** 코드 제출 -> 컴파일 -> 실행 파이프라인 완성 (Enclave 없이)

**작업 내용:**
- FastAPI 서버 구축
- SQLite DB 스키마 생성 및 초기 데이터 삽입
- REST API 구현 (/api/submit, /api/status, /api/result, /api/problems)
- GCC 컴파일 래퍼 구현
- 샌드박스 실행 환경 구현 (seccomp, 시간 제한)
- A+B 문제 + 테스트케이스 3-5개 등록

**산출물:**
- 동작하는 REST API 서버
- 코드 제출 -> 컴파일 -> 실행 -> 결과 반환 파이프라인
- curl로 테스트한 API 응답 로그

**리스크:** 샌드박스 구현 복잡도
**대응:** 최소한의 샌드박스(시간 제한 + 프로세스 격리)로 시작

### 3주차: Enclave 채점 로직 + Attestation 흐름

**목표:** 채점을 Enclave 내부에서 수행하고 Attestation으로 검증

**작업 내용:**
- Gramine 매니페스트 작성 (judge enclave용)
- Enclave 내 채점 로직 구현 (입출력 비교, 시간 측정)
- DCAP Attestation 흐름 구현 (nonce 발급 -> Quote 생성 -> 검증)
- RA-TLS 채널 수립
- 결과 서명 생성 (ECDSA/HMAC)
- 서버 측 서명 검증 구현

**산출물:**
- Enclave 내부에서 채점이 동작하는 프로토타입
- Attestation 성공/실패 로그
- 서명된 verdict 생성 및 검증

**리스크:** Attestation 설정 복잡도 (가장 어려운 주차)
**대응:** Gramine RA-TLS 예제 코드 참조, 단계별 디버깅

### 4주차: 웹 UI + End-to-End 통합

**목표:** 브라우저에서 코드 제출 -> Enclave 채점 -> 결과 표시 전체 흐름 동작

**작업 내용:**
- 웹 프론트엔드 구현 (HTML/CSS/JS)
  - 문제 목록 페이지
  - 코드 제출 페이지 (코드 에디터 영역 + 제출 버튼)
  - 결과 확인 페이지 (verdict + attestation 상태)
- Frontend <-> Backend API 연동
- End-to-End 통합 테스트
- 에러 핸들링 (컴파일 에러, Attestation 실패 등)

**산출물:**
- 동작하는 웹 UI
- End-to-End 시연 영상/스크린샷
- 통합 테스트 결과

**리스크:** 프론트엔드-백엔드 연동 이슈
**대응:** 간단한 UI로 시작, 기능 우선 디자인 후순위

### 5주차: 보안 검증 + 벤치마크

**목표:** 공격 시나리오 시연 + 성능 측정 데이터 수집

**작업 내용:**
- 공격 시뮬레이션 스크립트 작성
  - 재생 공격 테스트
  - 결과 위변조 테스트
  - 테스트케이스 추출 시도
- 각 공격의 방어 성공 로그 수집
- 성능 벤치마크:
  - 네이티브 실행 vs Enclave 실행 시간 비교
  - Attestation 오버헤드 측정
  - 전체 채점 RTT(Round Trip Time) 측정
- 결과 데이터를 그래프로 시각화

**산출물:**
- 공격 시뮬레이션 결과 로그
- 성능 비교 그래프 (2-3개)
- 보안 검증 보고서

**리스크:** 공격 시뮬레이션 구현 난이도
**대응:** 간단한 Python/bash 스크립트로 구현

### 6주차: 논문 작성

**목표:** KCC 학부생 논문 대회 제출용 논문 완성

**작업 내용:**
- 논문 초안 작성 (구조는 14장 참조)
- 시스템 아키텍처 다이어그램 정리
- 실험 결과 그래프 삽입
- 관련 연구 조사 및 비교
- 교정 및 최종 검토

**산출물:**
- KCC 제출용 논문 (4-6 페이지)
- 발표 자료 (필요 시)

## 14. 논문 구조 (KCC용)

### 14.1 섹션 구성

| 섹션 | 내용 | 예상 분량 |
|------|------|----------|
| 1. 서론 | 동기 (백준 종료, 서버 부하), 연구 목표, 기여 요약 | 0.5p |
| 2. 배경 | Intel SGX, DCAP Attestation, RA-TLS, 온라인 저지 구조 | 0.5p |
| 3. 관련 연구 | 기존 온라인 저지(Judge0, DMOJ), TEE 활용 사례, ZK/MPC 비교 | 0.5p |
| 4. 시스템 설계 | 아키텍처, 데이터 흐름, Enclave 경계, Attestation 흐름 | 1.0p |
| 5. 보안 모델 | 위협 모델, 공격 시나리오 3가지, 방어 메커니즘 | 0.5p |
| 6. 구현 | 기술 스택, 주요 구현 세부사항, Gramine 매니페스트 | 0.5p |
| 7. 평가 | Attestation 시연, 공격 방어 결과, 성능 벤치마크 | 1.0p |
| 8. 한계 및 향후 연구 | 사이드 채널 한계, 소비자 TEE 커버리지, 확장 방향 | 0.3p |
| 9. 결론 | 요약, 기여, 의의 | 0.2p |
| 합계 | | 약 5p |

### 14.2 포함할 결과 및 그래프

1. **시스템 아키텍처 다이어그램** - 전체 구성도 (Figure 1)
2. **시퀀스 다이어그램** - 채점 흐름 (Figure 2)
3. **Attestation 성공/실패 스크린샷** - MRENCLAVE 검증 로그 (Figure 3)
4. **공격 방어 결과 표** - 재생 공격, 위변조, 추출 시도 결과 (Table 1)
5. **성능 비교 그래프** - 네이티브 vs Enclave 실행 시간 (Figure 4)
6. **Attestation 오버헤드 그래프** - Attestation 유무에 따른 RTT 비교 (Figure 5)

### 14.3 기여 포인트 (Novelty)

1. **최초의 TEE 기반 온라인 저지 아키텍처 제안**
   - 선행 연구에서 TEE + 온라인 저지를 결합한 사례 없음
   - 서버 부하 오프로딩 + 채점 무결성을 동시에 달성하는 새로운 접근

2. **실제 동작하는 프로토타입 구현 및 검증**
   - 설계만이 아닌 Azure DCsv3에서 실제 SGX 하드웨어로 구현
   - End-to-end Attestation + 채점 흐름 시연

3. **구체적인 보안 위협 분석 및 방어 시연**
   - 재생 공격, 결과 위변조, 테스트케이스 추출에 대한 실제 공격/방어 시연
   - 사이드 채널 한계를 정직하게 분석

4. **대안 기술(ZK/MPC/중복 계산)과의 비교 분석**
   - TEE가 실행 무결성 + 비밀성을 동시에 제공하는 유일한 실용적 접근임을 논증

## 15. 한계 및 향후 연구

### 15.1 현재 설계의 알려진 한계

**하드웨어 커버리지:**
- Intel SGX는 소비자 CPU에서 점차 deprecation 추세
- ARM TrustZone은 범용 코드 실행에 부적합
- 모든 사용자가 TEE 지원 디바이스를 보유하지 않음
- 현실적으로 하이브리드 모델(TEE 가능 시 클라이언트 채점, 불가 시 서버 채점)이 필요

**사이드 채널 공격:**
- 타이밍 공격, 출력 기반 역추론은 완전 차단 불가
- 이는 TEE 고유 한계가 아닌 온라인 저지 시스템의 근본적 한계
- 완화 조치(타이밍 패딩, 출력 제한)로 위험 감소 가능하나 완전 제거 불가

**EPC 메모리 제한:**
- SGX Enclave의 EPC 메모리는 제한적 (수 GB)
- 대용량 테스트케이스나 메모리 집약적 문제에서 제약
- 스트리밍 I/O나 테스트케이스 분할로 완화 가능

**컴파일러 신뢰 문제:**
- 컴파일은 Enclave 밖에서 수행 (컴파일러가 너무 큼)
- 악의적 호스트가 컴파일 결과를 변조할 가능성
- 완화: 코드 해시를 Attestation에 바인딩하여 추적 가능

**단일 TEE 벤더 의존:**
- 현재 설계는 Intel SGX에 특화
- 다른 TEE(ARM TrustZone, AMD SEV-SNP)로의 이식성 제한

### 15.2 향후 연구 방향

1. **하이브리드 채점 아키텍처**
   - TEE 지원 디바이스: 클라이언트 채점
   - TEE 미지원: 서버 채점 (기존 방식)
   - 랜덤 재검증: TEE 결과 중 일부를 서버에서도 실행하여 신뢰도 보강

2. **다중 TEE 플랫폼 지원**
   - ARM TrustZone (모바일), AMD SEV-SNP (서버)
   - Enarx/WASM 기반 크로스 플랫폼 Enclave 런타임

3. **다중 언어 지원**
   - Python, Java, Rust 등 추가 언어
   - 언어별 런타임을 Enclave에 포함하는 방안

4. **분산 채점 네트워크**
   - 여러 클라이언트가 채점을 분담하는 P2P 구조
   - 중복 채점으로 결과 신뢰도 향상

5. **ZK-SNARK 기반 결과 증명과의 결합**
   - TEE 채점 결과를 ZK proof로 변환하여 검증 가능성 확보
   - TEE 하드웨어 없이도 결과를 검증할 수 있는 경로

6. **Enclave 내 컴파일**
   - 경량 컴파일러(TCC 등)를 Enclave에 포함
   - 컴파일 단계까지 신뢰 경계 안으로 이동

---

문서 버전: v1.0
작성일: 2026-04-16
프로젝트: TEE-Judge
대상 학회: KCC 학부생 논문 대회




