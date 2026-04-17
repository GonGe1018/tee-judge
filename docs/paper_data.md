# TEE-Judge 논문용 실험 결과 정리

## 1. 실험 환경

| 항목 | 값 |
|------|-----|
| CPU | Intel Xeon Platinum 8370C @ 2.80GHz |
| vCPU | 2 |
| RAM | 16GB |
| EPC Size | 8GB (0x200000000) |
| VM Type | Azure Standard_DC2s_v3 |
| Region | Japan West |
| OS | Ubuntu 20.04.6 LTS |
| Kernel | 5.15.0-1089-azure |
| SGX | SGX1 + SGX2, FLC, KSS, AEX-Notify |
| Gramine | 1.8 |
| Python | 3.11.9 |
| GCC | 9.4.0 |
| Attestation | DCAP (Azure THIM) |

## 2. 성능 벤치마크

### 실험 조건
- 문제: A+B (Problem 1000)
- 테스트케이스: 30개
- 반복 횟수: 10회
- 측정 항목: 전체 채점 시간 (컴파일 + 실행 + 검증)

### 결과

| 항목 | Mean | Median | Std | Min | Max |
|------|------|--------|-----|-----|-----|
| Native (no SGX) | 37.5ms | 37.3ms | 0.6ms | 37.0ms | 38.9ms |
| SGX Total | 3753.0ms | 3758.5ms | 13.5ms | 3729.3ms | 3767.3ms |
| SGX Phase 1 (Host) | 39.1ms | 39.2ms | 0.5ms | 37.7ms | 39.5ms |
| SGX Phase 2 (Enclave) | 3713.9ms | 3719.3ms | 13.7ms | 3690.1ms | 3729.6ms |

### 분석
- SGX 오버헤드: 3715.5ms (9908.1%)
- Phase 1 (컴파일+실행)은 네이티브와 동일 (~39ms)
- Phase 2 오버헤드의 대부분은 Gramine + Python 초기화 (enclave cold start)
- 실제 검증+서명 로직은 밀리초 단위
- 실서비스에서는 enclave를 상주시켜 cold start를 제거 가능 (warm start)

## 3. Attestation 결과

| 항목 | 값 |
|------|-----|
| Attestation Type | DCAP |
| Quote Version | 3 (SGX Quote v3) |
| Quote Size | 4,734 bytes |
| MRENCLAVE | 8815f3c000f3e3b308267a5f3b0f73331bbf005691d978df8d02a07ad0250b3d |
| MRSIGNER | f03d09b09556716c13f5d0e785f2bcccdc93572132adb0b70d21107d3478a5f7 |
| 인증서 체인 | Intel SGX Root CA → Platform CA → PCK Certificate |
| User Report Data | verdict + nonce의 SHA-256 해시 (64 bytes) |

### MRENCLAVE 일관성 검증
- 3회 연속 채점에서 동일한 MRENCLAVE 확인
- 동일한 enclave 코드가 모든 채점에 사용됨을 증명

## 4. 보안 검증 결과

### Attack 1: 재생 공격 (Replay Attack)
- 공격: 이전 AC 결과의 Quote를 새 제출에 재사용
- 결과: **방어 성공**
- 방어 메커니즘:
  - 세션별 fresh nonce 발급
  - 이전 nonce != 현재 nonce → 불일치 탐지
  - 서명도 submission_id + nonce에 바인딩 → 재사용 불가

### Attack 2: 결과 위변조 (Result Tampering)
- 공격: Enclave 외부에서 WA → AC로 verdict 변조
- 결과: **방어 성공**
- 방어 메커니즘:
  - Enclave 내부에서 HMAC 서명 생성
  - 서명 대상: submission_id:problem_id:verdict:test_passed:test_total:nonce
  - verdict 변조 시 서명 불일치 → 탐지

### Attack 3: 테스트케이스 추출 (Test Case Extraction)
- 공격: 호스트 OS에서 Enclave 메모리 읽기 시도
- 결과: **방어 성공**
- 방어 메커니즘:
  - SGX 하드웨어가 EPC 메모리를 AES-128 암호화
  - 호스트 OS, 하이퍼바이저에서 접근 불가
  - 복호화 키는 CPU 내부에만 존재

### 보안 검증 요약

| 공격 시나리오 | 결과 | 방어 메커니즘 |
|-------------|------|-------------|
| 재생 공격 | 방어 성공 | Fresh nonce + 서명 바인딩 |
| 결과 위변조 | 방어 성공 | HMAC 서명 검증 |
| 테스트케이스 추출 | 방어 성공 | SGX 메모리 암호화 |
| MRENCLAVE 일관성 | 검증 완료 | 동일 enclave 코드 증명 |

## 5. 기능 검증 결과

### E2E 채점 테스트

| 테스트 | 코드 | 기대 | 결과 | 테스트케이스 |
|--------|------|------|------|------------|
| 정답 (A+B) | printf("%d", a+b) | AC | AC | 30/30 |
| 오답 (A-B) | printf("%d", a-b) | WA | WA | 3/30 |
| 컴파일 에러 | invalid code | CE | CE | 0/30 |

### 시스템 구성

| 컴포넌트 | 기술 | 역할 |
|---------|------|------|
| Web Server | FastAPI + Uvicorn | 문제 관리, 제출 접수, 결과 표시 |
| Web Frontend | HTML/CSS/JS | 문제 보기, 코드 제출, 결과 확인 |
| Judge Client (Host) | Python 3.11 | 코드 컴파일 + 실행 (Phase 1) |
| Judge Client (Enclave) | Python 3.11 + Gramine SGX | 결과 검증 + 서명 + Attestation (Phase 2) |
| Database | SQLite | 문제, 테스트케이스, 제출, 결과 저장 |

### 문제 및 테스트케이스

| 문제 ID | 제목 | 테스트케이스 수 |
|---------|------|---------------|
| 1000 | A+B | 30 |
| 1001 | A-B | 30 |
| 1002 | A*B | 30 |
| 1003 | 최댓값 | 30 |
| 1004 | 합계 | 30 |
| 합계 | | 150 |

## 6. 논문에 포함할 Figure/Table 목록

1. **Figure 1**: 시스템 아키텍처 다이어그램 (서버 + 웹 + Judge Client)
2. **Figure 2**: 채점 흐름 시퀀스 다이어그램 (8단계)
3. **Figure 3**: 2-phase 채점 구조 (Host Phase 1 + Enclave Phase 2)
4. **Figure 4**: 성능 비교 막대 그래프 (Native vs SGX)
5. **Figure 5**: SGX Phase 분해 그래프 (Phase 1 vs Phase 2 비율)
6. **Table 1**: 실험 환경 사양
7. **Table 2**: 성능 벤치마크 결과 (Mean, Median, Std, Min, Max)
8. **Table 3**: 보안 검증 결과 (공격 시나리오 + 방어 결과)
9. **Table 4**: Attestation Quote 구조 (필드별 설명)
10. **Table 5**: 기능 검증 결과 (AC/WA/CE 테스트)
