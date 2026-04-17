const API = '';
let currentProblemId = null;
let authToken = localStorage.getItem('tee-judge-token');
let authUser = localStorage.getItem('tee-judge-user');
let isRegisterMode = false;
let browserWs = null;
let pendingSubmissionId = null;

// --- Auth ---

function getAuthHeaders() {
    return authToken
        ? { 'Authorization': `Bearer ${authToken}`, 'Content-Type': 'application/json' }
        : { 'Content-Type': 'application/json' };
}

function updateAuthUI() {
    const info = document.getElementById('user-info');
    const logoutBtn = document.getElementById('logout-btn');

    if (authToken && authUser) {
        info.textContent = authUser;
        info.style.display = '';
        logoutBtn.style.display = '';
    } else {
        info.style.display = 'none';
        logoutBtn.style.display = 'none';
    }
}

function showAuth() {
    document.getElementById('auth-view').style.display = '';
    document.getElementById('problem-list-view').style.display = 'none';
    document.getElementById('problem-view').style.display = 'none';
    document.getElementById('result-view').style.display = 'none';
    disconnectBrowserWs();
}

function toggleAuthMode() {
    isRegisterMode = !isRegisterMode;
    document.getElementById('auth-title').textContent = isRegisterMode ? '회원가입' : '로그인';
    document.getElementById('auth-submit-btn').textContent = isRegisterMode ? '회원가입' : '로그인';
    document.getElementById('auth-toggle-text').textContent = isRegisterMode ? '이미 계정이 있으신가요?' : '계정이 없으신가요?';
    document.getElementById('auth-toggle-link').textContent = isRegisterMode ? '로그인' : '회원가입';
    document.getElementById('auth-error').textContent = '';
}

function logout() {
    authToken = null;
    authUser = null;
    localStorage.removeItem('tee-judge-token');
    localStorage.removeItem('tee-judge-user');
    updateAuthUI();
    disconnectBrowserWs();
    showAuth();
}

document.getElementById('auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('auth-username').value.trim();
    const password = document.getElementById('auth-password').value;
    const errorEl = document.getElementById('auth-error');
    errorEl.textContent = '';

    const endpoint = isRegisterMode ? '/api/auth/register' : '/api/auth/login';

    try {
        const res = await fetch(`${API}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        const data = await res.json();

        if (!res.ok) {
            errorEl.textContent = data.detail || '인증 실패';
            return;
        }

        authToken = data.token;
        authUser = data.username;
        localStorage.setItem('tee-judge-token', authToken);
        localStorage.setItem('tee-judge-user', authUser);
        updateAuthUI();
        connectBrowserWs();
        showProblemList();
    } catch (err) {
        errorEl.textContent = '서버 연결 실패';
    }
});

// --- Browser WebSocket ---

function connectBrowserWs() {
    if (!authToken) return;
    if (browserWs && browserWs.readyState === WebSocket.OPEN) return;

    const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProto}//${location.host}/ws/browser`;

    browserWs = new WebSocket(wsUrl);

    browserWs.onopen = () => {
        browserWs.send(JSON.stringify({ token: `Bearer ${authToken}` }));
    };

    browserWs.onmessage = (event) => {
        const msg = JSON.parse(event.data);

        if (msg.type === 'ping') {
            browserWs.send(JSON.stringify({ type: 'pong' }));
            return;
        }

        if (msg.type === 'result' && msg.submission_id === pendingSubmissionId) {
            // Result arrived via WebSocket — fetch full result
            fetchAndRenderResult(msg.submission_id);
        }
    };

    browserWs.onclose = () => {
        // Reconnect after 3 seconds
        setTimeout(() => {
            if (authToken) connectBrowserWs();
        }, 3000);
    };

    browserWs.onerror = () => {
        browserWs.close();
    };
}

function disconnectBrowserWs() {
    if (browserWs) {
        browserWs.close();
        browserWs = null;
    }
}

// --- Navigation ---

function showProblemList() {
    document.getElementById('auth-view').style.display = 'none';
    document.getElementById('problem-list-view').style.display = '';
    document.getElementById('problem-view').style.display = 'none';
    document.getElementById('result-view').style.display = 'none';
    pendingSubmissionId = null;
    loadProblems();
}

function showProblem(id) {
    document.getElementById('auth-view').style.display = 'none';
    document.getElementById('problem-list-view').style.display = 'none';
    document.getElementById('problem-view').style.display = '';
    document.getElementById('result-view').style.display = 'none';
    currentProblemId = id;
    loadProblemDetail(id);
}

function showResult(submissionId) {
    document.getElementById('auth-view').style.display = 'none';
    document.getElementById('problem-list-view').style.display = 'none';
    document.getElementById('problem-view').style.display = 'none';
    document.getElementById('result-view').style.display = '';
    pendingSubmissionId = submissionId;
    showWaiting();
}

// --- Utility: escape HTML to prevent XSS ---

function esc(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// --- Problem List ---

async function loadProblems() {
    const res = await fetch(`${API}/api/problems`);
    const problems = await res.json();
    const tbody = document.getElementById('problem-tbody');
    tbody.innerHTML = '';
    for (const p of problems) {
        const tr = document.createElement('tr');
        tr.onclick = () => showProblem(p.id);
        tr.innerHTML = `
            <td>${esc(String(p.id))}</td>
            <td>${esc(p.title)}</td>
            <td>${esc(String(p.time_limit_ms))}ms</td>
            <td>${Math.floor(p.memory_limit_kb / 1024)}MB</td>
        `;
        tbody.appendChild(tr);
    }
}

// --- Problem Detail ---

async function loadProblemDetail(id) {
    const res = await fetch(`${API}/api/problems/${id}`);
    const p = await res.json();
    document.getElementById('problem-detail').innerHTML = `
        <div class="problem-section">
            <h2>${esc(String(p.id))}번: ${esc(p.title)}</h2>
            <div class="problem-meta">시간 제한: ${esc(String(p.time_limit_ms))}ms | 메모리 제한: ${Math.floor(p.memory_limit_kb / 1024)}MB</div>
            <p>${esc(p.description)}</p>
            <h3>입력</h3>
            <p>${esc(p.input_desc || '')}</p>
            <h3>출력</h3>
            <p>${esc(p.output_desc || '')}</p>
            <h3>예제 입력</h3>
            <div class="sample-box">${esc(p.sample_input || '')}</div>
            <h3>예제 출력</h3>
            <div class="sample-box">${esc(p.sample_output || '')}</div>
        </div>
    `;
}

// --- Submit ---

document.getElementById('submit-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    if (!authToken) {
        alert('로그인이 필요합니다.');
        showAuth();
        return;
    }

    const code = document.getElementById('code').value.trim();
    const language = document.getElementById('language').value;

    if (!code) {
        alert('코드를 입력하세요.');
        return;
    }

    const res = await fetch(`${API}/api/submit`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
            problem_id: currentProblemId,
            language: language,
            code: code,
        }),
    });

    const data = await res.json();
    if (res.ok) {
        showResult(data.submission_id);
    } else if (res.status === 401) {
        alert('로그인이 만료되었습니다. 다시 로그인해주세요.');
        logout();
    } else {
        alert(data.detail || '제출 실패');
    }
});

// --- Result Display ---

function showWaiting() {
    const detail = document.getElementById('result-detail');
    detail.innerHTML = '<div class="verdict verdict-JUDGING">채점 중... Judge Client를 실행해주세요.</div>';

    // Fallback polling in case WebSocket misses the notification
    startFallbackPolling();
}

let fallbackTimer = null;

function startFallbackPolling() {
    if (fallbackTimer) clearInterval(fallbackTimer);
    fallbackTimer = setInterval(async () => {
        if (!pendingSubmissionId) {
            clearInterval(fallbackTimer);
            return;
        }
        try {
            const res = await fetch(`${API}/api/status/${pendingSubmissionId}`, { headers: getAuthHeaders() });
            if (res.ok) {
                const status = await res.json();
                if (status.status === 'DONE') {
                    clearInterval(fallbackTimer);
                    fetchAndRenderResult(pendingSubmissionId);
                }
            }
        } catch (e) {}
    }, 5000); // 5 second fallback, WS should be faster
}

async function fetchAndRenderResult(submissionId) {
    if (fallbackTimer) clearInterval(fallbackTimer);
    pendingSubmissionId = null;

    const res = await fetch(`${API}/api/result/${submissionId}`, { headers: getAuthHeaders() });
    if (res.ok) {
        const result = await res.json();
        renderResult(result);
    }
}

function renderResult(r) {
    const verdictClass = `verdict-${esc(r.verdict)}`;
    const verdictText = {
        'AC': '맞았습니다!!',
        'WA': '틀렸습니다',
        'TLE': '시간 초과',
        'RE': '런타임 에러',
        'CE': '컴파일 에러',
    }[r.verdict] || esc(r.verdict);

    const attestBadge = r.attestation_verified
        ? '<span class="attestation-badge attestation-verified">Attestation 검증됨</span>'
        : '<span class="attestation-badge attestation-unverified">Attestation 미검증</span>';

    document.getElementById('result-detail').innerHTML = `
        <div class="verdict ${verdictClass}">${verdictText}</div>
        <div class="result-info">
            <table>
                <tr><td>제출 번호</td><td>${esc(String(r.submission_id))}</td></tr>
                <tr><td>문제</td><td>${esc(String(r.problem_id))}</td></tr>
                <tr><td>결과</td><td>${esc(r.verdict)}</td></tr>
                <tr><td>실행 시간</td><td>${r.time_ms !== null ? esc(String(r.time_ms)) + 'ms' : '-'}</td></tr>
                <tr><td>메모리</td><td>${r.memory_kb !== null ? esc(String(r.memory_kb)) + 'KB' : '-'}</td></tr>
                <tr><td>테스트</td><td>${r.test_passed !== null ? esc(String(r.test_passed)) + '/' + esc(String(r.test_total)) : '-'}</td></tr>
                <tr><td>Attestation</td><td>${attestBadge}</td></tr>
                <tr><td>Nonce</td><td><code>${esc(r.nonce || '-')}</code></td></tr>
                <tr><td>채점 시각</td><td>${esc(r.judged_at || '-')}</td></tr>
            </table>
        </div>
    `;
}

// --- Init ---

updateAuthUI();
if (authToken) {
    connectBrowserWs();
    showProblemList();
} else {
    showAuth();
}
