// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
function appUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

// 요청마다 어느 점검의 요청인지(alephEvidence: 사례·요청 키)를 붙여, 심판의 실행기가 응답을 따로 관측할 수 있게 합니다.
// 요청을 보내지 못하면(네트워크 오류) 점검 전체를 멈추지 않고, 그 점검만 아래 finalize에서 「미실행」으로 바꿉니다.
const FAILED = '요청 실패';
let currentCase = 'setup';
let requestSeq = 0;
const caseOf = (attackId) => { currentCase = attackId; };
// 12단계: 보낸 요청마다 점검 이름·요청(메서드·경로)·응답 상태·요청 ID(배포가 돌려준 x-vercel-id)·확인 시각을 남깁니다.
// 요청 본문·토큰·쿠키·쿼리 값은 남기지 않습니다. npm run ops:table 이 이 기록으로 한 표를 만듭니다.
const requestLog = [];
export function getRequestLog() { return requestLog.map((r) => ({ ...r })); }
async function net(url, options = {}) {
  requestSeq += 1;
  const requestKey = `${currentCase}#${requestSeq}`;
  const target = new URL(url);
  const entry = { caseId: currentCase, requestKey, method: options.method ?? 'GET', host: target.host, path: target.pathname,
    at: new Date().toISOString(), status: FAILED, requestId: null };
  requestLog.push(entry);
  try {
    const response = await fetch(url, { ...options, alephEvidence: { caseId: currentCase, requestKey } });
    entry.status = response.status;
    entry.requestId = response.headers?.get?.('x-vercel-id') ?? response.headers?.get?.('x-request-id') ?? null;
    return response;
  } catch {
    return { status: FAILED, ok: false, json: async () => { throw new Error('no_response'); }, text: async () => '', headers: { getSetCookie: () => [] } };
  }
}
// 보내지 못한 요청이 섞인 점검은 결과를 추측하지 않고 미실행으로 남깁니다.
const STAGE_OF = {
  anonymous_api_read: 3, forged_token_read: 3, cross_user_note_read: 4, anon_original_api_read: 5, browser_key_exposure: 5,
  registered_device_read: 6, unregistered_device_read: 6, anomalous_context_read: 7, real_step_up_block: 7,
  zone_decider_rules: 8, anonymous_notice_read: 8, zone_api_cross_owner: 8,
  detect_normal_device: 9, detect_doppelganger_burst: 9, live_revocation: 9,
  restore_anonymous: 10, policy_snapshot_verified: 10, restore_b_deleted_note: 10, restore_b_tampered_note: 10, post_restore_retest: 10,
  device_approval_gate: 11, ops_room_summary: 12,
};
// result: 결과를 관측하지 못했으면 not_run, 기대와 다른 관측이 있으면 breached, 그 밖은 blocked(기대대로 막거나 허용함).
const BREACH = /거부되지 않음|노출됨|발견됨|(?:ID|사본) \S+ 다름|바뀜|approved=true|뚫림|캐시 대상 확인 필요|검증 실패로 중단/u;
function finalize(list) {
  return list.map((a) => {
    const observed = String(a.observed).includes(FAILED) ? '미실행: 배포에 요청을 보내지 못해(네트워크 오류) 결과 없음' : a.observed;
    const result = observed.startsWith('미실행') ? 'not_run' : BREACH.test(observed) ? 'breached' : 'blocked';
    return { attackId: a.attackId, stage: STAGE_OF[a.attackId] ?? 0, expected: a.expected, observed, result };
  });
}

async function anonymousGet(app, path, headers = {}, method = 'GET') {
  const response = await net(new URL(path, app), {
    method, headers, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000),
  });
  let notes = null;
  let error = null;
  try {
    const data = await response.json();
    notes = Array.isArray(data) ? data.length : Array.isArray(data?.notes) ? data.notes.length : null;
    error = typeof data?.error === 'string' ? data.error.slice(0, 40) : null;
  } catch {
    // A non-JSON response is recorded as "no notes", not as a success.
  }
  if (!response.ok) notes = null;
  return { status: response.status, notes, error };
}

// 브라우저에 이미 공개된 값(공개용 URL·publishable key)만 씁니다. 서버 전용 키는 쓰지 않습니다.
const SUPABASE_URL = 'https://yojoqbnplvwsmqaohjfr.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_nnOsC1LS3LGw_mFyzczbew_XrF2jAoQ';

async function anonDataApi(url = `${SUPABASE_URL}/rest/v1/notes?select=id&limit=5`) {
  const response = await net(url, {
    headers: { apikey: SUPABASE_PUBLISHABLE_KEY },
    redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000),
  });
  let rows = null;
  let code = null;
  try {
    const data = await response.json();
    if (Array.isArray(data)) rows = data.length;
    else code = typeof data?.code === 'string' ? data.code.slice(0, 20) : null;
  } catch { /* JSON이 아니면 행 없음으로 기록 */ }
  return { status: response.status, rows, code };
}

async function deviceChecks() {
  const [{ decide }, { fixtureRequests }] = await Promise.all([
    import('./decider.mjs'),
    import('../scripts/fixture-7.mjs'),
  ]);
  const { normal } = fixtureRequests();
  const unregistered = {
    ...normal,
    requestId: crypto.randomUUID(),
    deviceRegistered: false,
  };
  const describe = (result) => `판정기 응답 ${result.decision} · ${result.reasonCode} · ${result.ruleIds.join(',')}`;
  const registeredResult = await decide(normal);
  const unregisteredResult = await decide(unregistered);
  return [
    { attackId: 'registered_device_read',
      expected: '등록 기기의 내 자료실 읽기(GET /notes/:id)는 allow',
      observed: describe(registeredResult) },
    { attackId: 'unregistered_device_read',
      expected: '미등록 기기의 같은 요청은 deny · device_not_registered',
      observed: `${describe(unregisteredResult)} (미등록 기기 실제 공격은 심판이 확인)` },
  ];
}

// 7단계: 판정기에 정상·복합 이상·재로그인 뒤·위조 출처 가상 사건을 직접 넣어 본 결과만 적습니다.
// 실제 재로그인 확인(제공 엔진이 새 로그인 시각을 검증하는 흐름)은 이 저장소에서 보낼 수 없어 미실행으로 남깁니다.
async function stepUpChecks({ compact = false } = {}) {
  const { decide } = await import('./decider.mjs');
  const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
  const { normal, suspicious } = fixtureRequests();
  const fresh = (r) => ({ ...r, requestId: crypto.randomUUID() });
  const said = (o) => `${o.decision} · ${o.reasonCode} · ${o.ruleIds.join(',')}`;
  const ok = await decide(fresh(normal));
  const odd = await decide(fresh(suspicious));
  const again = await decide(fresh({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }));
  const forged = await decide(fresh({ ...suspicious, signals: { ...suspicious.signals, source: 'client_header' } }));
  if (compact) {
    // 9단계부터는 제출 점검 20개 한도 때문에 7단계 가상 사건 네 건을 한 줄로 합쳐 적습니다(결과는 그대로 모두 기록).
    return [
      { attackId: 'anomalous_context_read',
        expected: '정상 사건 allow · 새벽+처음 보는 네트워크+5분 내 대량 읽기는 step_up · 재로그인(60초 전) 뒤 allow · 클라이언트 헤더 출처는 복합 규칙 미적용',
        observed: `판정기 응답 정상 ${said(ok)} / 복합 ${said(odd)} / 재로그인 뒤 ${said(again)} / client_header 출처 ${said(forged)}` },
      { attackId: 'real_step_up_block',
        expected: '제공 엔진이 새 로그인 시각을 검증할 때 재로그인 전 자료 차단·새 요청 허용 실측',
        observed: '미실행: 이 저장소에서는 엔진의 재로그인 검증 흐름을 보낼 수 없음. 판정기 응답만 가상 사건으로 확인' },
    ];
  }
  return [
    { attackId: 'normal_context_read',
      expected: '평소 시각·평소 네트워크·대량 읽기 없음 가상 사건은 allow',
      observed: `판정기 응답 ${said(ok)}` },
    { attackId: 'anomalous_context_read',
      expected: '새벽 시각 + 처음 보는 네트워크 + 5분 내 대량 읽기 가상 사건은 step_up · step_up_required',
      observed: `판정기 응답 ${said(odd)}` },
    { attackId: 'stepped_up_context_read',
      expected: '같은 복합 사건이라도 엔진이 확인한 재로그인(60초 전) 뒤 새 요청은 allow',
      observed: `판정기 응답 ${said(again)}` },
    { attackId: 'forged_client_signal',
      expected: '출처가 클라이언트 헤더인 접속 정보는 신뢰하지 않음(사건 근거로 승격하지 않음)',
      observed: `출처 client_header 요청의 판정기 응답 ${said(forged)} (복합 사건 규칙 미적용)` },
    { attackId: 'real_step_up_block',
      expected: '제공 엔진이 새 로그인 시각을 검증할 때 재로그인 전 자료 차단·새 요청 허용 실측',
      observed: '미실행: 이 저장소에서는 엔진의 재로그인 검증 흐름을 보낼 수 없음. 판정기 응답만 가상 사건으로 확인' },
  ];
}

// 8단계: 판정기 구역 규칙(가상 요청)과, 실제 배포의 공지 구역 비로그인 요청 결과만 적습니다.
// 로그인 토큰이 필요한 A/B·강사 요청은 이 스크립트로 보내지 않아 미실행으로 남깁니다.
async function zoneChecks(app, { compact = false, crossObserved = null } = {}) {
  const { decide } = await import('./decider.mjs');
  const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
  const { normal } = fixtureRequests();
  const ask = (patch) => decide({ ...normal, requestId: crypto.randomUUID(), ...patch });
  const said = (o) => `${o.decision} · ${o.reasonCode} · ${o.ruleIds.join(',')}`;
  const own = await ask({});
  const bulkList = await ask({ route: 'GET /notes', path: '/notes' });
  const noticeWrite = await ask({ method: 'PUT', route: 'PUT /notices/:id', path: '/notices/demo' });
  const noticeRead = await ask({ route: 'GET /notices/:id', path: '/notices/demo' });
  const exportPath = await ask({ path: '/notes/export' });
  const unknown = await ask({ route: 'GET /admin', path: '/admin' });
  const restoreOk = await ask({ method: 'POST', route: 'POST /restore/notes/:id', path: '/restore/notes/demo' });
  const restoreBad = await ask({ method: 'POST', route: 'POST /restore/notes/:id', path: '/restore/notes/demo', policyRevision: 2 });
  caseOf('anonymous_notice_read');
  const notices = await anonymousGet(app, '/api/notices');
  const noticeLine = { attackId: 'anonymous_notice_read',
    expected: '로그인 없는 /api/notices 요청은 401·403 JSON 오류로 거부',
    observed: `비로그인 /api/notices 요청 결과 HTTP ${notices.status}${notices.error ? ` ${notices.error}` : ''}${notices.notes === null ? ', 자료 없음' : `, ${notices.notes}건`}` };
  const crossLine = { attackId: 'zone_api_cross_owner',
    expected: '메뉴를 우회한 직접 API 요청: B의 A 메모 GET·PUT은 404, 학생의 공지 GET·PUT은 403 INSTRUCTOR_REQUIRED',
    observed: crossObserved ?? '미실행: 로그인 토큰이 필요해 이 스크립트로는 보내지 않음. 자료 API 소유자·강사 대조는 가짜 DB 로컬 시험으로 확인' };
  const short = (o) => `${o.decision}(${o.reasonCode})`; // 한 줄 300자 한도에 맞춰 결정과 이유 코드만
  if (compact) {
    // 10단계부터는 제출 점검 20개 한도 때문에 판정기 구역 가상 요청 여섯 건을 한 줄로 합쳐 적습니다(결과는 그대로 모두 기록).
    return [
      { attackId: 'zone_decider_rules',
        expected: '자기 메모 한 건 allow · 복구는 검증 정책 버전(1)만 allow, 바뀐 버전 deny(policy_unverified) · 전체 목록·공지·export·경로표 밖 deny',
        observed: `판정기 응답 자기 메모 ${short(own)} / 복구 버전1 ${short(restoreOk)} / 복구 버전2 ${short(restoreBad)} / 전체 목록 ${short(bulkList)} / 공지 수정 ${short(noticeWrite)} / 공지 읽기 ${short(noticeRead)} / export ${short(exportPath)} / GET /admin ${short(unknown)}` },
      noticeLine,
      crossLine,
    ];
  }
  return [
    { attackId: 'zone_own_note_read',
      expected: '등록 기기·로그인 사용자의 자기 메모 구역(GET /notes/:id)은 allow',
      observed: `판정기 응답 ${said(own)}` },
    { attackId: 'zone_bulk_note_list',
      expected: '메모 전체 목록(GET /notes)처럼 여러 사람의 자료를 한꺼번에 여는 경로는 deny · zone_notes_no_bulk',
      observed: `판정기 응답 ${said(bulkList)}` },
    { attackId: 'zone_student_notice_write',
      expected: '일반 학생의 강사 공지 수정(PUT /notices/:id)은 deny · instructor_required',
      observed: `판정기 응답 ${said(noticeWrite)}` },
    { attackId: 'zone_student_notice_read',
      expected: '일반 학생의 강사 공지 구역 읽기(GET /notices/:id)도 deny · instructor_required',
      observed: `판정기 응답 ${said(noticeRead)}` },
    { attackId: 'zone_function_path',
      expected: ':id 자리에 export 같은 기능 경로를 넣은 요청은 deny · route_not_allowed',
      observed: `판정기 응답 ${said(exportPath)}` },
    { attackId: 'zone_unknown_route',
      expected: '경로표에 없는 경로(GET /admin)는 deny · route_not_allowed',
      observed: `판정기 응답 ${said(unknown)}` },
    noticeLine,
    crossLine,
  ];
}

// 12단계: 판정기·탐지 규칙의 가상 입력 결과를 배포의 GET /api/checks?case=… 응답으로 받아 적습니다(실행기가 같은 응답을 관측).
// 응답을 받지 못하면 결과를 짐작하지 않고 미실행으로 남깁니다. 실제 엔진의 기기 검증·재로그인·회수 집행은 미실행입니다.
async function httpRuleChecks(app, { crossObserved = null } = {}) {
  const get = async (caseId, name) => {
    caseOf(caseId);
    const r = await authed(app, 'GET', `/api/checks?case=${name}`, null);
    return r.status === 200 && r.data?.synthetic === true ? r.data.results : null;
  };
  const d = await get('registered_device_read', 'decider');
  const t = await get('detect_normal_device', 'detect');
  const said = (o) => (o ? `${o.decision} · ${o.reasonCode} · ${o.ruleIds.join(',')}` : FAILED);
  const short = (o) => (o ? `${o.decision}(${o.reasonCode})` : FAILED);
  const act = (o) => (o ? (o.action === 'observe' ? 'observe' : `${o.action} · ${o.reasonCode} · 대상 ${o.subject}${o.deviceId ? `/${o.deviceId}` : ''}`) : FAILED);
  caseOf('anonymous_notice_read');
  const notices = await anonymousGet(app, '/api/notices');
  const via = '서버 /api/checks 가상 판정';
  return {
    device: [
      { attackId: 'registered_device_read', expected: '등록 기기의 내 자료실 읽기(GET /notes/:id)는 allow',
        observed: `${via} ${said(d?.registered)}` },
      { attackId: 'unregistered_device_read', expected: '미등록 기기의 같은 요청은 deny · device_not_registered. 실제 엔진의 기기 검증은 별도',
        observed: `${via} ${said(d?.unregistered)} / 실제 엔진 기기 검증: 미실행` },
    ],
    stepUp: [
      { attackId: 'anomalous_context_read',
        expected: '정상 allow · 새벽+처음 보는 네트워크+대량 읽기 step_up · 재로그인 뒤 allow · 클라이언트 헤더 출처 미적용. 엔진의 실제 재로그인 흐름은 별도',
        observed: `${via} 정상 ${short(d?.normalContext)} / 복합 ${short(d?.compound)} / 재로그인 뒤 ${short(d?.afterStepUp)} / client_header ${short(d?.clientHeader)} / 실제 재로그인 흐름: 미실행(엔진 경로 없음)` },
    ],
    zone: [
      { attackId: 'zone_decider_rules',
        expected: '자기 메모 한 건 allow · 복구는 검증 정책 버전(1)만 allow, 바뀐 버전 deny(policy_unverified) · 전체 목록·공지·export·경로표 밖 deny',
        observed: `${via} 자기 메모 ${short(d?.ownNote)} / 복구 버전1 ${short(d?.restoreV1)} / 복구 버전2 ${short(d?.restoreV2)} / 전체 목록 ${short(d?.bulkList)} / 공지 수정 ${short(d?.noticeWrite)} / 공지 읽기 ${short(d?.noticeRead)} / export ${short(d?.exportPath)} / GET /admin ${short(d?.unknownRoute)}` },
      { attackId: 'anonymous_notice_read', expected: '로그인 없는 /api/notices 요청은 401·403 JSON 오류로 거부',
        observed: `비로그인 /api/notices 요청 결과 HTTP ${notices.status}${notices.error ? ` ${notices.error}` : ''}${notices.notes === null ? ', 자료 없음' : `, ${notices.notes}건`}` },
      { attackId: 'zone_api_cross_owner',
        expected: '메뉴를 우회한 직접 API 요청: B의 A 메모 GET·PUT은 404, 학생의 공지 GET·PUT은 403',
        observed: crossObserved ?? '미실행: B·A 계정 비밀값이 없어 로그인 요청을 보내지 않음' },
    ],
    detect: [
      { attackId: 'detect_normal_device',
        expected: '평소 네트워크의 정상 기기 다량 조회, 지역만 다른 조회, 처음 보는 네트워크의 적은 조회(20건)는 모두 observe',
        observed: `서버 /api/checks 가상 사건 탐지 정상 기기 200건 ${act(t?.normal200)} / 지역만 다름 200건 ${act(t?.regionOnly200)} / 처음 보는 네트워크 20건 ${act(t?.unusual20)}` },
      { attackId: 'detect_doppelganger_burst',
        expected: '다른 기기가 10분 안에 120건 넘게 조회하면 그 기기만 propose_revocation · burst_read. 엔진의 실제 회수 집행은 별도',
        observed: `서버 /api/checks 가상 사건 정상 기기 50건 + 다른 기기 150건 탐지 ${act(t?.doppelganger)} / 실제 회수 집행: 미실행(엔진 경로 없음)` },
    ],
  };
}

// 12단계: 탈환 작전실 서버 요약(GET /api/ops)을 받아, 메모 본문 없이 요약 항목이 모두 있는지만 적습니다.
async function opsRoomCheck(app) {
  caseOf('ops_room_summary');
  const r = await authed(app, 'GET', '/api/ops', null);
  const o = r.data;
  const text = JSON.stringify(o ?? {});
  const leak = /"(title|body|content|owner_id|email|accessToken)"/u.test(text);
  const part = (k) => (o?.[k] ? `${k} ${o[k].source}` : `${k} 없음`);
  return [{ attackId: 'ops_room_summary',
    expected: '작전실 서버 요약에 판정기 규칙·탐지 사건·회수 상태·복구 버전이 출처(서버 기록·가상·미실행)와 함께 있고 메모 본문은 없음',
    observed: `작전실 /api/ops HTTP ${r.status} · ${['rules', 'detection', 'revocation', 'restore'].map(part).join(' · ')} · 메모 본문·사용자 정보 ${leak ? '발견됨' : '없음'}` }];
}

// 10단계: 실제로 보낸 요청과 실제로 실행한 검증의 결과만 적습니다.
// B 계정 점검은 학생이 GitHub Codespaces 비밀값(ALEPH_B_EMAIL, ALEPH_B_PASSWORD)에 직접 넣은 경우에만 보냅니다.
// 이메일·비밀번호·토큰은 결과·로그·제출 묶음에 넣지 않고, 메모 ID와 내용 해시 앞자리만 적습니다.
async function authed(app, method, path, token, { headers = {}, body } = {}) {
  const response = await net(new URL(path, app), {
    method, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000),
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await response.json(); } catch { /* JSON이 아니면 빈 값 */ }
  return { status: response.status, data, cookies: response.headers.getSetCookie?.() ?? [] };
}

async function login(app, email, password) {
  const r = await authed(app, 'POST', '/api/auth/login', null, { headers: { 'X-Vault-Request': '1' }, body: { email, password } });
  return { status: r.status, error: r.data?.error, token: typeof r.data?.accessToken === 'string' ? r.data.accessToken : null,
    cookie: r.cookies.map((c) => c.split(';')[0]).join('; ') };
}
async function logout(app, session) {
  if (session?.cookie) await authed(app, 'POST', '/api/auth/logout', session.token, { headers: { 'X-Vault-Request': '1', Cookie: session.cookie } }).catch(() => null);
}

// 실제 배포에 B(비밀값이 있으면 A도)로 로그인해 복원 연습과 복구 뒤 재시험을 보냅니다.
async function liveRestoreChecks(app, config) {
  const B = { email: process.env.ALEPH_B_EMAIL, password: process.env.ALEPH_B_PASSWORD };
  const A = { email: process.env.ALEPH_A_EMAIL, password: process.env.ALEPH_A_PASSWORD };
  const out = {};
  if (!B.email || !B.password) {
    const msg = '미실행: Codespaces 비밀값 ALEPH_B_EMAIL·ALEPH_B_PASSWORD가 없어 B 로그인 요청을 보내지 않음';
    return { drill: msg, tamper: msg, retest: msg, cross: null, crossZone: null };
  }
  const { contentSha256, MANIFEST, manifestEntry } = await import('../lib/backup-verify.mjs');
  caseOf('restore_b_deleted_note');
  const b = await login(app, B.email, B.password);
  if (!b.token) {
    const msg = `미실행: B 로그인 실패 HTTP ${b.status}${b.error ? ` ${b.error}` : ''}`;
    return { drill: msg, tamper: msg, retest: msg, cross: null, crossZone: null };
  }
  const restorePath = (id) => config.restoreRoute.slice(5).replace(':id', id);
  const short = (v) => String(v ?? '').slice(0, 12);
  const preview = (id) => authed(app, 'POST', restorePath(id), b.token, { headers: { 'X-Restore-Preview': '1' } });
  // 복원한 뒤 다시 읽어, 사본(침해 전 기록 backup/notes-manifest.json) 값과 나란히 적고 직접 비교합니다.
  const recheck = async (entry, done) => {
    const reread = await authed(app, 'GET', `/api/notes/${entry.id}`, b.token);
    const hash = reread.status === 200 ? contentSha256(reread.data.title, reread.data.body) : null;
    const owner = done.data?.restored?.ownerSha256 ?? null;
    const same = (x, y) => (x && x === y ? '같음' : '다름');
    return `ID ${reread.data?.id ?? '-'} ${same(reread.data?.id, entry.id)} · 소유자 지문 ${short(owner)}/사본 ${short(entry.owner_sha256)} ${same(owner, entry.owner_sha256)} · 내용 해시 ${short(hash)}/사본 ${short(entry.content_sha256)} ${same(hash, entry.content_sha256)}`;
  };
  // 복원 대상이 아닌 B의 다른 메모가 그대로인지 확인합니다(내용 해시 비교).
  const snapshotOthers = async (exceptId) => {
    const list = await authed(app, 'GET', '/api/notes', b.token);
    return new Map((Array.isArray(list.data) ? list.data : []).filter((n) => n.id !== exceptId)
      .map((n) => [n.id, contentSha256(n.title, n.body)]));
  };
  const othersSame = (before, after) => [...before].every(([id, h]) => after.get(id) === h) && before.size === after.size;
  let entry = null;
  try {
    const list = await authed(app, 'GET', '/api/notes', b.token);
    const notes = Array.isArray(list.data) ? list.data : [];
    for (const note of notes.filter((n) => manifestEntry(n.id))) {
      const plan = await preview(note.id);
      if (plan.status === 200 && plan.data?.verified === true && plan.data.changes?.length === 0) { entry = manifestEntry(note.id); break; }
    }
    const absent = await preview('00000000-0000-4000-8000-0000000000aa');
    if (!entry) {
      out.drill = `미실행: B 메모 가운데 검증 기록(${MANIFEST.label})에 있고 지금 사본과 같은 메모가 없어 복원 연습을 하지 않음 · 기록에 없는 ID HTTP ${absent.status}`;
      out.tamper = out.drill;
    } else {
      const othersBefore = await snapshotOthers(entry.id);
      // ① 삭제 → 복원
      const removed = await authed(app, 'DELETE', `/api/notes/${entry.id}`, b.token);
      const plan1 = await preview(entry.id);
      // 사본 버전과 다른 확인 값을 붙인 복원 요청은 멈추고 쓰지 않아야 합니다(메모는 여전히 없음).
      const wrong = await authed(app, 'POST', restorePath(entry.id), b.token, { headers: { 'X-Restore-Confirm': 'wrong-version' } });
      const stillGone = await authed(app, 'GET', `/api/notes/${entry.id}`, b.token);
      // 본문 없는 POST 한 번으로 복원합니다(경로의 ID만 보냄).
      const done1 = await authed(app, 'POST', restorePath(entry.id), b.token);
      out.drill = `B 실제 요청: 삭제 ${removed.status} → 미리보기(버전 ${plan1.data?.backupLabel ?? '-'}, 바뀔 항목 ${(plan1.data?.changes ?? []).join(',') || '-'}) → 틀린 확인 ${wrong.status}·쓰기 ${stillGone.status === 404 ? '없음' : '있음'} → POST 복원 ${done1.status} ${done1.data?.result ?? done1.data?.error ?? ''} → 다시 읽음: ${await recheck(entry, done1)} · 기록에 없는 ID ${absent.status} 멈춤`;
      // ② 변조 → 복원
      caseOf('restore_b_tampered_note');
      const changed = await authed(app, 'PUT', `/api/notes/${entry.id}`, b.token, { body: { title: '변조된 가상 제목', body: '변조된 가상 내용' } });
      const plan2 = await preview(entry.id);
      const done2 = await authed(app, 'POST', restorePath(entry.id), b.token);
      const othersAfter = await snapshotOthers(entry.id);
      out.tamper = `B 실제 요청: 변조 ${changed.status} → 미리보기(버전 ${plan2.data?.backupLabel ?? '-'}, 바뀔 항목 ${(plan2.data?.changes ?? []).join(',') || '-'}) → POST 복원 ${done2.status} ${done2.data?.result ?? done2.data?.error ?? ''} → 다시 읽음: ${await recheck(entry, done2)} · B의 다른 메모 ${othersBefore.size}건 ${othersSame(othersBefore, othersAfter) ? '그대로' : '바뀜'}`;
    }
  } catch (error) {
    out.drill = out.drill ?? `복원 연습 중 오류: ${String(error?.name ?? 'error')}`;
    out.tamper = out.tamper ?? `변조 복원 연습 중 오류: ${String(error?.name ?? 'error')}`;
  }

  caseOf('post_restore_retest');
  // ③ 복구 뒤 재시험(A 비밀값이 있으면 A 정상 요청과 B의 A 자료 요청까지)
  let aSession = null;
  let aNote = null;
  let aBefore = null;
  if (A.email && A.password) {
    aSession = await login(app, A.email, A.password);
    if (aSession.token) {
      const aList = await authed(app, 'GET', '/api/notes', aSession.token);
      aNote = Array.isArray(aList.data) && aList.data.length ? aList.data[0] : null;
      aBefore = aNote ? contentSha256(aNote.title, aNote.body) : null;
    }
  }
  try {
    const own = await authed(app, 'GET', '/api/notes', b.token);
    const one = entry ? await authed(app, 'GET', `/api/notes/${entry.id}`, b.token) : null;
    const notices = await authed(app, 'GET', '/api/notices', b.token);
    const noticeWrite = await authed(app, 'PUT', '/api/notices/00000000-0000-4000-8000-0000000000aa', b.token, { body: { title: 'x', body: '' } });
    const target = entry?.id ?? '00000000-0000-4000-8000-0000000000aa';
    const query = await authed(app, 'GET', `/api/notes/${target}?owner_id=00000000-0000-4000-8000-000000000001`, b.token);
    const ownerBody = await authed(app, 'POST', restorePath(target), b.token, { body: { owner_id: '00000000-0000-4000-8000-000000000001' } });
    const ghost = await authed(app, 'PUT', '/api/notes/00000000-0000-4000-8000-0000000000aa', b.token, { body: { title: 'x', body: '' } });
    const anon = await authed(app, 'GET', '/api/notes', null);
    const forgedList = await authed(app, 'GET', '/api/notes', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.forged');
    const publicData = await authed(app, 'GET', '/data.json', null);
    const publicNotes = Array.isArray(publicData.data) ? publicData.data.length : Array.isArray(publicData.data?.notes) ? publicData.data.notes.length : 0;
    let aPart = ' · A 미실행(비밀값 없음)';
    let bToA = '';
    if (aSession?.token && aNote) {
      const bRead = await authed(app, 'GET', `/api/notes/${aNote.id}`, b.token);
      const bPut = await authed(app, 'PUT', `/api/notes/${aNote.id}`, b.token, { body: { title: 'B가 바꿈', body: '' } });
      const bDel = await authed(app, 'DELETE', `/api/notes/${aNote.id}`, b.token);
      const bRestore = await authed(app, 'POST', restorePath(aNote.id), b.token);
      const aList2 = await authed(app, 'GET', '/api/notes', aSession.token);
      const aRead = await authed(app, 'GET', `/api/notes/${aNote.id}`, aSession.token);
      const aSame = aRead.status === 200 && contentSha256(aRead.data.title, aRead.data.body) === aBefore;
      aPart = ` · A 목록 ${aList2.status}·메모 ${aRead.status}(${aSame ? '그대로' : '바뀜'})`;
      bToA = ` · [4] B→A 메모 읽기 ${bRead.status}·수정 ${bPut.status}·삭제 ${bDel.status}·복원 ${bRestore.status}`;
      out.cross = `B 실제 요청으로 A 메모: 읽기 ${bRead.status} · 수정 ${bPut.status} · 삭제 ${bDel.status} · 복원 ${bRestore.status} → A가 다시 읽기 ${aRead.status}, 내용 ${aSame ? '그대로' : '바뀜'}`;
      out.crossZone = `B 실제 요청: A 메모 읽기 ${bRead.status} · 수정 ${bPut.status} / 학생 B의 공지 목록 ${notices.status} · 공지 수정 ${noticeWrite.status}`;
    } else if (A.email && A.password) {
      aPart = ` · A 미실행(로그인 ${aSession?.status ?? '-'} 또는 메모 없음)`;
    }
    out.retest = `복구 뒤 실제 요청 · 정상: B 목록 ${own.status}${one ? `·복원 메모 ${one.status}` : ''}${aPart} / 금지: [1·2] /data.json ${publicData.status}(메모 ${publicNotes}건) · [3] 비로그인 ${anon.status}·위조 토큰 ${forgedList.status}${bToA} · [5] 쿼리 ${query.status}·본문 owner_id ${ownerBody.status} · [8] 공지 ${notices.status}·없는 메모 ${ghost.status}`;
  } catch (error) {
    out.retest = `재시험 중 오류: ${String(error?.name ?? 'error')}`;
  }
  await logout(app, aSession);
  await logout(app, b);
  return out;
}

// 10단계: 복원 점검을 먼저 하고(앞쪽 줄), 그 뒤에 1~9단계 점검을 다시 실행합니다(복구 뒤 재시험).
async function restoreChecks(app, config) {
  if (typeof config.restoreRoute !== 'string' || !/^POST \/api\/[A-Za-z0-9/_-]+\/:id$/u.test(config.restoreRoute)) {
    throw new Error('aleph.config.json의 restoreRoute를 먼저 넣어 주세요.');
  }
  const { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, copyFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { createHash } = await import('node:crypto');
  const sha = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
  const auditPath = new URL('../policy/audit.jsonl', import.meta.url).pathname;
  const { verifySnapshot, diffPolicy, restorePolicy, TEST_POLICY, OPERATING_POLICY } = await import('../scripts/policy-restore.mjs');
  const deciderPath = TEST_POLICY; // 시험 정책. 실제 운영 정책(src/decider.mjs)은 읽기만 합니다.

  const path = config.restoreRoute.slice(5).replace(':id', '00000000-0000-4000-8000-000000000001');
  caseOf('restore_anonymous');
  const anonymous = await anonymousGet(app, path, {}, 'POST');
  const forged = await anonymousGet(app, path, {
    Authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.forged',
  }, 'POST');
  const denied = (r) => (r.status === 401 || r.status === 403 ? '거부됨' : '거부되지 않음');

  // 안전 정책 사본을 디스크에서 다시 읽어 검증하고, 변조·없는 사본으로는 멈추는지 임시 폴더에서 실제로 시도합니다.
  let policyLine;
  try {
    const v = await verifySnapshot();
    const d = await diffPolicy(deciderPath);
    const work = mkdtempSync(join(tmpdir(), 'aleph-restore-'));
    const target = join(work, 'decider.mjs');
    copyFileSync(deciderPath, target);
    const tampered = join(work, 'tampered.mjs');
    writeFileSync(tampered, readFileSync(deciderPath, 'utf8').replace("access: 'deny_bulk'", "access: 'allow'"));
    const before = [sha(target), existsSync(auditPath) ? sha(auditPath) : 'none', sha(OPERATING_POLICY)].join();
    const write = process.stdout.write.bind(process.stdout);
    process.stdout.write = () => true;
    const tryRestore = async (snapshotPath) => {
      try { await restorePolicy(target, v.manifest.version, { snapshotPath }); return '복원됨'; } catch { return '중단'; }
    };
    let tamper;
    let none;
    try { tamper = await tryRestore(tampered); none = await tryRestore(join(work, 'none.mjs')); } finally { process.stdout.write = write; }
    const after = [sha(target), existsSync(auditPath) ? sha(auditPath) : 'none', sha(OPERATING_POLICY)].join();
    rmSync(work, { recursive: true, force: true });
    policyLine = `사본 ${v.manifest.version} 다시 읽어 고정 지문 SHA-256·안전 요청 ${v.probes.length}건 검증 통과(${v.gitCheck.startsWith('Git 기록 없음') ? 'Git 기록 없음' : `Git ${v.manifest.sourceCommit.slice(0, 7)} 같음`}) / 실행 전 표시: 복원 버전 ${v.manifest.version}, 시험 정책 변경 범위 ${d.identical ? '없음' : `요청 ${d.changedProbes.length}건`} / 변조 사본 → ${tamper} · 없는 사본 → ${none} / 시험 정책·감사 기록·운영 정책(src/decider.mjs) ${before === after ? '그대로' : '바뀜'}`;
  } catch (error) {
    policyLine = `검증 실패로 중단: ${String(error?.message ?? error).slice(0, 150)}`;
  }
  const live = await liveRestoreChecks(app, config);
  return {
    first: [
      { attackId: 'restore_anonymous',
        expected: `로그인 없는·위조 토큰 복원 요청(${config.restoreRoute})은 401·403으로 거부`,
        observed: `비로그인 POST ${path} 결과 HTTP ${anonymous.status}${anonymous.error ? ` ${anonymous.error}` : ''} (${denied(anonymous)}) · 위조 토큰 HTTP ${forged.status} (${denied(forged)})` },
      { attackId: 'policy_snapshot_verified',
        expected: '침해 전 안전 정책 사본을 다시 읽어 검증하고 실행 전에 버전·변경 범위를 표시, 사본이 없거나 검증이 실패하면 중단, 실제 운영 정책은 건드리지 않음',
        observed: policyLine },
      { attackId: 'restore_b_deleted_note',
        expected: 'B 메모 삭제 뒤 복원: 사본을 다시 읽어 침해 전 검증 기록과 대조·미리보기 뒤 그 한 건만 복원, 다시 읽은 ID·소유자·내용 해시가 기록과 같음. 기록에 없는 ID는 멈춤',
        observed: live.drill },
      { attackId: 'restore_b_tampered_note',
        expected: 'B 메모 변조 뒤 복원: 미리보기에 바뀔 항목(제목·내용)을 보여 주고, 복원 뒤 다시 읽은 ID·소유자·내용 해시가 침해 전 기록과 같음',
        observed: live.tamper },
    ],
    last: [
      { attackId: 'post_restore_retest',
        expected: '복구 뒤 1~9단계 다시: 정상(B·A 자기 목록·메모 200) 유지, 금지([1·2] 공개 data.json 메모 없음, [3] 비로그인·위조 401, [4] B→A 404, [5] 쿼리·본문 owner_id 400, [8] 공지 403) 거부. [6·7·9]는 판정기·탐지 줄',
        observed: live.retest },
    ],
    cross: live.cross,
    crossZone: live.crossZone,
  };
}

// 9단계: 학생 탐지 함수(src/detect.mjs)에 가상 조회 사건을 넣어 본 결과만 적습니다.
// 실제 반 엔진의 사건 전달·접속 회수는 이 저장소에서 보낼 수 없으므로 미실행으로 남깁니다.
async function detectChecks({ compact = false } = {}) {
  const { detect } = await import('./detect.mjs');
  const start = Date.UTC(2026, 9, 1, 2, 0, 0);
  const reads = (count, deviceId, network) => Array.from({ length: count }, (_, i) => ({
    at: new Date(start + i * 2000).toISOString(), method: 'GET', identity: { sub: 'learner_fixture' },
    deviceId, decision: 'allow', signals: { source: 'judge_fixture', region: 'KR-11', network, hour: 2 },
  }));
  const mix = (...lists) => lists.flat().sort((a, b) => a.at.localeCompare(b.at));
  const said = (r) => (r.action === 'observe' ? 'observe'
    : `${r.action} · ${r.reasonCode} · 대상 ${r.subject}${r.deviceId ? `/${r.deviceId}` : ''}`);
  const normal = detect(reads(200, 'device_home', 'usual'));
  const regionOnly = detect(reads(200, 'device_home', 'usual').map((e) => ({ ...e, signals: { ...e.signals, region: 'US-CA' } })));
  const fewUnusual = detect(reads(20, 'device_other', 'unusual'));
  const doppel = detect(mix(reads(50, 'device_home', 'usual'), reads(150, 'device_other', 'unusual')));
  const liveLine = '미실행: 이 저장소에는 엔진의 사건 전달·회수 집행 경로가 없음. 실제 회수와 시간은 심판이 확인';
  if (compact) {
    // 11단계부터는 제출 점검 20개 한도 때문에 실제 회수 집행(미실행) 줄을 도플갱어 탐지 줄에 합쳐 적습니다.
    return [
      { attackId: 'detect_normal_device',
        expected: '평소 네트워크의 정상 기기 다량 조회, 지역만 다른 조회, 처음 보는 네트워크의 적은 조회(20건)는 모두 observe(회수 제안 없음)',
        observed: `가상 사건 탐지 결과 정상 기기 200건 ${said(normal)} / 지역만 다름 200건 ${said(regionOnly)} / 처음 보는 네트워크 20건 ${said(fewUnusual)}` },
      { attackId: 'detect_doppelganger_burst',
        expected: '다른 기기가 10분 안에 120건 넘게 조회하면 그 기기만 propose_revocation · burst_read. 엔진의 실제 회수 집행은 별도',
        observed: `정상 기기 50건 + 다른 기기 150건 탐지 결과 ${said(doppel)} / 실제 회수 집행: ${liveLine}` },
    ];
  }
  return [
    { attackId: 'detect_normal_device',
      expected: '평소 네트워크의 정상 기기 다량 조회, 지역만 다른 조회, 처음 보는 네트워크의 적은 조회(20건)는 모두 observe(회수 제안 없음)',
      observed: `가상 사건 탐지 결과 정상 기기 200건 ${said(normal)} / 지역만 다름 200건 ${said(regionOnly)} / 처음 보는 네트워크 20건 ${said(fewUnusual)}` },
    { attackId: 'detect_doppelganger_burst',
      expected: '같은 사용자의 다른 기기가 처음 보는 네트워크에서 10분 안에 120건을 넘게 조회하면 그 기기 하나만 propose_revocation · burst_read, 정상 기기는 유지',
      observed: `정상 기기 50건 + 다른 기기 150건 탐지 결과 ${said(doppel)}` },
    { attackId: 'live_revocation',
      expected: '반 엔진이 회수 제안을 집행해 의심 기기 접속이 끊기고 걸린 시간이 측정됨',
      observed: liveLine },
  ];
}

// 11단계: 접속 앱(manifest·서비스 워커)과 기기 승인 게이트. 실제로 보낸 요청의 결과만 적습니다.
// B 부분은 Codespaces 비밀값(ALEPH_B_EMAIL·ALEPH_B_PASSWORD)이 있을 때만 보내며, 이 점검은 기기를 승인하지 않습니다.
async function deviceGateChecks(app) {
  caseOf('device_approval_gate');
  const manifest = await authed(app, 'GET', '/manifest.json', null);
  const sw = await net(new URL('/sw.js', app), { redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000) });
  const swText = sw.ok ? await sw.text() : '';
  const swOnlyOffline = /OFFLINE_URL = '\/offline\.html'/u.test(swText) && !/cache\.(put|addAll)/u.test(swText);
  const anon = await anonymousGet(app, '/api/device/status');
  let bPart = '미실행: Codespaces 비밀값 ALEPH_B_EMAIL·ALEPH_B_PASSWORD가 없어 B 로그인 요청을 보내지 않음';
  const B = { email: process.env.ALEPH_B_EMAIL, password: process.env.ALEPH_B_PASSWORD };
  if (B.email && B.password) {
    const b = await login(app, B.email, B.password);
    if (!b.token) {
      bPart = `미실행: B 로그인 실패 HTTP ${b.status}`;
    } else {
      const fresh = await authed(app, 'GET', '/api/device/status', b.token);
      const forged = await authed(app, 'POST', '/api/device/request', b.token, { body: { approved: true } });
      const asked = await authed(app, 'POST', '/api/device/request', b.token);
      const cookie = asked.cookies.map((c) => c.split(';')[0]).join('; ');
      const after = await authed(app, 'GET', '/api/device/status', b.token, { headers: cookie ? { Cookie: cookie } : {} });
      const st = (r) => `${r.status} ${r.data?.state ?? r.data?.error ?? ''} approved=${r.data?.approved === true}`;
      bPart = `B 새 기기 ${st(fresh)} → 승인 값 넣은 요청 ${forged.status} → 승인 요청 ${st(asked)} → 다시 확인 ${st(after)}`;
      await logout(app, b);
    }
  }
  return [{ attackId: 'device_approval_gate',
    expected: '설치형 앱 manifest·오프라인 안내만 캐시하는 서비스 워커. 기기 상태는 로그인 필요, 승인 요청·설치 표시·요청 값으로는 승인되지 않음(승인 전 자료 없음)',
    observed: `manifest ${manifest.status} 이름 ${manifest.data?.name ?? '-'} · sw.js ${sw.status} ${swOnlyOffline ? '오프라인 안내만 캐시' : '캐시 대상 확인 필요'} · 비로그인 기기 상태 ${anon.status} / ${bPart}` }];
}

// 실행기는 runAttackChecks(publicAppUrl)처럼 배포 주소만 넘길 수 있고, npm run bundle 예전 방식은 설정 전체를 넘깁니다. 둘 다 받습니다.
export async function runAttackChecks(input) {
  let config = input;
  if (typeof input === 'string') {
    const { default: saved } = await import('../aleph.config.json', { with: { type: 'json' } });
    config = { ...saved, publicAppUrl: input };
  }
  const app = appUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 1) {
    const response = await net(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let visible = false;
    if (response.ok) {
      try {
        const data = await response.json();
        visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
          && data.notes.length > 0;
      } catch {
        // A non-JSON response is a failed check, not a successful deployment.
      }
    }
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  if (config.step === 2) {
    // 실제로 보낸 비로그인 요청의 결과만 적습니다. 메모 본문은 기록하지 않습니다.
    const oldFile = await anonymousGet(app, '/data.json');
    const api = await anonymousGet(app, '/api/notes');
    const oldFileBlocked = oldFile.status === 404 || oldFile.notes === 0;
    return [
      { attackId: 'anonymous_note_read',
        expected: '공개 /data.json에서 가상 메모가 보이지 않음 (404 또는 0건)',
        observed: oldFileBlocked
          ? `비로그인 /data.json 요청에서 메모가 보이지 않음 (HTTP ${oldFile.status})`
          : `비로그인 /data.json 요청에서 메모 ${oldFile.notes ?? '?'}건이 보임 (HTTP ${oldFile.status})` },
      { attackId: 'anonymous_api_read',
        expected: '남은 약점: 로그인이 없어 /api/notes는 아직 메모를 돌려줌 (3단계에서 차단 예정)',
        observed: `비로그인 /api/notes 요청 결과 HTTP ${api.status}, 메모 ${api.notes ?? 0}건` },
    ];
  }

  if (config.step === 3) {
    // 실제로 보낸 요청의 결과만 적습니다. 메모 본문·토큰은 기록하지 않습니다.
    const oldFile = await anonymousGet(app, '/data.json');
    const noLogin = await anonymousGet(app, '/api/notes');
    const forged = await anonymousGet(app, '/api/notes', {
      Authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.forged',
    });
    const denied = (r) => (r.status === 401 || r.status === 403) && r.notes === null;
    const describe = (r) => `HTTP ${r.status}${r.error ? ` ${r.error}` : ''}${r.notes === null ? ', 메모 없음' : `, 메모 ${r.notes}건`}`;
    return [
      { attackId: 'anonymous_note_read',
        expected: '공개 /data.json에서 가상 메모가 보이지 않음 (404 또는 0건)',
        observed: `비로그인 /data.json 요청 결과 HTTP ${oldFile.status}${oldFile.notes ? `, 메모 ${oldFile.notes}건` : ', 메모 없음'}` },
      { attackId: 'anonymous_api_read',
        expected: '로그인 없는 /api/notes 목록 요청은 401·403 JSON 오류로 거부',
        observed: `비로그인 /api/notes 요청 결과 ${describe(noLogin)}${denied(noLogin) ? ' (거부됨)' : ' (거부되지 않음)'}` },
      { attackId: 'forged_token_read',
        expected: '서명이 없는 위조 토큰의 /api/notes 요청은 401·403으로 거부',
        observed: `위조 토큰 /api/notes 요청 결과 ${describe(forged)}${denied(forged) ? ' (거부됨)' : ' (거부되지 않음)'}` },
      { attackId: 'login_a_crud',
        expected: 'A 로그인 뒤 가상 메모 추가·수정·삭제 성공, 삭제 뒤 GET 404',
        observed: '미실행: 계정 비밀번호를 코드에 넣지 않아 이 스크립트로는 보내지 않음. 학생이 화면에서 직접 확인' },
      { attackId: 'cross_user_note_write',
        expected: '남은 약점: 소유자 검사가 없어 B가 A 메모 id로 수정 가능 (4단계에서 차단·기록 예정)',
        observed: '미실행: B 계정 점검은 4단계에서 기록' },
    ];
  }

  if (config.step === 4) {
    // 실제로 보낸 요청의 결과만 적습니다. 메모 본문·토큰·이메일은 기록하지 않습니다.
    const noLogin = await anonymousGet(app, '/api/notes');
    const forged = await anonymousGet(app, '/api/notes', {
      Authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.forged',
    });
    const direct = await anonDataApi();
    const denied = (r) => (r.status === 401 || r.status === 403) && r.notes === null;
    const describe = (r) => `HTTP ${r.status}${r.error ? ` ${r.error}` : ''}${r.notes === null ? ', 메모 없음' : `, 메모 ${r.notes}건`}`;
    const directBlocked = direct.rows === null || direct.rows === 0;
    return [
      { attackId: 'anonymous_api_read',
        expected: '로그인 없는 /api/notes 목록 요청은 401·403 JSON 오류로 거부',
        observed: `비로그인 /api/notes 요청 결과 ${describe(noLogin)}${denied(noLogin) ? ' (거부됨)' : ' (거부되지 않음)'}` },
      { attackId: 'forged_token_read',
        expected: '서명이 없는 위조 토큰의 /api/notes 요청은 401·403으로 거부',
        observed: `위조 토큰 /api/notes 요청 결과 ${describe(forged)}${denied(forged) ? ' (거부됨)' : ' (거부되지 않음)'}` },
      { attackId: 'anon_direct_data_api',
        expected: 'anon 키로 Supabase Data API notes 직접 조회 시 권한 없음 또는 0행',
        observed: `anon 키 직접 조회 결과 HTTP ${direct.status}${direct.code ? ` ${direct.code}` : ''}, ${direct.rows === null ? '행 없음' : `${direct.rows}행`}${directBlocked ? ' (막힘)' : ' (노출됨)'}` },
      { attackId: 'cross_user_note_read',
        expected: 'B 로그인으로 A 메모 id를 GET·PUT·DELETE하면 404로 거부되고 A 메모는 그대로',
        observed: '미실행: 계정 비밀번호를 코드에 넣지 않아 이 스크립트로는 보내지 않음. 학생이 B 창에서 A 메모가 안 보이는 것을 직접 확인' },
      { attackId: 'owner_change_write',
        expected: '본인 메모의 owner_id를 다른 사용자로 바꾸는 PUT은 403으로 거부',
        observed: '미실행: 로그인 토큰이 필요해 이 스크립트로는 보내지 않음' },
    ];
  }

  if (config.step >= 5 && config.step <= 12) {
    // 실제로 보낸 요청의 결과만 적습니다. 메모 본문·토큰·이메일은 기록하지 않습니다.
    if (typeof config.originalApiUrl !== 'string' || !config.originalApiUrl.startsWith('https://')) {
      throw new Error('aleph.config.json의 originalApiUrl을 먼저 넣어 주세요.');
    }
    // 10단계: 복원 점검을 먼저 실행하고, 아래 1~9단계 점검은 그 뒤에 다시 보냅니다(복구 뒤 재시험).
    const restored = config.step >= 10 ? await restoreChecks(app, config) : null;
    caseOf('anonymous_api_read');
    const noLogin = await anonymousGet(app, '/api/notes');
    caseOf('forged_token_read');
    const forged = await anonymousGet(app, '/api/notes', {
      Authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.forged',
    });
    caseOf('anon_original_api_read');
    const direct = await anonDataApi(config.originalApiUrl);
    caseOf('browser_key_exposure');
    const page = await net(new URL('/', app), {
      redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000),
    });
    const html = await page.text();
    const keyInPage = /sb_publishable_|sb_secret_|supabase\.co/iu.test(html);
    const denied = (r) => (r.status === 401 || r.status === 403) && r.notes === null;
    const describe = (r) => `HTTP ${r.status}${r.error ? ` ${r.error}` : ''}${r.notes === null ? ', 메모 없음' : `, 메모 ${r.notes}건`}`;
    const directBlocked = direct.rows === null || direct.rows === 0;
    const rules = config.step >= 12 ? await httpRuleChecks(app, { crossObserved: restored?.crossZone }) : null;
    return finalize([
      ...(restored ? restored.first : []),
      { attackId: 'anonymous_api_read',
        expected: '로그인 없는 /api/notes 목록 요청은 401·403 JSON 오류로 거부',
        observed: `비로그인 /api/notes 요청 결과 ${describe(noLogin)}${denied(noLogin) ? ' (거부됨)' : ' (거부되지 않음)'}` },
      { attackId: 'forged_token_read',
        expected: '서명이 없는 위조 토큰의 /api/notes 요청은 401·403으로 거부',
        observed: `위조 토큰 /api/notes 요청 결과 ${describe(forged)}${denied(forged) ? ' (거부됨)' : ' (거부되지 않음)'}` },
      { attackId: 'anon_original_api_read',
        expected: 'anon 키로 originalApiUrl(원본 자료 경로)을 직접 불러도 메모 없음',
        observed: `anon 키 원본 직접 조회 결과 HTTP ${direct.status}${direct.code ? ` ${direct.code}` : ''}, ${direct.rows === null ? '행 없음' : `${direct.rows}행`}${directBlocked ? ' (막힘)' : ' (노출됨)'}` },
      { attackId: 'browser_key_exposure',
        expected: '첫 화면 코드에 자료 저장소 주소·공개 키가 없음',
        observed: `첫 화면 HTTP ${page.status}, 저장소 주소·키 문자열 ${keyInPage ? '발견됨' : '없음'}` },
      { attackId: 'cross_user_note_read',
        expected: 'B 로그인으로 A 메모 id를 GET·PUT·DELETE하면 404로 거부되고 A 메모는 그대로',
        observed: restored?.cross ?? '미실행: 계정 비밀번호를 코드에 넣지 않아 이 스크립트로는 보내지 않음. 학생이 B 창에서 A 메모가 안 보이는 것을 직접 확인' },
      ...(rules ? rules.device : config.step >= 6 ? await deviceChecks() : []),
      ...(rules ? rules.stepUp : config.step >= 7 ? await stepUpChecks({ compact: config.step >= 9 }) : []),
      ...(rules ? rules.zone : config.step >= 8 ? await zoneChecks(app, { compact: config.step >= 10, crossObserved: restored?.crossZone }) : []),
      ...(rules ? rules.detect : config.step >= 9 ? await detectChecks({ compact: config.step >= 11 }) : []),
      ...(restored ? restored.last : []),
      ...(config.step >= 11 ? await deviceGateChecks(app) : []),
      ...(config.step >= 12 ? await opsRoomCheck(app) : []),
    ]);
  }

  throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
}
