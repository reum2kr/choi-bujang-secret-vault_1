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

async function anonymousGet(app, path, headers = {}, method = 'GET') {
  const response = await fetch(new URL(path, app), {
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
  const response = await fetch(url, {
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
async function zoneChecks(app, { compact = false } = {}) {
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
  const notices = await anonymousGet(app, '/api/notices');
  const noticeLine = { attackId: 'anonymous_notice_read',
    expected: '로그인 없는 /api/notices 요청은 401·403 JSON 오류로 거부',
    observed: `비로그인 /api/notices 요청 결과 HTTP ${notices.status}${notices.error ? ` ${notices.error}` : ''}${notices.notes === null ? ', 자료 없음' : `, ${notices.notes}건`}` };
  const crossLine = { attackId: 'zone_api_cross_owner',
    expected: '메뉴를 우회한 직접 API 요청: B의 A 메모 GET·PUT은 404, 학생의 공지 GET·PUT은 403 INSTRUCTOR_REQUIRED',
    observed: '미실행: 로그인 토큰이 필요해 이 스크립트로는 보내지 않음. 자료 API 소유자·강사 대조는 가짜 DB 로컬 시험으로 확인' };
  const short = (o) => `${o.decision}(${o.reasonCode})`; // 한 줄 300자 한도에 맞춰 결정과 이유 코드만
  if (compact) {
    // 10단계부터는 제출 점검 20개 한도 때문에 판정기 구역 가상 요청 여섯 건을 한 줄로 합쳐 적습니다(결과는 그대로 모두 기록).
    return [
      { attackId: 'zone_decider_rules',
        expected: '자기 메모 한 건 allow · 메모 전체 목록 deny(zone_notes_no_bulk) · 학생의 공지 수정·읽기 deny(instructor_required) · export 기능 경로·경로표 밖 경로 deny(route_not_allowed)',
        observed: `판정기 응답 자기 메모 ${short(own)} / 전체 목록 ${short(bulkList)} / 공지 수정 ${short(noticeWrite)} / 공지 읽기 ${short(noticeRead)} / export ${short(exportPath)} / GET /admin ${short(unknown)}` },
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

// 10단계: 실제로 보낸 요청과 실제로 실행한 검증의 결과만 적습니다.
// B 계정 점검은 학생이 GitHub Codespaces 비밀값(ALEPH_B_EMAIL, ALEPH_B_PASSWORD)에 직접 넣은 경우에만 보냅니다.
// 이메일·비밀번호·토큰은 결과·로그·제출 묶음에 넣지 않고, 메모 ID와 내용 해시 앞자리만 적습니다.
async function authed(app, method, path, token, { headers = {}, body } = {}) {
  const response = await fetch(new URL(path, app), {
    method, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000),
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await response.json(); } catch { /* JSON이 아니면 빈 값 */ }
  return { status: response.status, data, cookies: response.headers.getSetCookie?.() ?? [] };
}

async function liveRestoreChecks(app, config) {
  const email = process.env.ALEPH_B_EMAIL;
  const password = process.env.ALEPH_B_PASSWORD;
  const notRun = '미실행: Codespaces 비밀값 ALEPH_B_EMAIL·ALEPH_B_PASSWORD가 없어 B 로그인 요청을 보내지 않음';
  if (!email || !password) return { drill: notRun, retest: notRun };
  const { contentSha256 } = await import('../lib/backup-verify.mjs');
  const login = await authed(app, 'POST', '/api/auth/login', null, { headers: { 'X-Vault-Request': '1' }, body: { email, password } });
  const token = login.data?.accessToken;
  if (login.status !== 200 || typeof token !== 'string') {
    const msg = `미실행: B 로그인 실패 HTTP ${login.status}${login.data?.error ? ` ${login.data.error}` : ''}`;
    return { drill: msg, retest: msg };
  }
  const restorePath = (id) => config.restoreRoute.slice(5).replace(':id', id);
  const short = (v) => String(v ?? '').slice(0, 12);
  let drill;
  let restoredId = null;
  try {
    const list = await authed(app, 'GET', '/api/notes', token);
    const notes = Array.isArray(list.data) ? list.data : [];
    // 미리보기로 사본 검증이 통과하고 바뀔 항목이 없는 메모 한 건만 고릅니다(사본 뒤에 고친 메모는 건드리지 않음).
    let pick = null;
    let previewed = 0;
    for (const note of notes.slice(0, 10)) {
      const plan = await authed(app, 'POST', restorePath(note.id), token, { headers: { 'X-Restore-Preview': '1' } });
      previewed += 1;
      if (plan.status === 200 && Array.isArray(plan.data?.changes) && plan.data.changes.length === 0) { pick = { note, plan: plan.data }; break; }
    }
    const missing = await authed(app, 'POST', restorePath('00000000-0000-4000-8000-0000000000aa'), token, { headers: { 'X-Restore-Preview': '1' } });
    if (!pick) {
      drill = `B 실제 로그인: 메모 ${notes.length}건 미리보기 ${previewed}건 중 사본과 같은 메모 없음 → 복원 연습 미실행 · 사본 없는 ID 미리보기 HTTP ${missing.status}`;
    } else {
      const id = pick.note.id;
      const removed = await authed(app, 'DELETE', `/api/notes/${id}`, token);
      const plan = await authed(app, 'POST', restorePath(id), token, { headers: { 'X-Restore-Preview': '1' } });
      const done = await authed(app, 'POST', restorePath(id), token);
      const reread = await authed(app, 'GET', `/api/notes/${id}`, token);
      restoredId = done.status === 200 ? id : null;
      const rereadHash = reread.status === 200 ? contentSha256(reread.data.title, reread.data.body) : null;
      const same = done.status === 200 && done.data?.idMatches === true && done.data?.ownerMatches === true
        && reread.data?.id === id && rereadHash === pick.plan.contentSha256 && done.data?.contentSha256 === pick.plan.contentSha256;
      drill = `B 실제 로그인: 메모 ${short(id)}… 사본 ${pick.plan.backupLabel} 검증 통과 → 삭제 HTTP ${removed.status} → 미리보기 바뀔 항목 ${(plan.data?.changes ?? []).join(',') || '-'} → 복원 HTTP ${done.status} ${done.data?.result ?? done.data?.error ?? ''} → 다시 읽은 ID·소유자·해시 ${short(rereadHash)} ${same ? '사본과 같음' : '사본과 다름'} · 사본 없는 ID HTTP ${missing.status} 중단`;
    }
  } catch (error) {
    drill = `복원 연습 중 오류: ${String(error?.name ?? 'error')}`;
  }
  let retest;
  try {
    const own = await authed(app, 'GET', '/api/notes', token);
    const one = restoredId ? await authed(app, 'GET', `/api/notes/${restoredId}`, token) : null;
    const notices = await authed(app, 'GET', '/api/notices', token);
    const target = restoredId ?? '00000000-0000-4000-8000-0000000000aa';
    const query = await authed(app, 'GET', `/api/notes/${target}?owner_id=00000000-0000-4000-8000-000000000001`, token);
    const ownerBody = await authed(app, 'POST', restorePath(target), token, { body: { owner_id: '00000000-0000-4000-8000-000000000001' } });
    const ghost = await authed(app, 'PUT', '/api/notes/00000000-0000-4000-8000-0000000000aa', token, { body: { title: 'x', body: '' } });
    const anon = await authed(app, 'GET', '/api/notes', null);
    retest = `B 실제 요청 · 정상: 내 목록 ${own.status}${Array.isArray(own.data) ? `(${own.data.length}건)` : ''}${one ? ` · 복원한 메모 읽기 ${one.status}` : ''} / 금지: 공지 목록 ${notices.status} · 쿼리로 다른 주인 지정 ${query.status} · 본문 owner_id 복원 ${ownerBody.status} · 없는 메모 수정 ${ghost.status} · 비로그인 목록 ${anon.status}`;
  } catch (error) {
    retest = `재시험 중 오류: ${String(error?.name ?? 'error')}`;
  }
  // 로그아웃: 이번 점검이 만든 로그인 세션을 닫습니다.
  const cookie = login.cookies.map((c) => c.split(';')[0]).join('; ');
  if (cookie) await authed(app, 'POST', '/api/auth/logout', token, { headers: { 'X-Vault-Request': '1', Cookie: cookie } }).catch(() => null);
  return { drill, retest };
}

async function restoreChecks(app, config) {
  if (typeof config.restoreRoute !== 'string' || !/^POST \/api\/[A-Za-z0-9/_-]+\/:id$/u.test(config.restoreRoute)) {
    throw new Error('aleph.config.json의 restoreRoute를 먼저 넣어 주세요.');
  }
  const { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, copyFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { createHash } = await import('node:crypto');
  const sha = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
  const deciderPath = new URL('./decider.mjs', import.meta.url).pathname;
  const auditPath = new URL('../policy/audit.jsonl', import.meta.url).pathname;
  const { verifySnapshot, diffPolicy, restorePolicy } = await import('../scripts/policy-restore.mjs');

  const path = config.restoreRoute.slice(5).replace(':id', '00000000-0000-4000-8000-000000000001');
  const anonymous = await anonymousGet(app, path, {}, 'POST');
  const forged = await anonymousGet(app, path, {
    Authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.forged',
  }, 'POST');
  const denied = (r) => (r.status === 401 || r.status === 403 ? '거부됨' : '거부되지 않음');

  // 안전 정책 사본을 디스크에서 다시 읽어 검증하고, 변조·없는 사본으로는 멈추는지 임시 폴더에서 실제로 시도합니다.
  let policyLine;
  try {
    const v = await verifySnapshot();
    const work = mkdtempSync(join(tmpdir(), 'aleph-restore-'));
    const target = join(work, 'decider.mjs');
    copyFileSync(deciderPath, target);
    const tampered = join(work, 'tampered.mjs');
    writeFileSync(tampered, readFileSync(deciderPath, 'utf8').replace("access: 'deny_bulk'", "access: 'allow'"));
    const before = [sha(target), existsSync(auditPath) ? sha(auditPath) : 'none'].join();
    const write = process.stdout.write.bind(process.stdout);
    process.stdout.write = () => true;
    const tryRestore = async (snapshotPath) => {
      try { await restorePolicy(target, v.manifest.version, { snapshotPath }); return '복원됨'; } catch { return '중단'; }
    };
    let tamper;
    let none;
    try { tamper = await tryRestore(tampered); none = await tryRestore(join(work, 'none.mjs')); } finally { process.stdout.write = write; }
    const after = [sha(target), existsSync(auditPath) ? sha(auditPath) : 'none'].join();
    rmSync(work, { recursive: true, force: true });
    policyLine = `사본 ${v.manifest.version} 다시 읽어 지문 확인 · Git 대조 ${v.gitCheck} · 안전 요청 ${v.probes.length}건 모두 기대대로 / 변조 사본 → ${tamper} · 없는 사본 → ${none} · 대상 파일·감사 기록 ${before === after ? '그대로' : '바뀜'}`;
  } catch (error) {
    policyLine = `검증 실패로 중단: ${String(error?.message ?? error).slice(0, 150)}`;
  }
  let diffLine;
  try {
    const d = await diffPolicy(deciderPath);
    diffLine = d.identical ? `복원할 버전 ${d.safe.manifest.version} · 현재 src/decider.mjs가 사본과 같음(변경 범위 없음)`
      : `복원할 버전 ${d.safe.manifest.version} · 현재 정책이 사본과 다름: 줄 ${d.text.removed}개 빠짐·${d.text.added}개 들어옴, 응답이 달라지는 요청 ${d.changedProbes.length}건`;
  } catch (error) {
    diffLine = '미실행: 사본 검증이 중단되어 비교하지 않음';
  }
  const live = await liveRestoreChecks(app, config);
  return [
    { attackId: 'restore_anonymous',
      expected: `로그인 없는·위조 토큰 복원 요청(${config.restoreRoute})은 401·403으로 거부`,
      observed: `비로그인 POST ${path} 결과 HTTP ${anonymous.status}${anonymous.error ? ` ${anonymous.error}` : ''} (${denied(anonymous)}) · 위조 토큰 HTTP ${forged.status} (${denied(forged)})` },
    { attackId: 'policy_snapshot_verified',
      expected: '침해 전 안전 정책 사본을 다시 읽어 지문·Git 기록·안전 요청으로 검증하고, 사본이 없거나 검증이 실패하면 중단',
      observed: policyLine },
    { attackId: 'policy_current_vs_snapshot',
      expected: '실행 전에 복원할 버전과 현재 시험 정책과의 변경 범위를 표시',
      observed: diffLine },
    { attackId: 'restore_b_own_note',
      expected: 'B 로그인으로 사본의 자기 메모 한 건 복원: 사본을 다시 읽어 검증·미리보기 뒤 복원하고, ID·소유자·내용 해시가 사본과 같음. 사본 없는 ID는 멈춤',
      observed: live.drill },
    { attackId: 'post_restore_retest',
      expected: '복구 뒤 B의 정상 요청(내 목록·복원한 메모 읽기)은 200, 금지 요청(공지 403, 쿼리·본문 owner_id 400, 없는 메모 404, 비로그인 401)은 거부',
      observed: live.retest },
  ];
}

// 9단계: 학생 탐지 함수(src/detect.mjs)에 가상 조회 사건을 넣어 본 결과만 적습니다.
// 실제 반 엔진의 사건 전달·접속 회수는 이 저장소에서 보낼 수 없으므로 미실행으로 남깁니다.
async function detectChecks() {
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
  return [
    { attackId: 'detect_normal_device',
      expected: '평소 네트워크의 정상 기기 다량 조회, 지역만 다른 조회, 처음 보는 네트워크의 적은 조회(20건)는 모두 observe(회수 제안 없음)',
      observed: `가상 사건 탐지 결과 정상 기기 200건 ${said(normal)} / 지역만 다름 200건 ${said(regionOnly)} / 처음 보는 네트워크 20건 ${said(fewUnusual)}` },
    { attackId: 'detect_doppelganger_burst',
      expected: '같은 사용자의 다른 기기가 처음 보는 네트워크에서 10분 안에 120건을 넘게 조회하면 그 기기 하나만 propose_revocation · burst_read, 정상 기기는 유지',
      observed: `정상 기기 50건 + 다른 기기 150건 탐지 결과 ${said(doppel)}` },
    { attackId: 'live_revocation',
      expected: '반 엔진이 회수 제안을 집행해 의심 기기 접속이 끊기고 걸린 시간이 측정됨',
      observed: '미실행: 이 저장소에는 엔진의 사건 전달·회수 집행 경로가 없음. 실제 회수와 시간은 심판이 확인' },
  ];
}

export async function runAttackChecks(config) {
  const app = appUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 1) {
    const response = await fetch(new URL('/data.json', app), {
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

  if (config.step >= 5 && config.step <= 10) {
    // 실제로 보낸 요청의 결과만 적습니다. 메모 본문·토큰·이메일은 기록하지 않습니다.
    if (typeof config.originalApiUrl !== 'string' || !config.originalApiUrl.startsWith('https://')) {
      throw new Error('aleph.config.json의 originalApiUrl을 먼저 넣어 주세요.');
    }
    const noLogin = await anonymousGet(app, '/api/notes');
    const forged = await anonymousGet(app, '/api/notes', {
      Authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.forged',
    });
    const direct = await anonDataApi(config.originalApiUrl);
    const page = await fetch(new URL('/', app), {
      redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000),
    });
    const html = await page.text();
    const keyInPage = /sb_publishable_|sb_secret_|supabase\.co/iu.test(html);
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
      { attackId: 'anon_original_api_read',
        expected: 'anon 키로 originalApiUrl(원본 자료 경로)을 직접 불러도 메모 없음',
        observed: `anon 키 원본 직접 조회 결과 HTTP ${direct.status}${direct.code ? ` ${direct.code}` : ''}, ${direct.rows === null ? '행 없음' : `${direct.rows}행`}${directBlocked ? ' (막힘)' : ' (노출됨)'}` },
      { attackId: 'browser_key_exposure',
        expected: '첫 화면 코드에 자료 저장소 주소·공개 키가 없음',
        observed: `첫 화면 HTTP ${page.status}, 저장소 주소·키 문자열 ${keyInPage ? '발견됨' : '없음'}` },
      { attackId: 'cross_user_note_read',
        expected: 'B 로그인으로 A 메모 id를 GET·PUT·DELETE하면 404로 거부되고 A 메모는 그대로',
        observed: '미실행: 계정 비밀번호를 코드에 넣지 않아 이 스크립트로는 보내지 않음. 학생이 B 창에서 A 메모가 안 보이는 것을 직접 확인' },
      ...(config.step >= 6 ? await deviceChecks() : []),
      ...(config.step >= 7 ? await stepUpChecks({ compact: config.step >= 9 }) : []),
      ...(config.step >= 8 ? await zoneChecks(app, { compact: config.step >= 10 }) : []),
      ...(config.step >= 9 ? await detectChecks() : []),
      ...(config.step >= 10 ? await restoreChecks(app, config) : []),
    ];
  }

  throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
}
