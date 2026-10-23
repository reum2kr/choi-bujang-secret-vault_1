// 학생 구현(13~19). createElement·textContent만 사용, 호출마다 새 요소(이전 값 미보관). 자동 재요청·POST 없음.
const DEVICE_STATUS = { compliant: ['보안 기준 충족', 1], noncompliant: ['보안 기준 미충족'], unknown: ['확인 불가'] };
const SESSION_STATUS = { active: ['활성', 1], expired: ['만료'], revoked: ['철회됨'], unknown: ['확인 불가'] };
const ACCESS_STATE = { allowed: ['접근 허용됨', 1], denied: ['접근 거부됨'], unknown: ['확인 불가'] };
const MODE_TEXT = { connected: '실제 연결', demo: '예제 자료(실제 연결 아님)', disconnected: '연결 없음', unknown: '확인 불가' };
const UNVERIFIED = new Set(['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED']);
const has = (o, k) => Object.hasOwn(o, k);

function node(tag, text, attrs = {}) {
const e = document.createElement(tag);
if (text != null) e.textContent = String(text);
for (const [k, v] of Object.entries(attrs)) if (v != null) k === 'className' ? (e.className = v) : e.setAttribute(k, String(v));
return e;
}
const textOf = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
const p = (text, cls, attrs = {}) => node('p', text, { className: cls, ...attrs });

function statusText(table, value) {
const raw = textOf(value) ?? 'unknown';
const [label, normal] = has(table, raw) ? table[raw] : ['확인 불가'];
return { raw, normal: !!normal, text: `${label} (${raw})${normal ? '' : ' · 주의'}` };
}
function badge(table, value, kind) {
const s = statusText(table, value);
return node('span', s.text, { className: `tag ${s.normal ? 'state-ok' : 'state-error'}`, 'data-student-status': s.raw });
}
function modeLine(r, what) {
const m = textOf(r?.mode);
return m ? p(`${what} 자료 상태: ${MODE_TEXT[m] ?? MODE_TEXT.unknown} (${m})`, m === 'connected' ? 'muted' : 'tag tag-demo') : null;
}
const errCode = (r) => textOf(r?.error?.code);
const errMsg = (r) => safeText(r?.error?.message, '서버 메시지 없음');
const codeTail = (c) => (c ? ` [${safeCode(c)}]` : '');
const isTimeout = (c) => /TIMEOUT$/u.test(c ?? '');
function notReady(r, what, failWord = '연결 실패') {
const st = r?.status;
if (st === 'loading') return p(`${what}: 불러오는 중`, 'state state-loading', { role: 'status' });
if (st === 'error') {
const c = errCode(r);
const head = isTimeout(c) ? `${failWord}(시간 초과)` : UNVERIFIED.has(c) ? `${failWord}(확인 불가 · 응답 형식 불일치)` : failWord;
return p(`${what}: ${head}: ${errMsg(r)}${codeTail(c)}`, 'state state-error', { role: 'alert' });
}
if (st !== 'ok') return p(`${what}: 확인 불가 (상태값 ${textOf(st) ?? '없음'})`, 'state state-empty');
return null;
}
function nameAndId(label, id) {
const l = textOf(label), i = textOf(id);
return l && i ? `${l} (ID ${i})` : l ?? (i ? `ID ${i}` : '이름·ID 없음');
}
function row(dl, term, ...vals) {
const dd = node('dd');
for (const v of vals) dd.append(typeof v === 'string' ? document.createTextNode(v) : v);
dl.append(node('dt', term), dd);
}
function section(title) { const s = node('section'); s.append(node('h3', title)); return s; }
function listSection(r, { part, title, table, kind, empty, describe, currentId, note, failWord, extra }) {
const s = section(title);
if (note) s.append(p(note, 'muted'));
const m = modeLine(r, title); if (m) s.append(m);
const nr = notReady(r, title, failWord);
if (nr) { s.append(nr); if (r?.status === 'error' && extra) s.append(extra); return s; }
const items = Array.isArray(r.data) ? r.data : [];
if (!items.length) { s.append(p(empty, 'state state-empty', { role: 'status' })); return s; }
const ul = node('ul', null, { className: 'plain-list' });
for (const it of items) {
const name = node('span', describe(it), { className: 'item-title' });
if (currentId && textOf(it?.id) === currentId) name.append(' · 현재 로그인');
const li = node('li', null, { [`data-student-${part}-id`]: textOf(it?.id) ?? '' });
li.append(name, badge(table, it?.status, kind));
ul.append(li);
}
s.append(ul);
return s;
}
const devDesc = (d) => nameAndId(d?.label, d?.id);
const sesDesc = (x) => nameAndId(null, x?.id);

// ---------- 13단계 · renderIdentity({ me, devices, sessions }) ----------
function renderIdentityView(input) {
const { me, devices, sessions } = input ?? {};
const root = node('div', null, { 'data-student': 'identity' });
const s = section('현재 로그인');
const m = modeLine(me, '로그인 정보'); if (m) s.append(m);
const nr = notReady(me, '로그인 정보');
if (nr) s.append(nr); // 오류면 이전 사용자 값 없음
else {
const { user, device, session } = me.data ?? {};
const dl = node('dl');
row(dl, '사용자', node('span', nameAndId(user?.label, user?.id)));
row(dl, '현재 기기', node('span', devDesc(device)), ' · ', badge(DEVICE_STATUS, device?.status, 'device'));
row(dl, '로그인 세션', node('span', sesDesc(session)), ' · ', badge(SESSION_STATUS, session?.status, 'session'));
s.append(dl);
}
const ok = me?.status === 'ok';
root.append(s,
listSection(devices, { part: 'devices', title: '본인 기기', table: DEVICE_STATUS, kind: 'device', empty: '표시할 기기가 없습니다.', describe: devDesc, currentId: ok ? textOf(me.data?.device?.id) : null }),
listSection(sessions, { part: 'sessions', title: '로그인 세션', table: SESSION_STATUS, kind: 'session', empty: '표시할 세션이 없습니다.', describe: sesDesc, currentId: ok ? textOf(me.data?.session?.id) : null }),
p('기기 보안 상태 표시는 악성코드 검사나 치료 기능이 아닙니다.', 'muted'));
return root;
}

// ---------- 14단계 · renderDecision({ status, mode, data?, error?, appId }) ----------
const DECISIONS = {
allow: ['접근 허용', '정책상 허용이며 실제 접속 성공을 보장하지 않습니다.'],
deny: ['접근 거부', '정책상 거부됐습니다.'],
challenge: ['추가 인증 또는 확인 필요', '이 앱이 추가 인증을 대신 수행하지 않습니다.'],
unknown: ['판정 확인 불가', '허용으로 보지 않습니다.'],
};
function timeText(v, none = '시각 정보 없음') {
const raw = textOf(v); if (!raw) return none;
const d = new Date(raw);
return Number.isNaN(d.getTime()) ? raw : `${d.toLocaleString('ko-KR')} (${raw})`;
}
function renderDecisionView(input) {
const st = input?.status, data = input?.data ?? null, asked = textOf(input?.appId);
const app = textOf(data?.appId) ?? asked;
const root = node('div', null, { 'data-student': 'decision' });
root.append(p(`대상 업무 앱: ${app ? `ID ${app}` : '선택한 앱 없음'}`, null));
const m = modeLine(input, '판정'); if (m) root.append(m);
const box = (key, text, kind, role = 'status') => { root.setAttribute('data-student-decision', key); root.append(p(text, `state state-${kind}`, { role })); return root; };
if (st == null || st === 'idle') return box('none', '요청 전: 앱을 골라 접속을 요청하세요. 아직 받은 판정이 없습니다.', 'empty');
if (st === 'loading') return box('pending', '판정 확인 중: 아직 판정이 아니며 허용되지 않음 상태입니다.', 'loading');
if (st === 'error') {
const c = errCode(input), unv = UNVERIFIED.has(c);
box(unv ? 'unverified' : 'request-failed', `${unv ? '확인 불가(응답 형식 불일치)' : '요청 실패'}: ${errMsg(input)}${codeTail(c)}`, 'error', 'alert');
root.append(p('접근 거부(deny) 판정이 아니며 허용도 아닙니다. 다시 요청은 직접 누르세요.', 'muted'));
return root;
}
if (st !== 'ok') return box('unknown', `판정 확인 불가(unknown) · 받은 상태값 ${textOf(st) ?? '없음'} · 허용되지 않음`, 'empty');
const raw = textOf(data?.decision), got = textOf(data?.appId);
const same = !asked || !got || got === asked;
const key = raw && has(DECISIONS, raw) && same ? raw : 'unknown';
let head = `${DECISIONS[key][0]}(${key})`;
if (key === 'unknown' && raw && raw !== 'unknown') head += ` · 받은 값 ${raw}`;
if (!same) head += ' · 요청한 앱과 판정 대상 앱이 다름';
box(key, key === 'allow' ? head : `${head} · 허용되지 않음`, key === 'allow' ? 'ok' : key === 'deny' ? 'error' : 'empty');
root.append(p(DECISIONS[key][1], 'muted'));
const dl = node('dl');
row(dl, '판정 이유', node('span', textOf(data?.reason) ?? '판정 이유 정보 없음'));
row(dl, '판정 시각', node('span', timeText(data?.checkedAt, '판정 시각 정보 없음')));
root.append(dl);
return root;
}

// ---------- 15단계 · renderEvents({ status, mode, data?, error? }) + 16단계 미지원 조치 ----------
const EVENT_KIND = { access: '접속 기록', xdr: 'XDR 경보' };
const ALL = 'all', NO_APP = '';
const kindText = (k) => { const r = textOf(k) ?? 'unknown'; return `${EVENT_KIND[r] ?? '확인 불가'}(${r})`; };
const appText = (a) => (textOf(a) ? `앱 ${textOf(a)}` : '앱 확인 불가(appId 없음)');
const atMs = (at) => { const t = Date.parse(at); return Number.isFinite(t) ? t : -Infinity; };
const keyOf = { kind: (e) => textOf(e?.kind) ?? 'unknown', app: (e) => textOf(e?.appId) ?? NO_APP, access: (e) => textOf(e?.state?.access) ?? 'unknown' };

function filterSelect(id, label, options, onChange) {
const wrap = node('div', null, { className: 'student-filter' });
const sel = node('select', null, { id, 'aria-label': label, 'data-student-filter': label });
for (const [v, t] of [[ALL, '전체(all)'], ...options]) { const o = node('option', t); o.value = v; sel.append(o); }
sel.addEventListener('change', () => onChange(sel.value));
wrap.append(node('label', label, { for: id }), sel);
return wrap;
}
function textRows(title, rows) {
const s = node('section'); s.append(node('h4', title));
const list = Array.isArray(rows) ? rows : [];
if (!list.length) s.append(p(`${title} 항목 없음`, 'muted'));
else { const ul = node('ul', null, { className: 'plain-list' }); for (const it of list) ul.append(node('li', `${textOf(it?.id) ?? 'ID 없음'}: ${textOf(it?.text) ?? '내용 없음'}`)); s.append(ul); }
return s;
}
function eventDetail(ev) {
const id = textOf(ev?.id) ?? '';
const d = node('section', null, { 'data-student-event-detail': id, 'aria-label': `${id} 상세 내용`, tabindex: '-1' });
d.append(node('h4', `${id} 상세`));
const dl = node('dl');
row(dl, '사건 ID', id || 'ID 없음');
row(dl, '종류', kindText(ev?.kind));
row(dl, '시각', timeText(ev?.at));
row(dl, '업무 앱(appId)', textOf(ev?.appId) ?? '확인 불가(appId 없음)');
row(dl, '요약', textOf(ev?.summary) ?? '요약 없음');
const sd = node('dl', null, { 'data-student-event-state': id });
row(sd, '접속 상태(state.access)', badge(ACCESS_STATE, ev?.state?.access, 'access'));
row(sd, '세션 상태(state.session)', badge(SESSION_STATUS, ev?.state?.session, 'session'));
row(sd, '기기 상태(state.device)', badge(DEVICE_STATUS, ev?.state?.device, 'device'));
d.append(dl, textRows('근거(evidence)', ev?.evidence), textRows('규칙(rules)', ev?.rules), node('h4', '상태(state)'), sd);
const acts = Array.isArray(ev?.supportedActions) ? ev.supportedActions.map(textOf).filter(Boolean) : [];
if (!acts.length) { d.append(p('지원되는 조치 없음(supportedActions 비어 있음)', 'muted')); return d; }
const noteId = `student-unsupported-${id}`;
const box = node('section', null, { 'data-student-unsupported-actions': id });
box.append(node('h4', '조치(아직 지원하지 않음)'));
for (const a of acts) {
const b = node('button', `${a} 미지원`, { type: 'button', className: 'btn', 'aria-label': `${a} 미지원`, 'aria-describedby': noteId, 'data-student-unsupported-action': a });
b.disabled = true;
box.append(b);
}
box.append(p('조치 실행 연결은 준비 중입니다(요청 없음, 미실행).', 'muted', { id: noteId }));
d.append(box);
return d;
}
function renderEventsView(input) {
const root = node('div', null, { 'data-student': 'events' });
root.append(p('관측 범위: 본인 최근 기록 최대 40건(저장된 XDR 경보만).', 'muted'));
const m = modeLine(input, '보안 기록'); if (m) root.append(m);
const st = input?.status;
if (st === 'loading') { root.append(p('보안 기록: 불러오는 중', 'state state-loading', { role: 'status' })); return root; }
if (st === 'error') {
const c = errCode(input);
root.append(p(`기록을 불러오지 못했습니다${UNVERIFIED.has(c) ? '(확인 불가 · 응답 형식 불일치)' : ''}: ${errMsg(input)}${codeTail(c)}`, 'state state-error', { role: 'alert' }),
p('이전 목록은 표시하지 않습니다(빈 목록과 다름).', 'muted'));
return root;
}
if (st !== 'ok' || !Array.isArray(input?.data)) { root.append(p(`보안 기록: 확인 불가 (상태값 ${textOf(st) ?? '없음'})`, 'state state-empty')); return root; }
const events = [...input.data].sort((a, b) => atMs(b?.at) - atMs(a?.at) || String(a?.id).localeCompare(String(b?.id)));
if (!events.length) { root.append(p('표시할 기록이 없습니다.', 'state state-empty', { role: 'status' })); return root; }

const filters = { kind: ALL, app: ALL, access: ALL };
let selected = null;
const values = (k) => [...new Set(events.map(keyOf[k]))].sort();
const count = p(null, null, { 'data-student-events-count': '', role: 'status' });
const listArea = node('div'), detailArea = node('div', null, { 'aria-live': 'polite' });
const matches = (e) => Object.keys(filters).every((k) => filters[k] === ALL || keyOf[k](e) === filters[k]);
function draw() {
const shown = events.filter(matches);
count.textContent = `표시 ${shown.length}건 / 받은 기록 ${events.length}건 (최신순)`;
if (!shown.length) listArea.replaceChildren(p('필터 조건에 맞는 기록이 없습니다.', 'state state-empty'));
else {
const ul = node('ul', null, { className: 'plain-list', 'aria-label': '보안 기록 목록' });
for (const ev of shown) {
const id = textOf(ev?.id) ?? '';
const li = node('li', null, { 'data-student-event-id': id });
const b = node('button', `${id} 상세`, { type: 'button', className: 'btn', 'aria-label': `${id} 상세`, 'aria-pressed': String(selected === id) });
b.addEventListener('click', () => { selected = id; draw(); detailArea.querySelector('[data-student-event-detail]')?.focus(); });
li.append(node('span', `${id} · ${timeText(ev?.at)} · ${kindText(ev?.kind)} · ${appText(ev?.appId)} · ${textOf(ev?.summary) ?? '요약 없음'}`, { className: 'item-title' }), b);
ul.append(li);
}
listArea.replaceChildren(ul);
}
const ev = shown.find((e) => textOf(e?.id) === selected);
if (!ev) selected = null;
detailArea.replaceChildren(ev ? eventDetail(ev) : p('상세를 볼 기록의 「상세」 버튼을 누르세요.', 'muted'));
}
const set = (k) => (v) => { filters[k] = v; draw(); };
const controls = node('div', null, { className: 'student-filters' });
controls.append(
filterSelect('student-filter-kind', '기록 종류', values('kind').map((k) => [k, kindText(k)]), set('kind')),
filterSelect('student-filter-app', '업무 앱', values('app').map((a) => [a, a === NO_APP ? '앱 확인 불가(appId 없음)' : a]), set('app')),
filterSelect('student-filter-access', '접속 상태', values('access').map((a) => [a, statusText(ACCESS_STATE, a).text]), set('access')));
root.append(controls, count, listArea, detailArea);
draw();
return root;
}

// ---------- 16단계 · renderStatus({ devices, sessions, notifications, diagnostics, mode }) ----------
const RESOURCE_NAMES = { me: '로그인 정보', devices: '등록 기기', sessions: '세션', events: '보안 기록', apps: '업무 앱', access: '접속 판정', diagnostics: '도움정보' };
const RETRY = '다시 시도는 위쪽 「다시 불러오기」 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.';
const SECRET_LIKE = [/\bBearer\s+\S+/giu, /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{4,}/gu, /\b(?:sk|pk|sb_secret|sb_publishable|ghp|gho|xox[abp])[_-][\w-]{8,}/giu,
/\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+/giu, /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu];
const safeText = (v, fb) => { const t = textOf(v); return t ? SECRET_LIKE.reduce((s, re) => s.replace(re, '[가림]'), t) : fb; };
const safeCode = (v) => { const t = textOf(v); return t && /^[\w.:-]{1,64}$/u.test(t) ? t : '확인 불가'; };
const DIAG_KEYS = [['requestId', (d) => d?.requestId], ['component', (d) => d?.component], ['version', (d) => d?.version],
['checkedAt', (d) => d?.checkedAt], ['engine.mode', (d) => d?.engine?.mode], ['engine.code', (d) => d?.engine?.code]];

function notificationsView(list) {
const s = section('알림');
const items = Array.isArray(list) ? list : [];
if (!items.length) { s.append(p('주의할 알림이 없습니다.', 'state state-ok', { role: 'status' })); return s; }
s.append(p(`주의할 알림 ${items.length}건`, null));
const ul = node('ul', null, { className: 'plain-list' });
for (const n of items) {
const r = textOf(n?.resource);
ul.append(node('li', `${r ? `${RESOURCE_NAMES[r] ?? '기타 자료'}(${safeCode(r)})` : '자료 확인 불가'} · 코드 ${safeCode(n?.code)} · ${safeText(n?.message, '메시지 없음')}`));
}
s.append(ul);
return s;
}
function diagnosticsView(diag) {
const s = section('도움정보(진단)');
const ok = diag?.status === 'ok' && diag.data && typeof diag.data === 'object';
const fields = ok ? DIAG_KEYS.map(([k, f]) => [k, safeText(f(diag.data), '없음')]) : null;
if (ok) { const dl = node('dl', null, { 'data-student-diagnostics': '' }); for (const [k, v] of fields) row(dl, k, v); s.append(dl); }
else if (diag?.status === 'loading' || diag?.status === 'error') {
s.append(notReady(diag, '도움정보', '조회 실패'));
if (diag.status === 'error') s.append(p('다시 시도는 위쪽 「도움정보 불러오기」를 직접 누르세요.', 'muted'));
} else s.append(p('도움정보를 아직 불러오지 않았습니다(위쪽 「도움정보 불러오기」).', 'state state-empty'));
const help = p('「도움정보 복사」: 진단 값 6개만, 누를 때만 복사(전송 없음, 비밀 제외).', 'muted', { id: 'student-diag-help' });
const result = p(ok ? null : '복사할 도움정보가 없습니다. 먼저 도움정보를 불러오세요.', null, { role: 'status' });
const b = node('button', '도움정보 복사', { type: 'button', className: 'btn', 'aria-describedby': 'student-diag-help' });
b.disabled = !ok;
b.addEventListener('click', async () => {
if (!fields) return;
const text = fields.map(([k, v]) => `${k}: ${v}`).join('\n');
try { await navigator.clipboard.writeText(text); result.textContent = '도움정보(진단 값 6개)를 클립보드에 복사했습니다.'; }
catch { result.replaceChildren('자동 복사 불가: 아래 내용을 Ctrl+C로 복사하세요.', node('pre', text, { tabindex: '0' })); }
});
s.append(help, b, result);
return s;
}
function renderStatusView(input) {
const root = node('div', null, { 'data-student': 'status' });
const m = textOf(input?.mode);
if (m) root.append(p(`전체 연결 상태: ${MODE_TEXT[m] ?? MODE_TEXT.unknown} (${m})`, m === 'connected' ? 'muted' : 'tag tag-demo'));
const retry = () => p(RETRY, 'muted');
root.append(
listSection(input?.devices, { part: 'devices', title: '등록 기기', table: DEVICE_STATUS, kind: 'device', empty: '등록된 기기가 없습니다.', describe: devDesc,
note: '내 등록 기기(최대 100개), 현재 기기가 맨 앞', failWord: '조회 실패', extra: retry() }),
listSection(input?.sessions, { part: 'sessions', title: '현재 세션', table: SESSION_STATUS, kind: 'session', empty: '현재 연결 없음: 지금 검증된 세션이 없습니다.', describe: sesDesc,
note: '지금 검증된 연결 하나만 표시합니다. 지난 세션 목록이 아닙니다.', failWord: '조회 실패', extra: retry() }),
notificationsView(input?.notifications),
diagnosticsView(input?.diagnostics));
return root;
}

// ---------- 17단계 · renderAiConnection({ status, mode, data?, error?, checkedAt, explanationAccepted }) ----------
const AI_ERRORS = [
[['ON_AI_PROVISIONING_PENDING', 'ON_AI_AUTHORIZATION_CHANGED', 'AI_REQUEST_UNVERIFIED'], '권한 준비 중·확인 불가', '담당자에게 계정 연결·앱 권한 확인을 요청하세요(학생 잘못 아님).'],
[['WB_CLCO_AUTH_REQUIRED'], '인증 실패', '계정 연결을 다시 확인하고 담당자에게 확인하세요.'],
[['WB_CLCO_ACCESS_BLOCKED', 'SUBJECT_SCOPE_UNVERIFIED'], '접근 제한', '계정 연결과 앱 권한을 담당자에게 확인하세요.'],
[['WB_CLCO_COHORT_BUDGET_EXHAUSTED', 'WB_CLCO_LIMIT_REACHED'], '사용량·이용 한도', '담당자에게 확인하세요.'],
[['WB_CLCO_SESSION_CLOSED'], '이용 시간 아님', '이용 시간을 확인하세요.'],
[['WB_CLCO_RATE_LIMITED', 'WB_CLCO_TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT', 'TIMEOUT', 'NETWORK_ERROR'], '요청 제한·시간 초과·네트워크', '잠시 뒤 직접 다시 점검하세요.'],
[['CANCELLED', 'WB_CLCO_CANCELLED', 'REQUEST_CANCELLED'], '취소됨', '이전 결과는 현재 결과가 아닙니다.'],
[['ON_AI_MODEL_LIST_EMPTY', 'MODEL_NOT_CONFIGURED'], '쓸 수 있는 모델 없음', '담당자에게 모델 허용 설정을 확인하세요.'],
];
const AUDIENCE = { test: '시험 연결 점검(test) · 실제 게이트 수용 아님', verified: '앱 권한 확인 후 점검(verified)' };
function renderAiConnectionView(input) {
const root = node('div', null, { 'data-student': 'ai-connection' });
const st = input?.status;
root.append(p('앱 서버를 통한 AI 연결 점검(사건 설명 실행과 별개)', 'muted'));
const m = modeLine(input, 'AI 연결'); if (m) root.append(m);
const manual = p('다시 점검은 「현재 API 연결 점검」 버튼을 직접 누르세요. 자동으로 다시 점검하지 않습니다.', 'muted');
if (st == null || st === 'idle') { root.append(p('AI 연결 점검 전: 표시할 점검 결과가 없습니다.', 'state state-empty', { role: 'status' }), manual); return root; }
if (st === 'loading') { root.append(p('AI 연결 점검 중: 취소하면 늦게 온 응답은 표시하지 않습니다.', 'state state-loading', { role: 'status' })); return root; }
if (st === 'error') {
const c = errCode(input) ?? 'AI_REQUEST_UNVERIFIED';
const [, kind, guide] = AI_ERRORS.find(([codes]) => codes.includes(c)) ?? AI_ERRORS[0];
root.append(p(`AI 연결 점검 실패 · ${kind}: ${safeCode(c)} · ${errMsg(input)}`, 'state state-error', { role: 'alert' }), p(guide, 'muted'), manual);
return root;
}
const d = input?.data ?? {}, aud = textOf(d.audienceAuthorization);
if (st !== 'ok' || !has(AUDIENCE, aud) || d.transportChecked !== true) {
root.append(p('AI 연결 점검 결과 확인 불가(연결 완료 아님)', 'state state-empty'), manual);
return root;
}
root.append(p(AUDIENCE[aud], 'state state-ok', { role: 'status', 'data-student-ai-audience': aud }));
const dl = node('dl');
row(dl, '응답 모델 수(modelCount)', Number.isInteger(d.modelCount) ? String(d.modelCount) : '확인 불가');
row(dl, '점검 시각(checkedAt)', timeText(input?.checkedAt));
row(dl, '전송 확인(transportChecked)', 'true');
root.append(dl, p(`사건 설명은 아직 실행하지 않았습니다(explanationAccepted: ${input?.explanationAccepted === true}). 모델 목록 응답은 사건 설명 성공이 아닙니다.`, 'muted'), manual);
return root;
}

// ---------- 18단계 · renderExplanation({ event, explanation, checkedAt }) ----------
// 근거 ID는 현재 event.evidence 와 대조, 불일치는 쓰지 않음. 실행 버튼 없음.
const EXPLAIN_FAIL = { ON_AI_INVALID_INPUT: '근거 부족: 설명에 필요한 사건 근거·규칙을 확인할 수 없습니다.', ON_AI_INVALID_OUTPUT: '근거 불일치·형식 확인 불가·실행됨 응답은 쓸 수 없습니다.', CANCELLED: '요청이 취소됐습니다. 이전 설명은 현재 결과가 아닙니다.' };
const STATE_PARTS = [['access', '접속'], ['session', '세션'], ['device', '기기']];
function renderExplanationView(input) {
const ev = input?.event ?? null, x = input?.explanation ?? {}, id = textOf(ev?.id);
const root = node('div', null, { 'data-student': 'explanation' });
const fail = (head, reason, c) => { root.append(p(`${head}${c ? `: ${safeCode(c)}` : ''}${x.status === 'error' ? ` · ${errMsg(x)}` : ''}`, 'state state-error', { role: 'alert' }), p(reason, 'muted'), p('기록은 그대로입니다(과제 실패 아님, 판정·기록은 계속 동작).', 'muted')); return root; };
if (x.status === 'error') { // event 가 없어도 실패 이유를 먼저 보여 줍니다.
if (id) root.append(p(`사건 ID: ${id}`));
const c = errCode(x);
return fail('AI 설명 실패', EXPLAIN_FAIL[c] ?? (c?.endsWith('CANCELLED') ? EXPLAIN_FAIL.CANCELLED : 'AI 연결 또는 응답 문제입니다. 다시 요청은 직접 누르세요.'), c);
}
if (!ev || !id) { root.append(p('보안 기록에서 기록을 먼저 고르세요.', 'state state-empty', { role: 'status' })); return root; }
root.append(p(`사건 ID: ${id}`));
if (x.status === 'loading') { root.append(p('AI 설명 요청 중', 'state state-loading', { role: 'status' })); return root; }
if (x.status !== 'ok') { root.append(p('아직 AI 설명을 요청하지 않았습니다.', 'state state-empty')); return root; }
const d = x.data ?? {};
if (d.executed !== false || d.requiresHumanConfirmation !== true) return fail('AI 설명을 쓸 수 없음', '실행됨 응답이나 사람 확인 표시 없는 설명은 쓸 수 없습니다.', 'ON_AI_INVALID_OUTPUT');
const evidence = new Map((Array.isArray(ev.evidence) ? ev.evidence : []).map((e) => [textOf(e?.id), textOf(e?.text)]));
const ids = Array.isArray(d.evidenceIds) ? d.evidenceIds.map(textOf) : [];
const proposals = Array.isArray(d.proposals) ? d.proposals : [];
const actions = Array.isArray(ev.supportedActions) ? ev.supportedActions.map(textOf).filter(Boolean) : [];
const missing = [...ids, ...proposals.flatMap((q) => (Array.isArray(q?.evidenceIds) ? q.evidenceIds.map(textOf) : [null]))].filter((e) => !e || !evidence.has(e));
if (!ids.length) return fail('AI 설명을 쓸 수 없음', '근거 부족: 인용한 근거 ID가 없습니다.', 'ON_AI_INVALID_OUTPUT');
if (missing.length) return fail('AI 설명을 쓸 수 없음', `근거가 맞지 않음: 이 기록(${id})에 없는 근거 ID ${missing.map((e) => e ?? '없음').join(', ')}`, 'ON_AI_INVALID_OUTPUT');
const bad = proposals.find((q) => !actions.includes(textOf(q?.action)));
if (bad) return fail('AI 설명을 쓸 수 없음', `지원하지 않는 조치 제안: ${safeText(bad?.action, '없음')}`, 'ON_AI_INVALID_OUTPUT');
root.setAttribute('data-student-explanation-event', id);
const list = (title, items) => { const ul = node('ul', null, { className: 'plain-list' }); for (const t of items) ul.append(node('li', t)); root.append(node('h4', title), ul); };
root.append(node('h4', 'AI 설명(참고용)'), p(safeText(d.summary, '요약 없음')), p(`설명 시각: ${timeText(input?.checkedAt)}`, 'muted'));
list('인용한 근거', ids.map((e) => `${e} — ${evidence.get(e) ?? '근거 글 없음'}`));
const rules = Array.isArray(ev.rules) ? ev.rules : [];
list('규칙', rules.length ? rules.map((r) => `${textOf(r?.id) ?? 'ID 없음'} — ${textOf(r?.text) ?? '규칙 글 없음'}`) : ['규칙 항목 없음']);
const unknown = STATE_PARTS.filter(([k]) => (textOf(ev.state?.[k]) ?? 'unknown') === 'unknown').map(([, n]) => `${n}: 확인 불가(unknown)`);
list('확인 불가 상태(정상·안전으로 보지 않음)', unknown.length ? unknown : ['없음']);
list('AI 제안', proposals.length ? proposals.map((q) => `${textOf(q.action)} — ${safeText(q.reason, '이유 없음')} (근거 ${q.evidenceIds.map(textOf).join(', ')}) · 사람 확인이 필요하며 실행되지 않았습니다`)
: [actions.length ? 'AI가 제안한 조치가 없습니다.' : '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).']);
root.append(p('설명·제안만으로 보안 조치는 실행되지 않습니다.', 'muted'));
return root;
}

// ---------- 19단계 · renderAction({ status, event, actionId, target, receipt, observation, message, confirmationExpiresAt, error }) ----------
// 버튼·POST·확인 티켓 없음. ACK는 효과 아님, succeeded+effectApplied===true 만 효과 확인.
const ACTION_TEXT = {
idle: ['아직 미실행(idle)', 'empty'], loading: ['조치 준비 또는 결과 조회 중(loading) · 완료 아님', 'loading'],
prepared: ['준비됨·미실행(prepared): 사람이 대상·조치를 확인해야 전달됩니다', 'empty'],
executing: ['서버에 전달 중(executing): 결과가 아직 없습니다 · 완료 아님', 'loading'],
pending: ['서버 접수·처리 중(pending): ACK일 뿐 효과 미확인', 'loading'],
succeeded: ['효과 확인(succeeded)', 'ok'], denied: ['거절(denied): 연동 시스템이 조치를 거절했습니다', 'error'],
failed: ['실패(failed): 연동 시스템 처리에 실패했습니다', 'error'],
unknown: ['결과 불명(unknown): 성공으로도 효과 없음으로도 판단하지 마세요. 제공 화면의 「원천 결과만 재조회」를 직접 누르세요', 'empty'],
expired: ['확인 기한 지남(expired): 조치를 다시 준비하세요', 'empty'],
error: ['요청 처리 안 됨(error)', 'error'],
};
function renderActionView(input) {
const a = input ?? {}, ev = a.event ?? null, r = a.receipt ?? null, o = a.observation ?? null;
const eid = textOf(ev?.id), req = textOf(r?.requestId);
const root = node('div', null, { 'data-student': 'action' });
root.append(p('AI 제안은 실행이 아닙니다(사람 확인·전달·재조회는 제공 화면 버튼).', 'muted'));
let st = textOf(a.status) ?? 'unknown';
if (!has(ACTION_TEXT, st)) st = 'unknown';
const mismatch = r && ((textOf(r.eventId) && eid && textOf(r.eventId) !== eid) || (textOf(r.actionId) && textOf(a.actionId) && textOf(r.actionId) !== textOf(a.actionId)));
if (st === 'succeeded' && (o?.effectApplied !== true || mismatch)) st = 'unknown';
if (mismatch && ['pending', 'prepared'].includes(st)) st = 'unknown';
const [text, kind] = ACTION_TEXT[st];
root.append(p(st === 'error' ? `${text}: ${safeCode(errCode(a))} · ${errMsg(a)}` : text, `state state-${kind}`, { role: kind === 'error' ? 'alert' : 'status' }));
if (mismatch) root.append(p('현재 사건·조치와 맞지 않아 결과 불명입니다.', 'muted'));
if (a.error && st !== 'error') root.append(p(`${safeCode(errCode(a))}: ${errMsg(a)}`, 'muted'));
if (['denied', 'failed'].includes(st) || (textOf(a.message) && st !== 'error')) { const m = safeText(a.message, null); if (m) root.append(p(`메시지: ${m}`, 'muted')); }
if (st === 'idle' || !ev) {
if (!ev) root.append(p('지원 조치가 없어(supportedActions 빈 배열) 조치 준비 버튼이 없는 것이 정상입니다.', 'muted'));
return root;
}
root.setAttribute('data-student-action-event', eid ?? '');
if (req) root.setAttribute('data-student-action-request', req);
const dl = node('dl');
const add = (k, v) => { const t = v == null ? null : String(v); if (t !== null && t !== '') row(dl, k, t); };
add('사건 ID(event.id)', eid);
add('근거 ID', (Array.isArray(ev.evidence) ? ev.evidence : []).map((e) => textOf(e?.id)).filter(Boolean).join(', '));
add('조치(actionId)', textOf(a.actionId));
add('실제 대상(target.id)', textOf(a.target?.id));
add('대상 세대(target.generation)', Number.isSafeInteger(a.target?.generation) ? a.target.generation : null);
if (st === 'prepared') add('확인 기한', timeText(a.confirmationExpiresAt));
add('requestId', req);
add('receiptId', textOf(r?.receiptId));
add('version', Number.isSafeInteger(r?.version) ? r.version : null);
if (r && typeof r.replayed === 'boolean') add('replayed', r.replayed ? 'true · 기존 접수 결과(중복 실행 없음)' : 'false');
if (r?.superseded === true) add('superseded', 'true · 다른 요청으로 대체됨(결과 불명)');
if (st === 'succeeded') { add('관측 시각(observedAt)', timeText(o.observedAt)); add('effectApplied', 'true'); }
else if (o && typeof o.effectApplied === 'boolean') add('관측(effectApplied)', `${o.effectApplied} · 효과 확인 아님`);
root.append(dl, p('「조치 화면 취소」는 이미 전달된 효과를 되돌리지 않습니다.', 'muted'));
return root;
}

export function createStudentView() {
return {
renderIdentity(input) { return renderIdentityView(input); },
renderDecision(input) { return renderDecisionView(input); },
renderEvents(input) { return renderEventsView(input); },
renderStatus(input) { return renderStatusView(input); },
renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
renderAiConnection(input) { return renderAiConnectionView(input); },
renderExplanation(input) { return renderExplanationView(input); },
renderAction(input) { return renderActionView(input); },
};
}
