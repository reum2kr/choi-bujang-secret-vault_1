// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.

// ---------- 13단계 · renderIdentity: 로그인 사용자·현재 기기·로그인 세션 표시 ----------
// 입력: { me, devices, sessions } — 셋 다 { status, mode, data?, error? } (status: loading·ok·error).
// DOM은 document.createElement와 textContent로만 만들고, 호출할 때마다 새 요소 하나를 돌려줍니다.
// 이전 값을 모듈 변수에 저장하지 않으므로, 다시 불러오기로 새 입력이 오면 이전 사용자·기기·세션 DOM이 통째로 교체되고
// 오류가 오면 이전 사용자 이름이 남지 않습니다.
// 기기 보안 상태 표시는 악성코드 검사나 치료 기능이 아닙니다.

const DEVICE_STATUS = {
  compliant: { text: '보안 기준 충족', normal: true },
  noncompliant: { text: '보안 기준 미충족', normal: false },
  unknown: { text: '확인 불가', normal: false },
};
const SESSION_STATUS = {
  active: { text: '활성', normal: true },
  expired: { text: '만료', normal: false },
  revoked: { text: '철회됨', normal: false },
  unknown: { text: '확인 불가', normal: false },
};
const MODE_TEXT = {
  connected: '실제 연결',
  demo: '예제 자료 · 실제 연결 결과가 아닙니다',
  disconnected: '연결 없음',
  unknown: '확인 불가 · 연결 상태를 확인할 수 없습니다',
};
// 응답 형식이 계약과 다를 때의 오류 코드: 연결 실패가 아니라 확인 불가입니다(정상·빈 목록으로 보지 않음).
const UNVERIFIED_CODES = new Set(['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED']);

function node(tag, text, attrs = {}) {
  const element = document.createElement(tag);
  if (text !== undefined && text !== null) element.textContent = String(text);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === null) continue;
    if (name === 'className') element.className = value;
    else element.setAttribute(name, String(value));
  }
  return element;
}

const textOf = (value) => (typeof value === 'string' && value.trim() ? value.trim() : null);

// 상태값을 한국어 문구와 원래 값(코드)으로 함께 보여 줍니다. 정상이 아닌 값은 색이 아니라 「주의」 글자로도 구분합니다.
function statusText(table, value) {
  const raw = textOf(value) ?? 'unknown';
  const known = Object.hasOwn(table, raw) ? table[raw] : null;
  const label = known ? known.text : '확인 불가';
  return { raw, normal: Boolean(known?.normal), text: `${label} (${raw})${known?.normal ? '' : ' · 주의'}` };
}

function statusBadge(table, value, kind) {
  const s = statusText(table, value);
  return node('span', s.text, {
    className: `tag ${s.normal ? 'state-ok' : 'state-error'}`,
    'data-student-status': s.raw,
    'data-student-status-kind': kind,
  });
}

function modeLine(resource, what) {
  const mode = textOf(resource?.mode);
  if (!mode) return null;
  const text = Object.hasOwn(MODE_TEXT, mode) ? MODE_TEXT[mode] : MODE_TEXT.unknown;
  return node('p', `${what} 자료 상태: ${text} (${mode})`, {
    className: mode === 'connected' ? 'muted' : 'tag tag-demo',
    'data-student-mode': mode,
  });
}

// loading·error 를 글자로 보여 줍니다. 처리하지 못한 상태도 정상으로 보지 않고 확인 불가로 둡니다.
function pendingOrFailure(resource, what) {
  const status = resource?.status;
  if (status === 'loading') {
    return node('p', `${what}: 불러오는 중`, { className: 'state state-loading', role: 'status', 'data-student-state': 'loading' });
  }
  if (status === 'error') {
    const code = textOf(resource.error?.code);
    const message = textOf(resource.error?.message) ?? '서버 메시지 없음';
    const head = code && UNVERIFIED_CODES.has(code) ? '확인 불가(응답 형식 불일치)' : '연결 실패';
    return node('p', `${what}: ${head}: ${message}${code ? ` [${code}]` : ''}`, {
      className: 'state state-error', role: 'alert', 'data-student-state': 'error',
    });
  }
  if (status !== 'ok') {
    return node('p', `${what}: 확인 불가 (상태값 ${textOf(status) ?? '없음'})`, { className: 'state state-empty', 'data-student-state': 'unknown' });
  }
  return null;
}

function nameAndId(label, id) {
  const l = textOf(label);
  const i = textOf(id);
  if (l && i) return `${l} (ID ${i})`;
  return l ?? (i ? `ID ${i}` : '이름·ID 없음');
}

function row(list, term, ...values) {
  list.append(node('dt', term));
  const dd = node('dd');
  for (const value of values) dd.append(typeof value === 'string' ? document.createTextNode(value) : value);
  list.append(dd);
}

// 현재 로그인: 사용자·기기·세션 (me)
function renderMe(me) {
  const section = node('section', null, { 'data-student-identity-part': 'me' });
  section.append(node('h3', '현재 로그인'));
  const mode = modeLine(me, '로그인 정보');
  if (mode) section.append(mode);
  const notReady = pendingOrFailure(me, '로그인 정보');
  if (notReady) {
    // loading·error 일 때는 사용자 이름·기기·세션 값을 하나도 그리지 않습니다(이전 값이 현재 값처럼 남지 않게).
    section.append(notReady);
    return section;
  }
  const { user, device, session } = me.data ?? {};
  const list = node('dl');
  row(list, '사용자', node('span', nameAndId(user?.label, user?.id), { 'data-student-user-id': textOf(user?.id) ?? '' }));
  row(list, '현재 기기', node('span', nameAndId(device?.label, device?.id), { 'data-student-device-id': textOf(device?.id) ?? '' }), ' · ',
    statusBadge(DEVICE_STATUS, device?.status, 'device'));
  row(list, '로그인 세션', node('span', nameAndId(null, session?.id), { 'data-student-session-id': textOf(session?.id) ?? '' }), ' · ',
    statusBadge(SESSION_STATUS, session?.status, 'session'));
  section.append(list);
  return section;
}

// 본인 기기 목록(devices) 또는 세션 목록(sessions)
function renderList(resource, { part, title, table, describe, currentId, empty }) {
  const section = node('section', null, { 'data-student-identity-part': part });
  section.append(node('h3', title));
  const mode = modeLine(resource, title);
  if (mode) section.append(mode);
  const notReady = pendingOrFailure(resource, title);
  if (notReady) {
    section.append(notReady);
    return section;
  }
  const items = Array.isArray(resource.data) ? resource.data : [];
  if (!items.length) {
    section.append(node('p', empty, { className: 'state state-empty' }));
    return section;
  }
  const list = node('ul', null, { className: 'plain-list' });
  for (const item of items) {
    const li = node('li', null, { [`data-student-${part}-id`]: textOf(item?.id) ?? '' });
    const name = node('span', describe(item), { className: 'item-title' });
    if (currentId && textOf(item?.id) === currentId) name.append(document.createTextNode(' · 현재 로그인'));
    li.append(name, statusBadge(table, item?.status, part === 'devices' ? 'device' : 'session'));
    list.append(li);
  }
  section.append(list);
  return section;
}

function renderIdentityView(input) {
  const { me, devices, sessions } = input ?? {};
  const meOk = me?.status === 'ok';
  const root = node('div', null, { 'data-student': 'identity', 'aria-label': '로그인 사용자·기기·세션' });
  root.append(
    renderMe(me),
    renderList(devices, {
      part: 'devices', title: '본인 기기', table: DEVICE_STATUS, empty: '표시할 기기가 없습니다.',
      describe: (d) => nameAndId(d?.label, d?.id), currentId: meOk ? textOf(me.data?.device?.id) : null,
    }),
    renderList(sessions, {
      part: 'sessions', title: '로그인 세션', table: SESSION_STATUS, empty: '표시할 세션이 없습니다.',
      describe: (s) => nameAndId(null, s?.id), currentId: meOk ? textOf(me.data?.session?.id) : null,
    }),
    node('p', '기기 보안 상태 표시는 악성코드 검사나 치료 기능이 아닙니다.', { className: 'muted' }),
  );
  return root;
}

// ---------- 14단계 · renderDecision: 선택한 업무 앱 한 개의 접근 판정과 이유 ----------
// 입력: { status, mode, data?, error?, appId } — status: idle(요청 전)·loading(요청 중)·ok(판정 수신)·error(요청 실패)
//       data: { appId, decision, reason, checkedAt }, decision: allow·deny·challenge·unknown
// 판정(ok)과 요청 실패(error)를 서로 다른 문구로 보여 줍니다. 요청 실패·확인 불가는 허용도 거부도 아닙니다.
// 이 표시는 선택한 앱 한 개의 판정이며, 전체 업무 앱 권한 목록을 조회하는 기능이 아닙니다.
const DECISIONS = {
  allow: { text: '접근 허용', allowed: true, note: '정책상 접근이 허용됐습니다. 실제 앱 접속 성공을 보장하지는 않습니다.' },
  deny: { text: '접근 거부', allowed: false, note: '정책상 접근이 거부됐습니다.' },
  challenge: { text: '추가 인증 또는 확인 필요', allowed: false, note: '추가 인증 또는 확인이 끝나기 전에는 허용되지 않습니다. 이 앱이 추가 인증을 대신 수행하지 않습니다.' },
  unknown: { text: '판정 확인 불가', allowed: false, note: '판정을 확인할 수 없어 허용되지 않음으로 다룹니다.' },
};

function formatCheckedAt(value) {
  const raw = textOf(value);
  if (!raw) return '판정 시각 정보 없음';
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? raw : `${date.toLocaleString('ko-KR')} (${raw})`;
}

function decisionBox(text, kind, code, role) {
  return node('p', text, { className: `state state-${kind}`, role, 'data-student-decision-state': code });
}

function renderDecisionView(input) {
  const { status, error } = input ?? {};
  const data = input?.data ?? null;
  const requestedApp = textOf(input?.appId);
  const root = node('div', null, { 'data-student': 'decision', 'aria-label': '업무 앱 접근 판정' });
  const app = textOf(data?.appId) ?? requestedApp;
  root.append(node('p', `대상 업무 앱: ${app ? `ID ${app}` : '선택한 앱 없음'}`, { 'data-student-app-id': app ?? '' }));
  const mode = modeLine(input, '판정');
  if (mode) root.append(mode);

  if (status === 'idle' || status === undefined || status === null) {
    root.setAttribute('data-student-decision', 'none');
    root.append(decisionBox('요청 전: 업무 앱을 골라 접속을 요청하세요. 아직 받은 판정이 없습니다.', 'empty', 'idle', 'status'));
    return root;
  }
  if (status === 'loading') {
    root.setAttribute('data-student-decision', 'pending');
    root.append(decisionBox('요청 중: 판정 확인 중입니다. 아직 판정이 아니며 허용되지 않음 상태입니다.', 'loading', 'loading', 'status'));
    return root;
  }
  if (status === 'error') {
    const code = textOf(error?.code);
    const message = textOf(error?.message) ?? '서버 메시지 없음';
    const unverified = code && UNVERIFIED_CODES.has(code);
    root.setAttribute('data-student-decision', unverified ? 'unverified' : 'request-failed');
    root.append(
      decisionBox(`${unverified ? '확인 불가(응답 형식 불일치)' : '요청 실패'}: ${message}${code ? ` [${code}]` : ''}`, 'error', 'error', 'alert'),
      node('p', '이것은 접근 거부(deny) 판정이 아니며, 접근 허용도 아닙니다. 판정을 받지 못했으므로 허용되지 않음 상태입니다. 다시 요청은 직접 눌러 주세요.', { className: 'muted' }),
    );
    return root;
  }
  if (status !== 'ok') {
    root.setAttribute('data-student-decision', 'unknown');
    root.append(decisionBox(`판정 확인 불가(unknown) · 받은 상태값: ${textOf(status) ?? '없음'} · 허용되지 않음`, 'empty', 'unknown', 'status'));
    return root;
  }

  // 판정 수신(ok). 네 값이 아니거나 요청한 앱과 판정 대상이 다르면 확인 불가로 처리합니다(허용으로 보이지 않게).
  const raw = textOf(data?.decision);
  const sameApp = !requestedApp || !textOf(data?.appId) || textOf(data?.appId) === requestedApp;
  const key = raw && Object.hasOwn(DECISIONS, raw) && sameApp ? raw : 'unknown';
  const info = DECISIONS[key];
  root.setAttribute('data-student-decision', key);
  let headline = `${info.text}(${key})`;
  if (key === 'unknown' && raw && raw !== 'unknown') headline += ` · 받은 값: ${raw}`;
  if (!sameApp) headline += ' · 요청한 앱과 판정 대상 앱이 다름';
  root.append(decisionBox(info.allowed ? headline : `${headline} · 허용되지 않음`, info.allowed ? 'ok' : key === 'deny' ? 'error' : 'empty', key, 'status'));
  root.append(node('p', info.note, { className: 'muted' }));
  const list = node('dl');
  row(list, '판정 이유', node('span', textOf(data?.reason) ?? '판정 이유 정보 없음', { 'data-student-decision-reason': '' }));
  row(list, '판정 시각', node('span', formatCheckedAt(data?.checkedAt), { 'data-student-decision-checked-at': textOf(data?.checkedAt) ?? '' }));
  root.append(list);
  return root;
}

// ---------- 15단계 · renderEvents: 내 접속 기록·XDR 경보 목록, 필터, 상세 ----------
// 입력: { status, mode, data?, error? } — data 는 기록 배열
//   기록: { id, kind, at, appId, summary, evidence:[{id,text}], rules:[{id,text}], state:{access,session,device}, supportedActions:[] }
// 관측 범위: 앱 서버가 내 SDP 감사 기록에서 맞춰 본 본인 최근 기록(최대 40건)입니다. 전체 직원 이력·실시간 전체 위협 탐지가 아니며,
//   XDR 경보는 서버에 이미 저장된 경보만 옵니다. 화면을 열 때 새로 탐지하지 않습니다.
// 받은 배열은 복사해서 정렬·필터링합니다(원본·서버 데이터를 바꾸지 않음). 필터는 서버에 다시 묻지 않고 받은 배열 안에서만 거릅니다.
// renderEvents 가 불릴 때마다(= 새 자료) 필터·상세 선택을 초기화하고 목록과 상세를 새로 그립니다.
// 조치 버튼은 만들지 않습니다(supportedActions 는 글자로만 표시).
const EVENT_KIND = { access: '접속 기록', xdr: 'XDR 경보' };
const ACCESS_STATE = {
  allowed: { text: '접근 허용됨', normal: true },
  denied: { text: '접근 거부됨', normal: false },
  unknown: { text: '확인 불가', normal: false },
};
const FILTER_ALL = 'all';
const NO_APP = '';   // appId 가 없는 옛 기록을 고르는 값(받은 appId 값과 겹치지 않도록 빈 문자열)

const kindText = (kind) => {
  const raw = textOf(kind) ?? 'unknown';
  return `${Object.hasOwn(EVENT_KIND, raw) ? EVENT_KIND[raw] : '확인 불가'}(${raw})`;
};
const appText = (appId) => (textOf(appId) ? `앱 ${textOf(appId)}` : '앱 확인 불가(appId 없음)');
const eventTime = (at) => formatCheckedAt(at).replace('판정 시각 정보 없음', '시각 정보 없음');
const atMs = (at) => { const t = Date.parse(at); return Number.isFinite(t) ? t : -Infinity; };

function sortedEvents(data) {
  // 원본 배열을 바꾸지 않도록 복사한 뒤 at 기준 최신순으로 정렬합니다.
  return [...data].sort((a, b) => atMs(b?.at) - atMs(a?.at) || String(a?.id).localeCompare(String(b?.id)));
}

function filterSelect(id, label, options, value, onChange) {
  const wrap = node('div', null, { className: 'student-filter' });
  const labelEl = node('label', label, { for: id });
  const select = node('select', null, { id, 'aria-label': label, 'data-student-filter': label });
  for (const [optValue, optText] of options) {
    const option = node('option', optText);
    option.value = optValue;
    if (optValue === value) option.selected = true;
    select.append(option);
  }
  select.addEventListener('change', () => onChange(select.value));
  wrap.append(labelEl, select);
  return wrap;
}

function textRows(title, rows, emptyText) {
  const section = node('section');
  section.append(node('h4', title));
  const list = Array.isArray(rows) ? rows : [];
  if (!list.length) {
    section.append(node('p', emptyText, { className: 'muted' }));
    return section;
  }
  const ul = node('ul', null, { className: 'plain-list' });
  for (const item of list) ul.append(node('li', `${textOf(item?.id) ?? 'ID 없음'}: ${textOf(item?.text) ?? '내용 없음'}`));
  section.append(ul);
  return section;
}

function eventDetail(event) {
  const id = textOf(event?.id) ?? '';
  const detail = node('section', null, { 'data-student-event-detail': id, 'aria-label': `${id} 상세 내용`, tabindex: '-1' });
  detail.append(node('h4', `${id} 상세`));
  const facts = node('dl');
  row(facts, '사건 ID', id || 'ID 없음');
  row(facts, '종류', kindText(event?.kind));
  row(facts, '시각', eventTime(event?.at));
  row(facts, '업무 앱(appId)', textOf(event?.appId) ?? '확인 불가(appId 없음 · 현재 등록 정보와 맞출 수 없는 기록)');
  row(facts, '요약', textOf(event?.summary) ?? '요약 없음');
  detail.append(facts);
  detail.append(textRows('근거(evidence)', event?.evidence, '근거 항목 없음'));
  detail.append(textRows('규칙(rules)', event?.rules, '규칙 항목 없음'));
  const states = node('dl', null, { 'data-student-event-state': id });
  row(states, '접속 상태(state.access)', statusBadge(ACCESS_STATE, event?.state?.access, 'access'));
  row(states, '세션 상태(state.session)', statusBadge(SESSION_STATUS, event?.state?.session, 'session'));
  row(states, '기기 상태(state.device)', statusBadge(DEVICE_STATUS, event?.state?.device, 'device'));
  detail.append(node('h4', '상태(state)'), states);
  // 16단계: 연결되지 않은 조치가 넘어온 경우에만 「<action> 미지원」 비활성 버튼을 둡니다.
  // 버튼은 disabled 이고 클릭 처리기가 없어 어떤 요청도 보내지 않습니다. 목록이 비어 있으면 버튼을 만들지 않습니다.
  const actions = Array.isArray(event?.supportedActions) ? event.supportedActions.map((a) => textOf(a)).filter(Boolean) : [];
  if (!actions.length) {
    detail.append(node('p', '지원되는 조치 없음(supportedActions 비어 있음) · 조치 버튼을 만들지 않습니다.', { className: 'muted' }));
    return detail;
  }
  const unsupported = node('section', null, { 'data-student-unsupported-actions': id });
  unsupported.append(node('h4', '조치(아직 지원하지 않음)'));
  const noteId = `student-unsupported-note-${id}`;
  for (const action of actions) {
    const button = node('button', `${action} 미지원`, {
      type: 'button', className: 'btn', 'aria-label': `${action} 미지원`, 'aria-describedby': noteId, 'data-student-unsupported-action': action,
    });
    button.disabled = true;
    unsupported.append(button);
  }
  unsupported.append(node('p', '조치 실행 연결은 준비 중입니다. 아직 지원하지 않는 조치이므로 이 화면은 어떤 조치 요청도 보내지 않으며, 조치가 실행되지 않았습니다.', { id: noteId, className: 'muted' }));
  detail.append(unsupported);
  return detail;
}

function renderEventsView(input) {
  const status = input?.status;
  const root = node('div', null, { 'data-student': 'events', 'aria-label': '내 접속 기록·XDR 경보' });
  root.append(node('p', '관측 범위: 본인의 최근 보안 기록(최대 40건)입니다. 모든 직원의 전체 이력이나 실시간 전체 위협 탐지가 아니며, XDR 경보는 서버에 이미 저장된 경보만 표시합니다.', { className: 'muted' }));
  const mode = modeLine(input, '보안 기록');
  if (mode) root.append(mode);

  if (status === 'loading') {
    root.append(node('p', '보안 기록: 불러오는 중', { className: 'state state-loading', role: 'status', 'data-student-events-state': 'loading' }));
    return root;
  }
  if (status === 'error') {
    // 실패 화면: 빈 목록과 다르게 보이고, 이전 목록·상세는 그리지 않습니다.
    const code = textOf(input.error?.code);
    const message = textOf(input.error?.message) ?? '서버 메시지 없음';
    const head = code && UNVERIFIED_CODES.has(code) ? '기록을 불러오지 못했습니다(확인 불가 · 응답 형식 불일치)' : '기록을 불러오지 못했습니다';
    root.append(node('p', `${head}: ${message}${code ? ` [${code}]` : ''}`, { className: 'state state-error', role: 'alert', 'data-student-events-state': 'error' }));
    root.append(node('p', '이전 목록은 현재 결과가 아니어서 표시하지 않습니다. 빈 목록(기록 없음)과 다릅니다.', { className: 'muted' }));
    return root;
  }
  if (status !== 'ok' || !Array.isArray(input?.data)) {
    root.append(node('p', `보안 기록: 확인 불가 (상태값 ${textOf(status) ?? '없음'})`, { className: 'state state-empty', 'data-student-events-state': 'unknown' }));
    return root;
  }
  const events = sortedEvents(input.data);
  if (!events.length) {
    root.append(node('p', '표시할 기록이 없습니다.', { className: 'state state-empty', role: 'status', 'data-student-events-state': 'empty' }));
    return root;
  }

  // 새 자료마다 필터·상세 선택을 처음 상태로 둡니다(이전 선택이 남지 않음).
  const filters = { kind: FILTER_ALL, app: FILTER_ALL, access: FILTER_ALL };
  let selectedId = null;
  const uniq = (values) => [...new Set(values)].sort();
  const kinds = uniq(events.map((e) => textOf(e?.kind) ?? 'unknown'));
  const apps = uniq(events.map((e) => textOf(e?.appId) ?? NO_APP));
  const accesses = uniq(events.map((e) => textOf(e?.state?.access) ?? 'unknown'));

  const controls = node('div', null, { className: 'student-filters', 'data-student-events-filters': '' });
  const countLine = node('p', null, { 'data-student-events-count': '', role: 'status' });
  const listArea = node('div');
  const detailArea = node('div', null, { 'aria-live': 'polite' });

  const matches = (e) => (filters.kind === FILTER_ALL || (textOf(e?.kind) ?? 'unknown') === filters.kind)
    && (filters.app === FILTER_ALL || (textOf(e?.appId) ?? NO_APP) === filters.app)
    && (filters.access === FILTER_ALL || (textOf(e?.state?.access) ?? 'unknown') === filters.access);

  function drawDetail() {
    const event = selectedId === null ? null : events.find((e) => textOf(e?.id) === selectedId && matches(e));
    if (!event) selectedId = null;
    detailArea.replaceChildren(event ? eventDetail(event)
      : node('p', '상세를 볼 기록의 「상세」 버튼을 누르세요.', { className: 'muted' }));
  }

  function drawList() {
    const shown = events.filter(matches);
    countLine.textContent = `표시 ${shown.length}건 / 받은 기록 ${events.length}건 (최신순)`;
    if (!shown.length) {
      listArea.replaceChildren(node('p', '필터 조건에 맞는 기록이 없습니다. 필터를 「전체」로 바꾸면 받은 기록이 다시 보입니다.', { className: 'state state-empty' }));
      drawDetail();
      return;
    }
    const ul = node('ul', null, { className: 'plain-list', 'aria-label': '보안 기록 목록' });
    for (const event of shown) {
      const id = textOf(event?.id) ?? '';
      const li = node('li', null, { 'data-student-event-id': id });
      li.append(node('span', `${id} · ${eventTime(event?.at)} · ${kindText(event?.kind)} · ${appText(event?.appId)} · ${textOf(event?.summary) ?? '요약 없음'}`, { className: 'item-title' }));
      const button = node('button', `${id} 상세`, { type: 'button', className: 'btn', 'aria-label': `${id} 상세`, 'aria-pressed': String(selectedId === id) });
      button.addEventListener('click', () => {
        selectedId = id;
        drawList();
        const panel = detailArea.querySelector('[data-student-event-detail]');
        if (panel) panel.focus();
      });
      li.append(button);
      ul.append(li);
    }
    listArea.replaceChildren(ul);
    drawDetail();
  }

  const setFilter = (key) => (value) => { filters[key] = value; drawList(); };
  controls.append(
    filterSelect('student-filter-kind', '기록 종류', [[FILTER_ALL, '전체(all)'], ...kinds.map((k) => [k, kindText(k)])], filters.kind, setFilter('kind')),
    filterSelect('student-filter-app', '업무 앱', [[FILTER_ALL, '전체(all)'], ...apps.map((a) => [a, a === NO_APP ? '앱 확인 불가(appId 없음)' : a])], filters.app, setFilter('app')),
    filterSelect('student-filter-access', '접속 상태', [[FILTER_ALL, '전체(all)'], ...accesses.map((a) => [a, statusText(ACCESS_STATE, a).text])], filters.access, setFilter('access')),
  );
  root.append(controls, countLine, listArea, detailArea);
  drawList();
  return root;
}

// ---------- 16단계 · renderStatus: 기기·세션·알림·도움정보, 빈 화면과 실패 구분 ----------
// 입력: { devices, sessions, notifications, diagnostics, mode }
//   devices·sessions·diagnostics: { status, mode, data?, error? } / notifications: [{ resource, code, message }]
// 진단 정보(diagnostics)는 제공 화면이 조회해 넘겨 준 값만 씁니다. 학생 코드는 /api/diagnostics 를 직접 부르지 않습니다.
// 다시 시도는 사용자가 위쪽 「다시 불러오기」를 직접 누를 때만 일어납니다. 이 코드에는 자동 재요청·타이머가 없습니다.
// 호출마다 새 DOM 을 만들므로, 다시 불러와 성공하면 이전 실패 안내가 남지 않습니다.
const RESOURCE_NAMES = {
  me: '로그인 정보', devices: '등록 기기', sessions: '세션', events: '보안 기록', apps: '업무 앱',
  access: '접속 판정', diagnostics: '도움정보', vulnerabilities: '취약점 조회', aiConnection: 'AI 연결',
};
const RETRY_GUIDE = '다시 시도는 위쪽 「다시 불러오기」 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.';
const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,64}$/u;
// 화면·복사 내용에 비밀처럼 보이는 값이 섞이지 않도록 가립니다(토큰·열쇠·비밀번호 모양).
const SECRET_LIKE = [
  /\bBearer\s+\S+/giu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/gu,
  /\b(?:sk|pk|sb_secret|sb_publishable|ghp|gho|xox[abp])[_-][A-Za-z0-9_-]{8,}/giu,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+/giu,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
];
const redact = (value) => SECRET_LIKE.reduce((t, re) => t.replace(re, '[가림]'), String(value));
const safeText = (value, fallback) => { const t = textOf(value); return t ? redact(t) : fallback; };
const safeCode = (value) => { const t = textOf(value); return t && SAFE_CODE.test(t) ? t : '확인 불가'; };
const resourceName = (key) => { const k = textOf(key); return k ? `${Object.hasOwn(RESOURCE_NAMES, k) ? RESOURCE_NAMES[k] : '기타 자료'}(${safeCode(k)})` : '자료 확인 불가'; };
const isTimeout = (code) => /TIMEOUT$/u.test(textOf(code) ?? '');

// loading·error·빈 목록·ok 를 서로 다른 문장으로 보여 줍니다.
function statusList(resource, { part, what, empty, describe, table, kind, scopeNote }) {
  const section = node('section', null, { 'data-student-status-part': part });
  section.append(node('h3', what));
  if (scopeNote) section.append(node('p', scopeNote, { className: 'muted' }));
  const mode = modeLine(resource, what);
  if (mode) section.append(mode);
  const status = resource?.status;
  if (status === 'loading') {
    section.append(node('p', `${what}: 불러오는 중`, { className: 'state state-loading', role: 'status', 'data-student-status-state': 'loading' }));
    return section;
  }
  if (status === 'error') {
    const code = textOf(resource.error?.code);
    const message = safeText(resource.error?.message, '서버 메시지 없음');
    const head = isTimeout(code) ? `${what} 조회 실패(시간 초과)`
      : code && UNVERIFIED_CODES.has(code) ? `${what} 조회 실패(확인 불가 · 응답 형식 불일치)`
        : `${what} 조회 실패`;
    section.append(
      node('p', `${head}: ${message}${code ? ` [${safeCode(code)}]` : ''}`, { className: 'state state-error', role: 'alert', 'data-student-status-state': isTimeout(code) ? 'timeout' : 'error' }),
      node('p', RETRY_GUIDE, { className: 'muted', 'data-student-retry': part }),
    );
    return section;
  }
  if (status !== 'ok' || !Array.isArray(resource?.data)) {
    section.append(node('p', `${what}: 확인 불가 (상태값 ${textOf(status) ?? '없음'})`, { className: 'state state-empty', 'data-student-status-state': 'unknown' }));
    return section;
  }
  if (!resource.data.length) {
    section.append(node('p', empty, { className: 'state state-empty', role: 'status', 'data-student-status-state': 'empty' }));
    return section;
  }
  const ul = node('ul', null, { className: 'plain-list' });
  for (const item of resource.data) {
    const li = node('li', null, { [`data-student-${part}-item`]: textOf(item?.id) ?? '' });
    li.append(node('span', describe(item), { className: 'item-title' }), statusBadge(table, item?.status, kind));
    ul.append(li);
  }
  section.append(ul);
  return section;
}

function notificationsView(notifications) {
  const section = node('section', null, { 'data-student-status-part': 'notifications' });
  section.append(node('h3', '알림'));
  const list = Array.isArray(notifications) ? notifications : [];
  if (!list.length) {
    section.append(node('p', '주의할 알림이 없습니다.', { className: 'state state-ok', role: 'status', 'data-student-notifications': '0' }));
    return section;
  }
  section.append(node('p', `주의할 알림 ${list.length}건`, { 'data-student-notifications': String(list.length) }));
  const ul = node('ul', null, { className: 'plain-list' });
  for (const n of list) {
    ul.append(node('li', `${resourceName(n?.resource)} · 코드 ${safeCode(n?.code)} · ${safeText(n?.message, '메시지 없음')}`, {
      'data-student-notification-resource': textOf(n?.resource) ?? '',
    }));
  }
  section.append(ul);
  return section;
}

// 도움정보: 허용한 여섯 값만 뽑습니다. 그 밖의 값(ai 설정 등)과 비밀처럼 보이는 값은 쓰지 않습니다.
function safeDiagnostics(data) {
  return {
    requestId: safeText(data?.requestId, '없음'),
    component: safeText(data?.component, '없음'),
    version: safeText(data?.version, '없음'),
    checkedAt: safeText(data?.checkedAt, '없음'),
    'engine.mode': safeText(data?.engine?.mode, '없음'),
    'engine.code': safeText(data?.engine?.code, '없음'),
  };
}

function diagnosticsView(diagnostics) {
  const section = node('section', null, { 'data-student-status-part': 'diagnostics' });
  section.append(node('h3', '도움정보(진단)'));
  const status = diagnostics?.status;
  const ok = status === 'ok' && diagnostics.data && typeof diagnostics.data === 'object';
  const fields = ok ? safeDiagnostics(diagnostics.data) : null;
  if (status === 'loading') {
    section.append(node('p', '도움정보: 불러오는 중', { className: 'state state-loading', role: 'status' }));
  } else if (status === 'error') {
    const code = textOf(diagnostics.error?.code);
    section.append(
      node('p', `도움정보를 불러오지 못했습니다${isTimeout(code) ? '(시간 초과)' : ''}: ${safeText(diagnostics.error?.message, '서버 메시지 없음')}${code ? ` [${safeCode(code)}]` : ''}`, { className: 'state state-error', role: 'alert' }),
      node('p', '다시 시도는 위쪽 「도움정보 불러오기」 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.', { className: 'muted' }),
    );
  } else if (ok) {
    const dl = node('dl', null, { 'data-student-diagnostics': '' });
    for (const [key, value] of Object.entries(fields)) row(dl, key, value);
    section.append(dl);
  } else {
    section.append(node('p', '도움정보를 아직 불러오지 않았습니다. 위쪽 「도움정보 불러오기」를 누르면 여기에 표시됩니다.', { className: 'state state-empty' }));
  }

  const help = node('p', '「도움정보 복사」는 도움 요청에 쓸 진단 값(requestId·component·version·checkedAt·engine.mode·engine.code)만 클립보드에 복사합니다. 누를 때만 복사하며 어디에도 전송하지 않습니다. 비밀번호·토큰·API 키는 넣지 않습니다.', { id: 'student-diag-help', className: 'muted' });
  const result = node('p', null, { role: 'status', 'data-student-copy-result': '' });
  const button = node('button', '도움정보 복사', { type: 'button', className: 'btn', 'aria-describedby': 'student-diag-help' });
  if (!ok) {
    button.disabled = true;
    result.textContent = '복사할 도움정보가 없습니다. 먼저 도움정보를 불러오세요.';
  }
  button.addEventListener('click', async () => {
    if (!fields) return;
    const text = Object.entries(fields).map(([k, v]) => `${k}: ${v}`).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      result.textContent = '도움정보(진단 값 6개)를 클립보드에 복사했습니다.';
    } catch {
      // 자동 복사를 쓸 수 없으면 같은 안전한 값을 보여 주고 직접 복사하게 합니다.
      const pre = node('pre', text, { tabindex: '0' });
      result.replaceChildren(document.createTextNode('자동 복사를 사용할 수 없습니다. 아래 내용을 선택해 Ctrl+C로 복사하세요.'), pre);
    }
  });
  section.append(help, button, result);
  return section;
}

function renderStatusView(input) {
  const root = node('div', null, { 'data-student': 'status', 'aria-label': '기기·세션·알림·도움정보 상태' });
  const overall = textOf(input?.mode);
  if (overall) {
    root.append(node('p', `전체 연결 상태: ${Object.hasOwn(MODE_TEXT, overall) ? MODE_TEXT[overall] : MODE_TEXT.unknown} (${overall})`, {
      className: overall === 'connected' ? 'muted' : 'tag tag-demo', 'data-student-mode': overall,
    }));
  }
  root.append(
    statusList(input?.devices, {
      part: 'devices', what: '등록 기기', empty: '등록된 기기가 없습니다.', table: DEVICE_STATUS, kind: 'device',
      describe: (d) => nameAndId(d?.label, d?.id),
      scopeNote: '내 이름으로 등록되고 회수되지 않은 기기(최대 100개)입니다. 지금 쓰는 기기가 맨 앞에 옵니다.',
    }),
    statusList(input?.sessions, {
      part: 'sessions', what: '현재 세션', empty: '현재 연결 없음: 지금 검증된 세션이 없습니다.', table: SESSION_STATUS, kind: 'session',
      describe: (x) => nameAndId(null, x?.id),
      scopeNote: '지금 검증된 연결 하나만 표시합니다. 지난 세션 목록이 아닙니다.',
    }),
    notificationsView(input?.notifications),
    diagnosticsView(input?.diagnostics),
  );
  return root;
}

export function createStudentView() {
  return {
    renderIdentity(input) { return renderIdentityView(input); },
    renderDecision(input) { return renderDecisionView(input); },
    renderEvents(input) { return renderEventsView(input); },
    renderStatus(input) { return renderStatusView(input); },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
