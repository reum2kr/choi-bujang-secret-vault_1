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

export function createStudentView() {
  return {
    renderIdentity(input) { return renderIdentityView(input); },
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
