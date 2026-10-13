// 9단계 「도플갱어를 찾고 권한을 거둡니다」 학생 탐지 함수입니다.
// 반 엔진이 검증해 넘긴 가상 조회 사건만 받습니다. 브라우저가 보낸 사용자 번호·본문·헤더는 신원으로 쓰지 않습니다.
// 결과는 접속 허용/거부 응답(src/decider.mjs)과 별도인 탐지 결과입니다. 회수를 직접 집행하거나 기기 권한을 바꾸지 않고,
// propose_revocation "제안"만 돌려줍니다. 실제 회수와 걸린 시간은 심판이 확인합니다.
export const DETECT_RULE_IDS = Object.freeze(['detect_burst_read']);

// ── 제작 1: 사건 입력 정리 ───────────────────────────────────────────────────
// 사건 하나에서 가명 사용자(identity.sub, 없으면 계약 이름 subjectId)·기기(deviceId)·요청 종류(method, route)·
// 판정(decision)·엔진이 출처를 밝힌 네트워크(signals.network)·시각(at)만 골라 새 객체로 만듭니다.
// 메모 제목·본문, 토큰, 이메일·실명, 요청 본문 같은 다른 값은 복사하지 않으므로 저장·출력될 수 없습니다.
const PSEUDONYM = /^[A-Za-z0-9_.:-]{1,128}$/u;      // 이메일(@)·공백·한글 실명 같은 값은 가명으로 받지 않음
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const DECISIONS = new Set(['allow', 'deny', 'step_up']);
const NETWORKS = new Set(['usual', 'unusual']);
const UNTRUSTED_SOURCE = (source) => source !== undefined && source !== 'judge_fixture';
const MAX_EVENTS = 50_000;

const pseudonym = (value) => (typeof value === 'string' && PSEUDONYM.test(value) ? value : null);

export function readEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const at = typeof raw.at === 'string' ? Date.parse(raw.at) : Number.NaN;
  const method = typeof raw.method === 'string' ? raw.method.toUpperCase() : null;
  const subject = pseudonym(raw.identity?.sub) ?? pseudonym(raw.subjectId);
  if (!Number.isFinite(at) || !METHODS.has(method) || !subject) return null; // 빠진 값을 지어내지 않고 버림
  // 네트워크: 출처가 judge_fixture(또는 엔진이 출처 칸 없이 넘김)일 때만 씁니다. 클라이언트 헤더 등은 "모름".
  const signals = raw.signals && typeof raw.signals === 'object' ? raw.signals : null;
  const network = signals && !UNTRUSTED_SOURCE(signals.source) && NETWORKS.has(signals.network)
    ? signals.network : null;
  return {
    at,
    subject,
    deviceId: pseudonym(raw.deviceId) ?? pseudonym(raw.identity?.deviceId),
    method,
    route: typeof raw.route === 'string' ? raw.route.slice(0, 80) : null,
    decision: DECISIONS.has(raw.decision) ? raw.decision : null,
    network, // 지역(region)은 읽지 않습니다. 지역 하나만으로 의심을 확정하지 않기 위함입니다.
  };
}

export function readEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const out = [];
  for (const raw of events.slice(0, MAX_EVENTS)) {
    const event = readEvent(raw);
    if (event) out.push(event);
  }
  return out.sort((a, b) => a.at - b.at);
}

// ── 제작 2: 복합 의심 규칙 detect_burst_read ─────────────────────────────────
// 같은 가명 사용자·같은 기기의 GET 조회가 어느 10분 구간에서든 120건을 넘으면 "갑작스러운 다량 조회"입니다.
// 엔진이 네트워크를 알려 준 사건이면, 그 조회가 평소와 다른 네트워크(unusual)에서 왔을 때만 셉니다.
//   → 평소 네트워크의 많은 조회(정상 기기)나, 처음 보는 네트워크의 적은 조회는 의심이 아닙니다.
// 네트워크 정보가 전혀 없는 연습 사건(docs/DETECT_EVENTS.md 형식)은 다량 조회 기준만 적용합니다.
// 다른 사용자·다른 기기의 사건은 합치지 않고, 10분 밖의 사건은 같은 묶음으로 세지 않습니다. 정확히 120건은 제외.
const WINDOW_MS = 10 * 60 * 1000;
const BURST_OVER = 120;

function suspiciousReads(group) {
  const reads = group.filter((e) => e.method === 'GET');
  const knowsNetwork = reads.some((e) => e.network !== null);
  return knowsNetwork ? reads.filter((e) => e.network === 'unusual') : reads;
}

// 120건을 처음 넘은 시각(ms)을 돌려줍니다. 넘지 않으면 null.
function burstAt(reads) {
  let start = 0;
  for (let end = 0; end < reads.length; end += 1) {
    while (reads[end].at - reads[start].at >= WINDOW_MS) start += 1;
    if (end - start + 1 > BURST_OVER) return reads[end].at;
  }
  return null;
}

// ── 제작 3: 별도 탐지 결과에 회수 제안 ───────────────────────────────────────
// 대상은 확인된 가명 사용자 한 명과, 엔진이 알려 준 기기가 있으면 그 기기 한 개로만 한정합니다.
// 같은 사용자의 다른(정상) 기기는 제안에 넣지 않으므로 그대로 유지됩니다. 여러 묶음이 의심이면 가장 먼저 넘은 하나만.
export function detect(events) {
  const clean = readEvents(events);
  const groups = new Map();
  for (const event of clean) {
    const key = `${event.subject}\u0000${event.deviceId ?? ''}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(event);
  }
  let found = null;
  for (const group of groups.values()) {
    const at = burstAt(suspiciousReads(group));
    if (at !== null && (found === null || at < found.at)) {
      found = { at, subject: group[0].subject, deviceId: group[0].deviceId };
    }
  }
  if (!found) return { action: 'observe' };
  return {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject: found.subject,
    ...(found.deviceId ? { deviceId: found.deviceId } : {}),
  };
}
