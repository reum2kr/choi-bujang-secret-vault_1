// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 계약(docs/DECIDER_REQUEST.md)의 값 중 로그인(subjectId)·기기 등록 여부(deviceRegistered)·
// 동작(method)·경로(route)·엔진이 넘긴 접속 사건(signals, recentEvents)·재로그인 확인(stepUp)만 봅니다.
// 요청 본문의 userId, role, 기기 키, 토큰, 브라우저가 보낸 위치·헤더는 믿거나 저장하지 않습니다.
// 6단계 device_registered: 등록된 기기의 내 자료실 읽기만 허용합니다.
// 7단계 step_up_required: 평소와 다른 시각 + 처음 보는 네트워크 + 갑작스러운 대량 읽기가 겹치면 다시 로그인을 요구합니다.
// 8단계 zone_*: 자원을 메모(notes)·공지(notices) 구역으로 나누고, 엔진이 확인한 사용자·기기·메서드·정확한 경로로만 판단합니다.
// 10단계 restore_verified_policy: 자기 메모 한 건 복구 경로는 엔진이 알려 준 정책 버전(request.policyRevision)이
//   침해 전에 검증한 안전 정책 버전일 때만 통과시킵니다. 버전이 바뀌었거나 없으면 복원하지 않고 멈춥니다(deny).
export const RULE_IDS = Object.freeze([
  'starter.deny', 'device_registered', 'step_up_required',
  'zone_route_allowlist', 'zone_notes_self', 'zone_notes_no_bulk', 'zone_notices_instructor', 'restore_verified_policy',
]);

// 침해 전에 검증한 안전 정책 버전(policy/safe/manifest.json의 policyRevision과 같음). 이 버전일 때만 복구를 허용합니다.
const VERIFIED_POLICY_REVISIONS = Object.freeze(new Set([1]));

// ── 8단계 제작 2: 구역별 허용 경로표 ─────────────────────────────────────────────
// 정확히 이 메서드+경로 모양만 압니다(/api 접두사는 있어도 되고 없어도 됨). 나머지는 모두 거부합니다.
// 경로의 마지막 칸은 자료 ID뿐이며, 쿼리로 기능을 고르지 않습니다.
const ZONE_ROUTES = Object.freeze({
  // 메모 전체 목록은 여러 사람의 자료를 한꺼번에 여는 경로라 판정기에서 허용하지 않습니다(자기 메모는 한 건씩만).
  'GET /notes':        { zone: 'notes',   ruleId: 'zone_notes_no_bulk',      access: 'deny_bulk' },
  'GET /notes/:id':    { zone: 'notes',   ruleId: 'zone_notes_self',         access: 'allow' },
  'PUT /notes/:id':    { zone: 'notes',   ruleId: 'zone_notes_self',         access: 'allow' },
  // 10단계: 제출한 복구 경로(POST /api/restore/notes/:id)와 같은 뜻의 경로 모양. 메모 한 건만, 검증된 정책 버전일 때만.
  'POST /restore/notes/:id': { zone: 'notes', ruleId: 'zone_notes_self', access: 'restore', services: ['notes', 'restore'] },
  'POST /notes/:id/restore': { zone: 'notes', ruleId: 'zone_notes_self', access: 'restore', services: ['notes', 'restore'] },
  // 강사 공지 구역: 강사만 들어갈 수 있는 구역입니다(학생의 자기 메모 구역과 다름).
  // 현재 판정 요청 계약에는 엔진이 확인한 강사 역할이 없어서(request.role 없음) 판정기는 모든 요청자를 일반 학생으로 보고 거부합니다.
  // 강사 여부는 자료 API가 DB의 instructors 표로 다시 확인합니다. 역할 계약이 생기기 전까지 여기서 허용하지 않습니다.
  'GET /notices':      { zone: 'notices', ruleId: 'zone_notices_instructor', access: 'instructor_required' },
  'GET /notices/:id':  { zone: 'notices', ruleId: 'zone_notices_instructor', access: 'instructor_required' },
  'PUT /notices/:id':  { zone: 'notices', ruleId: 'zone_notices_instructor', access: 'instructor_required' },
});
// 구역별로 받아들이는 엔진 서비스 이름. 메모 경로는 notes 서비스만, 공지 경로는 notes(같은 자료실)·notices만.
const SERVICE_OK = Object.freeze({
  notes: (service) => service === 'notes',
  notices: (service) => service === 'notes' || service === 'notices',
});
const RESERVED_IDS = new Set(['export', 'import', 'all', 'admin', 'bulk', 'download', 'search', 'new', 'me']);
const ID_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/u;

// route와 path가 서로 맞는지까지 봅니다. 예: route 'GET /notes/:id' 이면 path는 '/notes/<자료 ID>' 하나뿐.
export function matchZone(request) {
  if (typeof request?.route !== 'string' || typeof request?.path !== 'string') return null;
  const [method, rawShape, extra] = request.route.split(' ');
  if (extra !== undefined || method !== request.method || typeof rawShape !== 'string') return null;
  const shape = rawShape.replace(/^\/api(?=\/)/u, '');
  const entry = ZONE_ROUTES[`${method} ${shape}`];
  if (!entry) return null;
  // 엔진이 확인한 서비스가 다른 구역을 가리키면 거부합니다(예: service 'notices'로 메모 경로 요청).
  const serviceOk = entry.services ? entry.services.includes(request.service) : SERVICE_OK[entry.zone](request.service);
  if (!serviceOk) return null;
  const path = request.path.replace(/^\/api(?=\/)/u, '');
  const parts = path.split('/');
  const shapeParts = shape.split('/');
  if (parts.length !== shapeParts.length) return null;
  for (let i = 0; i < parts.length; i += 1) {
    if (shapeParts[i] === ':id') {
      if (!ID_SEGMENT.test(parts[i]) || RESERVED_IDS.has(parts[i].toLowerCase())) return null;
    } else if (parts[i] !== shapeParts[i]) {
      return null;
    }
  }
  return entry;
}

// ── 7단계 제작 1: 엔진이 넘긴 접속 정보만 골라 씁니다 ──────────────────────────
// 엔진이 출처를 밝힌 값만 믿습니다. 'judge_fixture'는 심판의 가상 사건이고 실제 위치 증거가 아닙니다.
// 'none'이나 모르는 출처(예: 클라이언트 헤더)는 신뢰하지 않으며, 빠진 값을 정상값으로 채우지 않습니다.
const TRUSTED_SIGNAL_SOURCES = new Set(['judge_fixture']);
const KNOWN_NETWORKS = new Set(['usual', 'unusual']);
const MAX_EVENTS = 12;

const isInt = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;

export function readContext(request) {
  const raw = request?.signals;
  const source = typeof raw?.source === 'string' ? raw.source : null;
  const trusted = source !== null && TRUSTED_SIGNAL_SOURCES.has(source);
  // 신뢰하지 않는 출처면 지역·네트워크·시각을 모두 "모름(null)"으로 둡니다.
  const signals = trusted ? {
    region: typeof raw.region === 'string' && raw.region !== 'unknown' ? raw.region : null,
    network: KNOWN_NETWORKS.has(raw.network) ? raw.network : null,
    hour: isInt(raw.hour, 0, 23) ? raw.hour : null,
  } : { region: null, network: null, hour: null };

  // 행동 사건: 형식이 맞는 항목만, 최대 12건. 틀린 항목은 버리고 대신 채우지 않습니다.
  const events = Array.isArray(request?.recentEvents)
    ? request.recentEvents.slice(0, MAX_EVENTS).filter((e) => e && typeof e === 'object'
      && typeof e.kind === 'string' && isInt(e.ageSeconds, 0, 86_400) && isInt(e.count, 0, 1_000_000))
    : [];

  // 재로그인 확인: 엔진이 검증한 경우(verified true, 나이 0~900초)만 인정합니다.
  const stepUp = request?.stepUp?.verified === true && isInt(request.stepUp.authAgeSeconds, 0, 900)
    ? { verified: true, authAgeSeconds: request.stepUp.authAgeSeconds }
    : { verified: false, authAgeSeconds: null };

  return { source, trusted, signals, events: trusted ? events : [], stepUp };
}

// ── 7단계 제작 2: 복합 이상 사건 규칙 ──────────────────────────────────────────
const ODD_HOURS = (hour) => hour !== null && (hour >= 0 && hour <= 5); // 새벽 0~5시
const BURST_WINDOW_SECONDS = 300;   // 최근 5분
const BURST_MIN_COUNT = 10;         // 그 사이 10건 이상
const FRESH_LOGIN_SECONDS = 300;    // 다시 로그인한 지 5분 이내면 확인된 것으로 봄

function anomaly(ctx) {
  if (!ctx.trusted) return null; // 출처가 불명확하면 이 규칙의 근거로 쓰지 않음(허용/거부를 지어내지 않음)
  const oddHour = ODD_HOURS(ctx.signals.hour);
  const newNetwork = ctx.signals.network === 'unusual';
  const burst = ctx.events.some((e) => e.ageSeconds <= BURST_WINDOW_SECONDS && e.count >= BURST_MIN_COUNT);
  // 지역 하나만으로는 판단하지 않습니다. 세 신호가 모두 겹칠 때만 추가 확인을 요구합니다.
  return oddHour && newNetwork && burst ? { oddHour, newNetwork, burst } : null;
}

const answer = (request, decision, reasonCode, ruleId) => ({
  schema: 'aleph.decision.v1',
  requestId: request?.requestId,
  decision,
  reasonCode,
  ruleIds: [ruleId],
});

export async function decide(request) {
  // device_registered: 등록 상태가 정확히 true일 때만 다음으로 넘어갑니다. 값이 없거나 false면 거부.
  if (request?.deviceRegistered !== true) {
    return answer(request, 'deny', 'device_not_registered', 'device_registered');
  }
  const loggedIn = typeof request.subjectId === 'string' && request.subjectId.length > 0;
  if (!loggedIn) {
    // 엔진이 확인한 로그인 주체가 없으면 시작 틀의 기본 거부를 그대로 둡니다.
    return answer(request, 'deny', 'starter_not_ready', 'starter.deny');
  }

  // zone_route_allowlist: 경로표에 없는 경로, route·path가 어긋난 요청, 쿼리가 붙은 요청은 거부합니다.
  const zone = matchZone(request);
  if (!zone || request.queryLength !== 0) {
    return answer(request, 'deny', 'route_not_allowed', 'zone_route_allowlist');
  }

  // zone_notices_instructor: 엔진이 확인한 강사 역할이 계약에 없으므로 강사 공지 구역(읽기·수정)은 거부합니다.
  if (zone.access === 'instructor_required') {
    return answer(request, 'deny', 'instructor_required', zone.ruleId);
  }

  // zone_notes_no_bulk: 메모 전체 목록처럼 여러 사람의 자료를 한꺼번에 여는 경로는 거부합니다.
  if (zone.access === 'deny_bulk') {
    return answer(request, 'deny', 'route_not_allowed', zone.ruleId);
  }

  // restore_verified_policy: 복구는 검증한 안전 정책 버전일 때만. 아니면 복원하지 않고 멈춥니다.
  if (zone.access === 'restore' && !VERIFIED_POLICY_REVISIONS.has(request.policyRevision)) {
    return answer(request, 'deny', 'policy_unverified', 'restore_verified_policy');
  }

  // step_up_required: 복합 이상 사건이면, 엔진이 확인한 새 로그인이 있을 때까지 자료를 주지 않습니다.
  // 영구 차단(deny)이 아니라 다시 로그인(step_up)이며, 사유는 reasonCode·ruleIds로 남깁니다.
  const ctx = readContext(request);
  if (anomaly(ctx) && !(ctx.stepUp.verified && ctx.stepUp.authAgeSeconds <= FRESH_LOGIN_SECONDS)) {
    return answer(request, 'step_up', 'step_up_required', 'step_up_required');
  }
  // 메모 한 건의 주인 비교는 자료 API가 검증된 사용자와 저장된 owner_id로 합니다(남의 메모는 404). 판정기는 주인을 비교하지 않습니다.
  const ruleIds = zone.access === 'restore'
    ? ['device_registered', zone.ruleId, 'restore_verified_policy'] : ['device_registered', zone.ruleId];
  return { ...answer(request, 'allow', 'approved', 'device_registered'), ruleIds };
}

