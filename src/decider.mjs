// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 계약(docs/DECIDER_REQUEST.md)의 값 중 로그인(subjectId)·기기 등록 여부(deviceRegistered)·
// 동작(method)·경로(route)·엔진이 넘긴 접속 사건(signals, recentEvents)·재로그인 확인(stepUp)만 봅니다.
// 요청 본문의 userId, role, 기기 키, 토큰, 브라우저가 보낸 위치·헤더는 믿거나 저장하지 않습니다.
// 6단계 device_registered: 등록된 기기의 내 자료실 읽기만 허용합니다.
// 7단계 step_up_required: 평소와 다른 시각 + 처음 보는 네트워크 + 갑작스러운 대량 읽기가 겹치면 다시 로그인을 요구합니다.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required']);

// 내 자료실 읽기 경로 (allowedRoutes의 GET 경로와 같은 모양, /api 접두사는 있어도 되고 없어도 됨)
const READ_ROUTES = /^GET \/(?:api\/)?notes(?:\/:id)?$/u;

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
  if (loggedIn && request.method === 'GET' && typeof request.route === 'string' && READ_ROUTES.test(request.route)) {
    // step_up_required: 복합 이상 사건이면, 엔진이 확인한 새 로그인이 있을 때까지 자료를 주지 않습니다.
    // 영구 차단(deny)이 아니라 다시 로그인(step_up)이며, 사유는 reasonCode·ruleIds로 남깁니다.
    const ctx = readContext(request);
    if (anomaly(ctx) && !(ctx.stepUp.verified && ctx.stepUp.authAgeSeconds <= FRESH_LOGIN_SECONDS)) {
      return answer(request, 'step_up', 'step_up_required', 'step_up_required');
    }
    return answer(request, 'allow', 'approved', 'device_registered');
  }
  // 그 밖의 요청은 시작 틀의 기본 거부를 그대로 둡니다.
  return answer(request, 'deny', 'starter_not_ready', 'starter.deny');
}
