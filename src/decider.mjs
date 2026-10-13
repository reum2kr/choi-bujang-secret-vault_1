// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 계약(docs/DECIDER_REQUEST.md)의 값 중 로그인(subjectId)·기기 등록 여부(deviceRegistered)·
// 동작(method)·경로(route)만 봅니다. 요청 본문의 userId, role, 기기 키, 토큰은 믿거나 저장하지 않습니다.
// 6단계 device_registered: 등록된 기기의 내 자료실 읽기만 허용합니다.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

// 내 자료실 읽기 경로 (allowedRoutes의 GET 경로와 같은 모양, /api 접두사는 있어도 되고 없어도 됨)
const READ_ROUTES = /^GET \/(?:api\/)?notes(?:\/:id)?$/u;

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
    return answer(request, 'allow', 'approved', 'device_registered');
  }
  // 그 밖의 요청은 시작 틀의 기본 거부를 그대로 둡니다.
  return answer(request, 'deny', 'starter_not_ready', 'starter.deny');
}
