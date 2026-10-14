// 12단계: GET /api/checks?case=decider|detect
// 학생 판정기·탐지 규칙에 고정된 가상 입력만 넣은 결과를 돌려줍니다(synthetic: true). 사용자 입력을 판정 입력으로 쓰지 않습니다.
// 메모·토큰·기기 ID·사용자 정보는 읽지도 돌려주지도 않습니다. 실제 엔진의 집행 결과가 아닙니다.
import { runRuleCheck, RULE_CHECK_CASES } from '../../src/rule-check.mjs';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const query = request.query ?? {};
  const keys = Object.keys(query);
  if (keys.length !== 1 || keys[0] !== 'case' || typeof query.case !== 'string' || !RULE_CHECK_CASES.includes(query.case)) {
    return response.status(400).json({ error: 'UNKNOWN_CHECK', cases: RULE_CHECK_CASES });
  }
  try {
    return response.status(200).json(await runRuleCheck(query.case));
  } catch {
    return response.status(500).json({ error: 'CHECK_FAILED' });
  }
}
