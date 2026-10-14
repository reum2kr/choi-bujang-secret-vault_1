// 12단계: 학생 판정기(src/decider.mjs)와 탐지 규칙(src/detect.mjs)에 고정된 가상 입력만 넣어 본 결과입니다.
// 서버 함수 GET /api/ops?case=<묶음> 이 이 결과를 돌려주므로, 점검 코드와 심판의 실행기가 같은 HTTP 응답을 관측할 수 있습니다.
// 사용자 입력을 판정 입력으로 쓰지 않고, 실제 세션·메모·기기 상태는 읽거나 바꾸지 않습니다.
// 결과의 synthetic: true 는 가상 입력이라는 뜻이며, 실제 엔진의 집행 결과가 아닙니다.
import { decide, RULE_IDS } from './decider.mjs';
import { detect } from './detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const brief = (o) => ({ decision: o.decision, reasonCode: o.reasonCode, ruleIds: o.ruleIds });
const actionOf = (r) => ({ action: r.action, reasonCode: r.reasonCode ?? null, subject: r.subject ?? null, deviceId: r.deviceId ?? null });

async function deciderCases() {
  const { normal, suspicious } = fixtureRequests();
  const ask = (base, patch = {}) => decide({ ...base, requestId: crypto.randomUUID(), ...patch });
  return {
    registered: brief(await ask(normal)),
    unregistered: brief(await ask(normal, { deviceRegistered: false })),
    normalContext: brief(await ask(normal)),
    compound: brief(await ask(suspicious)),
    afterStepUp: brief(await ask(suspicious, { stepUp: { verified: true, authAgeSeconds: 60 } })),
    clientHeader: brief(await ask(suspicious, { signals: { ...suspicious.signals, source: 'client_header' } })),
    ownNote: brief(await ask(normal)),
    bulkList: brief(await ask(normal, { route: 'GET /notes', path: '/notes' })),
    noticeWrite: brief(await ask(normal, { method: 'PUT', route: 'PUT /notices/:id', path: '/notices/demo' })),
    noticeRead: brief(await ask(normal, { route: 'GET /notices/:id', path: '/notices/demo' })),
    exportPath: brief(await ask(normal, { path: '/notes/export' })),
    unknownRoute: brief(await ask(normal, { route: 'GET /admin', path: '/admin' })),
    restoreV1: brief(await ask(normal, { method: 'POST', route: 'POST /restore/notes/:id', path: '/restore/notes/demo' })),
    restoreV2: brief(await ask(normal, { method: 'POST', route: 'POST /restore/notes/:id', path: '/restore/notes/demo', policyRevision: 2 })),
  };
}

function detectCases() {
  const start = Date.UTC(2026, 9, 1, 2, 0, 0);
  const reads = (count, deviceId, network) => Array.from({ length: count }, (_, i) => ({
    at: new Date(start + i * 2000).toISOString(), method: 'GET', identity: { sub: 'learner_fixture' },
    deviceId, decision: 'allow', signals: { source: 'judge_fixture', region: 'KR-11', network, hour: 2 },
  }));
  const mix = (...lists) => lists.flat().sort((a, b) => a.at.localeCompare(b.at));
  return {
    normal200: actionOf(detect(reads(200, 'device_home', 'usual'))),
    regionOnly200: actionOf(detect(reads(200, 'device_home', 'usual').map((e) => ({ ...e, signals: { ...e.signals, region: 'US-CA' } })))),
    unusual20: actionOf(detect(reads(20, 'device_other', 'unusual'))),
    doppelganger: actionOf(detect(mix(reads(50, 'device_home', 'usual'), reads(150, 'device_other', 'unusual')))),
  };
}

export const RULE_CHECK_CASES = Object.freeze(['decider', 'detect']);

export async function runRuleCheck(caseId) {
  if (caseId === 'decider') return { synthetic: true, case: caseId, ruleIds: [...RULE_IDS], results: await deciderCases() };
  if (caseId === 'detect') return { synthetic: true, case: caseId, results: detectCases() };
  return null;
}
