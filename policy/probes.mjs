// 10단계: 판정기 정책을 검증·비교할 때 쓰는 가상 요청 묶음입니다(계약 docs/DECIDER_REQUEST.md의 18개 이름만 사용).
// expected는 "안전 정책이라면 반드시 이렇게 답해야 한다"는 값입니다. 실제 학생 계정·토큰·메모 본문은 없습니다.
import { createHash, randomUUID } from 'node:crypto';

const base = () => ({
  schema: 'aleph.decision.v1', requestId: randomUUID(), classId: 'class_fixture',
  projectId: 'project_fixture', subjectId: 'learner_fixture', deviceId: 'a'.repeat(16),
  service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
  queryLength: 0, querySha256: createHash('sha256').update('').digest('hex'),
  at: new Date().toISOString(), policyRevision: 1, deviceRegistered: true,
  stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [],
  signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
});
const odd = {
  signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
  recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
};

export const PROBES = Object.freeze([
  { name: 'own_note_read', label: '등록 기기의 자기 메모 한 건 읽기', expected: 'allow', patch: {} },
  { name: 'own_note_write', label: '등록 기기의 자기 메모 한 건 수정', expected: 'allow',
    patch: { method: 'PUT', route: 'PUT /notes/:id' } },
  { name: 'unregistered_device', label: '미등록 기기의 메모 읽기', expected: 'deny', patch: { deviceRegistered: false } },
  { name: 'no_subject', label: '로그인 주체 없는 요청', expected: 'deny', patch: { subjectId: '' } },
  { name: 'bulk_note_list', label: '메모 전체 목록(B가 A 메모까지 한꺼번에 열기)', expected: 'deny',
    patch: { path: '/notes', route: 'GET /notes' } },
  { name: 'notice_read', label: '학생의 강사 공지 읽기', expected: 'deny',
    patch: { service: 'notices', path: '/notices', route: 'GET /notices' } },
  { name: 'notice_write', label: '학생의 강사 공지 수정', expected: 'deny',
    patch: { service: 'notices', method: 'PUT', path: '/notices/demo', route: 'PUT /notices/:id' } },
  { name: 'note_delete', label: '판정기 경로의 메모 삭제', expected: 'deny',
    patch: { method: 'DELETE', route: 'DELETE /notes/:id' } },
  { name: 'function_path', label: '자료 ID 자리에 기능 이름(export)', expected: 'deny', patch: { path: '/notes/export' } },
  { name: 'query_attached', label: '쿼리가 붙은 요청', expected: 'deny', patch: { queryLength: 9 } },
  { name: 'route_path_mismatch', label: 'route와 path가 다른 구역', expected: 'deny', patch: { path: '/notices/demo' } },
  { name: 'unknown_route', label: '경로표에 없는 관리 경로', expected: 'deny',
    patch: { path: '/admin/export', route: 'GET /admin/export' } },
  { name: 'own_note_restore', label: '등록 기기의 자기 메모 한 건 복원', expected: 'allow',
    patch: { method: 'POST', path: '/restore/notes/demo', route: 'POST /restore/notes/:id' } },
  { name: 'notice_restore', label: '공지 구역 복원 경로', expected: 'deny',
    patch: { method: 'POST', path: '/restore/notices/demo', route: 'POST /restore/notices/:id' } },
  { name: 'restore_with_query', label: '쿼리가 붙은 복원 요청', expected: 'deny',
    patch: { method: 'POST', path: '/restore/notes/demo', route: 'POST /restore/notes/:id', queryLength: 9 } },
  { name: 'anomaly', label: '새벽 + 처음 보는 네트워크 + 대량 읽기', expected: 'step_up', patch: odd },
  { name: 'anomaly_stepped_up', label: '같은 이상 사건 + 60초 전 재로그인', expected: 'allow',
    patch: { ...odd, stepUp: { verified: true, authAgeSeconds: 60 } } },
  { name: 'forged_signal_source', label: '클라이언트 헤더 출처의 이상 신호(근거로 쓰지 않음)', expected: 'allow',
    patch: { ...odd, signals: { ...odd.signals, source: 'client_header' } } },
]);

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

// 판정기 하나에 묶음 전체를 넣어 응답을 모읍니다. 형식이 틀린 응답은 'invalid'로 둡니다.
export async function runProbes(decide) {
  const results = [];
  for (const probe of PROBES) {
    const request = { ...base(), ...probe.patch };
    let decision = 'invalid';
    let reasonCode = null;
    try {
      const out = await decide(request);
      if (out && Object.keys(out).sort().join(',') === RESPONSE_KEYS && out.requestId === request.requestId
        && out.schema === 'aleph.decision.v1' && Array.isArray(out.ruleIds)) {
        decision = out.decision;
        reasonCode = out.reasonCode;
      }
    } catch {
      decision = 'error';
    }
    results.push({ name: probe.name, label: probe.label, expected: probe.expected, decision, reasonCode });
  }
  return results;
}
