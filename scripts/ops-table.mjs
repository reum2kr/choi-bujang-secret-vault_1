// 12단계 제작 2: npm run ops:table
// 1~11단계의 정상·금지 요청을 실제 배포에 다시 보내고, 정상·금지 구분, 기대 결과, 실제 API 결과, 요청 ID, 확인 시각을 한 표로 만듭니다.
// - 요청 ID는 배포가 응답에 붙인 x-vercel-id입니다. 요청을 보내지 못했거나 보내지 않은 점검은 「미실행」으로 둡니다.
// - 이 표는 이 저장소의 직접 점검입니다. 심판의 41종 공격 시험을 통과 처리하지 않습니다(그 결과는 심판 판정으로만 확인).
// - B·A 계정 요청은 Codespaces 비밀값(ALEPH_B_EMAIL·ALEPH_B_PASSWORD, ALEPH_A_EMAIL·ALEPH_A_PASSWORD)이 있을 때만 보냅니다.
// - 결과는 artifacts/ops-table.md·artifacts/ops-table.json에 씁니다(artifacts/는 커밋하지 않음). 토큰·이메일·메모 본문은 넣지 않습니다.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { getRequestLog, runAttackChecks } from '../src/attack-check.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
const KIND = {
  anonymous_api_read: '금지', forged_token_read: '금지', cross_user_note_read: '금지(+A 정상 유지)', anon_original_api_read: '금지',
  browser_key_exposure: '금지', registered_device_read: '정상', unregistered_device_read: '금지', anomalous_context_read: '정상·금지',
  zone_decider_rules: '정상·금지', anonymous_notice_read: '금지', zone_api_cross_owner: '금지', detect_normal_device: '정상',
  detect_doppelganger_burst: '금지', restore_anonymous: '금지', policy_snapshot_verified: '정상·금지', restore_b_deleted_note: '정상·금지',
  restore_b_tampered_note: '정상·금지', post_restore_retest: '정상·금지', device_approval_gate: '정상·금지', ops_room_summary: '정상',
};
// 한 번의 HTTP 응답을 여러 점검이 함께 쓰는 경우(서버 /api/ops?case=…, B 로그인 재시험)
const SOURCE_CASE = {
  cross_user_note_read: 'post_restore_retest', zone_api_cross_owner: 'post_restore_retest',
};
const secret = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|\bsb_secret_[A-Za-z0-9_-]{12,}|\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu;
const cell = (v) => String(v ?? '').replace(/\|/gu, '/').replace(/\s+/gu, ' ').trim();

try {
  const started = new Date().toISOString();
  const checks = await runAttackChecks(config);
  const log = getRequestLog();
  const rows = checks.map((c) => {
    const reqs = log.filter((r) => r.caseId === (SOURCE_CASE[c.attackId] ?? c.attackId));
    const ids = reqs.map((r) => r.requestId).filter(Boolean);
    return {
      stage: c.stage, attackId: c.attackId, kind: KIND[c.attackId] ?? '-', expected: c.expected, observed: c.observed,
      result: c.result,
      requests: reqs.length ? reqs.map((r) => `${r.method} ${r.path} → ${r.status}`).join(', ') : '없음(서버 요청 없이 로컬 실행)',
      requestIds: ids.length ? ids : null,
      checkedAt: reqs.length ? `${reqs[0].at} ~ ${reqs.at(-1).at}` : started,
    };
  }).sort((a, b) => a.stage - b.stage);
  const counts = { total: rows.length, blocked: rows.filter((r) => r.result === 'blocked').length,
    breached: rows.filter((r) => r.result === 'breached').length, notRun: rows.filter((r) => r.result === 'not_run').length,
    requests: log.length, requestsWithId: log.filter((r) => r.requestId).length };
  const out = { schema: 'aleph.ops.table.v1', deployment: config.publicAppUrl, step: config.step, startedAt: started,
    note: '이 저장소의 직접 점검입니다. 심판의 41종 공격 시험은 이 표로 통과 처리하지 않습니다.', counts, rows,
    requests: log.map(({ caseId, method, path, status, requestId, at }) => ({ caseId, method, path, status, requestId, at })) };
  const json = JSON.stringify(out, null, 2);
  if (secret.test(json)) throw new Error('표에 비밀값 또는 연락처로 보이는 내용이 있어 쓰지 않았습니다.');
  const md = [
    `# 1~11단계 정상·금지 요청 표 (${started})`, '',
    `배포 ${config.publicAppUrl} · 점검 ${counts.total}개(기대대로 ${counts.blocked}, 기대와 다름 ${counts.breached}, 미실행 ${counts.notRun}) · HTTP 요청 ${counts.requests}건(요청 ID 있음 ${counts.requestsWithId}건)`,
    '', '이 표는 이 저장소의 직접 점검입니다. 심판의 41종 공격 시험은 이 표로 통과 처리하지 않습니다.', '',
    '| 단계 | 점검 | 정상·금지 | 기대 결과 | 실제 API 결과 | 결과 | 요청(응답 상태) | 요청 ID | 확인 시각 |',
    '|---|---|---|---|---|---|---|---|---|',
    ...rows.map((r) => `| ${r.stage} | ${r.attackId} | ${r.kind} | ${cell(r.expected)} | ${cell(r.observed)} | ${r.result === 'not_run' ? '미실행' : r.result === 'breached' ? '기대와 다름' : '기대대로'} | ${cell(r.requests)} | ${cell(r.requestIds ? r.requestIds.slice(0, 2).join(', ') + (r.requestIds.length > 2 ? ` 외 ${r.requestIds.length - 2}건` : '') : '-')} | ${cell(r.checkedAt)} |`),
    '',
  ].join('\n');
  mkdirSync(join(root, 'artifacts'), { recursive: true });
  writeFileSync(join(root, 'artifacts', 'ops-table.json'), `${json}\n`, 'utf8');
  writeFileSync(join(root, 'artifacts', 'ops-table.md'), md, 'utf8');
  process.stdout.write(`${md}\n표를 artifacts/ops-table.md, artifacts/ops-table.json에 썼습니다.\n`);
} catch (error) {
  process.stderr.write(`요청 표 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}
