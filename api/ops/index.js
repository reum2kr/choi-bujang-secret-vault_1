// 12단계 제작 1: GET /api/ops → 탈환 작전실 요약
// 학생 판정기 규칙, 탐지 사건, 회수 상태, 복구 버전을 실제로 읽은 값으로만 돌려줍니다. 항목마다 출처(source)를 붙입니다.
//   server_record : Supabase 서버 기록(restore_audit, notes_policy_audit, vault_devices)을 이번 요청에서 읽어 센 값
//   code          : 배포된 코드(src/decider.mjs, policy/safe/manifest.json)를 이번 요청에서 읽어 검증한 값
//   virtual       : 고정된 가상 입력으로 학생 규칙을 실행한 값(실제 사건 아님)
//   not_run       : 이 저장소에서 보낼 수 없어 실행하지 않음(제공 엔진의 실제 집행)
//   unavailable   : 읽지 못함 → 수치를 0으로 채우지 않고 null로 둡니다
// 메모 제목·본문, 사용자 ID, 이메일, 기기 지문, 토큰은 읽지도 돌려주지도 않습니다(감사 기록은 결과 이름과 시각만 셉니다).
import { createClient } from '@supabase/supabase-js';
import { RULE_IDS } from '../../src/decider.mjs';
import { runRuleCheck } from '../../src/rule-check.mjs';
import { verifyPolicyManifest } from '../../lib/policy-pin.mjs';
import policyManifest from '../../policy/safe/manifest.json' with { type: 'json' };
import notesManifest from '../../backup/notes-manifest.json' with { type: 'json' };

let db;
function client() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return null;
  db ??= createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
  return db;
}

function countBy(rows, key) {
  const out = {};
  for (const row of rows) out[row[key]] = (out[row[key]] ?? 0) + 1;
  return out;
}

async function read(q) {
  try {
    const { data, error } = await q;
    return error || !Array.isArray(data) ? null : data;
  } catch {
    return null;
  }
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  if (Object.keys(request.query ?? {}).length) return response.status(400).json({ error: 'QUERY_NOT_ALLOWED' });
  const checkedAt = new Date().toISOString();
  const supa = client();

  const policy = verifyPolicyManifest(policyManifest);
  const detect = await runRuleCheck('detect');
  const devices = supa ? await read(supa.from('vault_devices').select('status')) : null;
  const restoreRows = supa ? await read(supa.from('restore_audit').select('result, at')) : null;
  const policyRows = supa ? await read(supa.from('notes_policy_audit').select('action, result, at')) : null;

  const actions = Object.values(detect.results).map((r) => r.action);
  const lastOf = (rows) => (rows?.length ? rows.map((r) => r.at).sort().at(-1) : null);
  const policyTests = policyRows?.filter((r) => r.action === 'policy_restore_test') ?? null;
  const lastPolicyTest = policyTests?.length ? policyTests.slice().sort((a, b) => String(a.at).localeCompare(String(b.at))).at(-1) : null;

  return response.status(200).json({
    checkedAt,
    rules: {
      source: 'code',
      ruleCount: RULE_IDS.length,
      ruleIds: [...RULE_IDS],
      policyVersion: policy.ok ? policy.version : null,
      policyRevision: policy.ok ? policy.policyRevision : null,
      policyVerified: policy.ok,
    },
    detection: {
      source: 'virtual',
      cases: Object.keys(detect.results).length,
      observe: actions.filter((a) => a === 'observe').length,
      proposeRevocation: actions.filter((a) => a === 'propose_revocation').length,
      liveEvents: 'not_run',
    },
    revocation: {
      source: devices ? 'server_record' : 'unavailable',
      devices: devices ? { total: devices.length, ...{ pending: 0, approved: 0, revoked: 0, ...countBy(devices, 'status') } } : null,
      engineRevocation: 'not_run',
    },
    restore: {
      source: restoreRows ? 'server_record' : 'unavailable',
      noteBackupLabel: notesManifest.label,
      policyVersion: policy.ok ? policy.version : null,
      restoreAudit: restoreRows ? { total: restoreRows.length, byResult: countBy(restoreRows, 'result'), lastAt: lastOf(restoreRows) } : null,
      policyRestoreTest: policyTests ? { total: policyTests.length, lastResult: lastPolicyTest?.result ?? null, lastAt: lastPolicyTest?.at ?? null } : null,
    },
  });
}
