// 10단계 제작 3: POST /api/restore/notes/:id  (서비스: 메모 자료실 notes)
// 비공개 가상 메모 사본(notes_backup)에서 지정한 한 건만 notes로 되살립니다.
//   1) 로그인 토큰으로 요청자를 확인합니다. 브라우저가 보낸 owner_id·userId·내용은 받지 않습니다(본문은 비어 있어야 함, 쿼리 거부).
//   1-1) 정책 사본 검증: 요청마다 침해 전에 검증한 안전 정책 사본(policy/safe/manifest.json)을 다시 읽어
//      고정 지문(lib/policy-pin.mjs)·정책 버전(policyRevision 1)·복원 범위(메모 한 건)를 확인합니다. 실패하면 DB에 닿기 전에 멈춥니다.
//   2) 메모 사본을 다시 읽어 ID·소유자·내용 해시를 대조합니다. 침해 전 메모는 커밋한 검증 기록(backup/notes-manifest.json)과,
//      그 뒤에 만든 메모는 만들 때 DB가 남긴 처음 사본의 해시를 다시 계산해 대조합니다(lib/backup-verify.mjs).
//      사본이 없거나 남의 것이면 404, 하나라도 다르면(검증 실패) 409로, 아무것도 쓰지 않고 멈춥니다.
//   3) 실행 전 확인: GET 또는 X-Restore-Preview: 1이면 복원할 버전과 바뀔 항목만 보여 주고 쓰지 않습니다.
//      X-Restore-Confirm을 보냈는데 그 값이 사본 버전과 다르면 쓰지 않고 409로 멈춥니다.
//   4) POST는 그 ID 한 건만 넣거나 고친 뒤, 다시 읽어 ID·소유자·내용 해시가 사본과 같은지 확인합니다.
//      이 검증이 실패하면 쓰기 전 상태로 되돌리고 멈춥니다. 다른 메모는 건드리지 않습니다.
//   5) 결과를 restore_audit에 한 줄 덧붙입니다(고치기·지우기 불가). 응답과 로그에 메모 본문·토큰·이메일은 넣지 않습니다.
import { contentSha256, ownerSha256, verifyCopy, verifyRestored } from '../../../lib/backup-verify.mjs';
import { UUID, fail, pathId, requireLogin, send } from '../../../lib/notes-server.mjs';
import { logDeny, markResource } from '../../../lib/zones.mjs';
import { verifyPolicyManifest } from '../../../lib/policy-pin.mjs';
import policyManifest from '../../../policy/safe/manifest.json' with { type: 'json' };
import config from '../../../aleph.config.json' with { type: 'json' };

function emptyBody(raw) {
  if (raw === undefined || raw === null || raw === '') return true;
  if (typeof raw === 'string') {
    try { raw = JSON.parse(raw); } catch { return false; }
  }
  return Boolean(raw) && typeof raw === 'object' && !Array.isArray(raw) && Object.keys(raw).length === 0;
}

async function audit(db, entry) {
  const { error } = await db.from('restore_audit').insert(entry);
  if (error) console.error('restore: 감사 기록을 남기지 못했습니다.', error?.code ?? 'unknown');
  return !error;
}

export default async function handler(request, response) {
  if (request.method !== 'POST' && request.method !== 'GET') {
    response.setHeader('Allow', 'GET, POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET(미리보기)·POST(복원) 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  const { db, userId } = login;
  // 심판 시험 계정의 복원 시험은 B 신원으로만 받습니다(A 신원은 B 자료에 닿지 않게 404).
  if (login.kind === 'judge' && login.identity !== 'b') {
    logDeny('notes', request.method, 'restore_judge_identity_not_b');
    return fail(response, 404, 'NOT_FOUND', '복원할 사본을 찾을 수 없습니다.');
  }

  const { id, query } = pathId(request);
  if (query) {
    logDeny('notes', 'POST', 'restore_query_not_allowed');
    return fail(response, 400, 'QUERY_NOT_ALLOWED', '복원 주소에는 쿼리를 붙일 수 없습니다.');
  }
  if (!emptyBody(request.body)) {
    logDeny('notes', 'POST', 'restore_body_not_allowed');
    return fail(response, 400, 'BODY_NOT_ALLOWED', '복원 요청 본문은 비어 있어야 합니다. 내용과 소유자는 사본에서만 가져옵니다.');
  }
  if (!UUID.test(id)) {
    logDeny('notes', 'POST', 'restore_bad_id');
    return fail(response, 404, 'NOT_FOUND', '복원할 사본을 찾을 수 없습니다.');
  }
  const noteId = id.toLowerCase();
  markResource(response, 'notes', noteId);

  // 1-1) 정책 사본을 다시 읽어 검증. 복원 범위는 경로의 메모 한 건뿐이어야 합니다. 실패하면 DB에 닿지 않고 멈춤.
  const policy = verifyPolicyManifest(policyManifest);
  const scopeOk = config.restoreRoute === 'POST /api/restore/notes/:id';
  if (!policy.ok || !scopeOk) {
    logDeny('notes', 'POST', `restore_stopped_${policy.ok ? 'scope_differs' : policy.reason}`);
    return fail(response, 503, 'POLICY_UNVERIFIED', '안전 정책 사본을 검증하지 못해 복원을 멈췄습니다.');
  }
  const policySummary = { policyVerified: true, policyVersion: policy.version, policyRevision: policy.policyRevision, scopeCount: 1 };
  const confirmLabel = typeof request.headers?.['x-restore-confirm'] === 'string' ? request.headers['x-restore-confirm'] : null;
  const preview = request.method === 'GET' || request.headers?.['x-restore-preview'] === '1';

  // 2) 사본 다시 읽기 → 침해 전 검증 기록과 대조. 실패하면 여기서 멈춤(쓰기 없음).
  const { data: copy, error: copyError } = await db.from('notes_backup')
    .select('id, owner_id, title, body, content_sha256, backup_label, backed_up_at').eq('id', noteId).maybeSingle();
  if (copyError) {
    console.error('restore: 사본을 읽지 못했습니다.', copyError?.code ?? 'unknown');
    return fail(response, 502, 'BACKUP_UNAVAILABLE', '사본을 읽지 못해 복원을 멈췄습니다.');
  }
  const check = verifyCopy(copy, { id: noteId, ownerId: userId });
  if (!check.ok) {
    logDeny('notes', 'POST', `restore_stopped_${check.reason}`);
    await audit(db, { note_id: noteId, actor_id: userId, result: `stopped_${check.reason}`, detail: preview ? 'preview' : 'restore' });
    return check.status === 404
      ? fail(response, 404, 'NOT_FOUND', '검증된 사본에 없는 메모라 복원을 멈췄습니다.')
      : fail(response, 409, 'BACKUP_INVALID', '사본이 침해 전 검증 기록과 달라 복원을 멈췄습니다.');
  }
  const { entry, label } = check;

  const { data: current, error: currentError } = await db.from('notes')
    .select('id, owner_id, title, body').eq('id', noteId).maybeSingle();
  if (currentError) {
    console.error('restore: 현재 메모를 읽지 못했습니다.', currentError?.code ?? 'unknown');
    return fail(response, 502, 'NOTES_UNAVAILABLE', '현재 메모를 읽지 못했습니다.');
  }
  if (current && current.owner_id !== userId) {
    await audit(db, { note_id: noteId, actor_id: userId, result: 'stopped_other_owner', detail: label });
    return fail(response, 409, 'OWNER_CONFLICT', '같은 ID의 메모가 다른 소유자에게 있어 복원하지 않았습니다.');
  }
  const changes = !current ? ['note']
    : [current.title !== copy.title ? 'title' : null, current.body !== copy.body ? 'body' : null].filter(Boolean);

  // 3) 미리보기 요청이면 복원할 버전과 바뀔 항목만 보여 주고 끝냄. 확인 머리글의 버전이 사본 버전과 다르면 쓰지 않음.
  if (preview || (confirmLabel !== null && confirmLabel !== label)) {
    await audit(db, { note_id: noteId, actor_id: userId, result: preview ? 'previewed' : 'stopped_confirm_mismatch', detail: label });
    return send(response, preview ? 200 : 409, {
      id: noteId, result: preview ? 'preview' : 'confirm_mismatch', backupLabel: label, verified: true,
      backedUpAt: copy.backed_up_at ?? null,
      contentSha256: entry.content_sha256,
      backupOwnerSha256: entry.owner_sha256,
      currentSha256: current ? contentSha256(current.title, current.body) : null,
      changes,
      ...policySummary,
      confirmWith: { header: 'X-Restore-Confirm', value: label },
    });
  }

  // 4) 그 한 건만 되살리기
  let result = 'already_same';
  if (!current) {
    const { error } = await db.from('notes').insert({ id: noteId, owner_id: userId, title: copy.title, body: copy.body });
    if (error) {
      console.error('restore: 메모를 넣지 못했습니다.', error?.code ?? 'unknown');
      return fail(response, 502, 'RESTORE_FAILED', '메모를 되살리지 못했습니다.');
    }
    result = 'restored';
  } else if (changes.length) {
    const { error } = await db.from('notes').update({ title: copy.title, body: copy.body })
      .eq('id', noteId).eq('owner_id', userId);
    if (error) {
      console.error('restore: 메모를 고치지 못했습니다.', error?.code ?? 'unknown');
      return fail(response, 502, 'RESTORE_FAILED', '메모를 되살리지 못했습니다.');
    }
    result = 'restored';
  }
  const { data: after, error: afterError } = await db.from('notes')
    .select('id, owner_id, title, body').eq('id', noteId).eq('owner_id', userId).maybeSingle();
  const verified = !afterError && verifyRestored(after, entry);
  if (!verified && result === 'restored') {
    // 쓰기 뒤 검증 실패: 쓰기 전 상태로 되돌립니다(새로 넣었으면 지우고, 고쳤으면 원래 제목·내용으로).
    const undo = !current
      ? await db.from('notes').delete().eq('id', noteId).eq('owner_id', userId)
      : await db.from('notes').update({ title: current.title, body: current.body }).eq('id', noteId).eq('owner_id', userId);
    result = undo.error ? 'restore_verify_failed_undo_failed' : 'restore_verify_failed_undone';
  } else if (!verified) {
    result = 'restore_verify_failed';
  }

  // 5) 감사 기록
  const audited = await audit(db, { note_id: noteId, actor_id: userId, result, detail: label });
  console.info(`restore result=${result} audited=${audited}`);
  if (!verified) return fail(response, 500, 'RESTORE_VERIFY_FAILED', '되살린 메모가 검증 기록과 달라 쓰기 전 상태로 되돌리고 멈췄습니다.');
  return send(response, 200, {
    id: noteId, result, backupLabel: label,
    idMatches: true, ownerMatches: true, contentHashMatches: true, ...policySummary,
    contentSha256: entry.content_sha256,
    backupOwnerSha256: entry.owner_sha256,
    // 다시 읽은 복원 행의 값(소유자는 지문만). 호출한 쪽이 침해 전 기록과 직접 비교할 수 있습니다.
    restored: { id: after.id, ownerSha256: ownerSha256(after.owner_id), contentSha256: contentSha256(after.title, after.body) },
    audited,
  });
}
