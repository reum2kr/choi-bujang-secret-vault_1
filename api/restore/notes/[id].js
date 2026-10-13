// 10단계 제작 3: POST /api/restore/notes/:id
// 비공개 가상 메모 사본(notes_backup)에서 지정한 한 건만 notes로 되살립니다. 서비스는 메모 자료실(notes)입니다.
//   1) 로그인 토큰으로 요청자를 확인합니다(브라우저가 보낸 owner_id·userId는 받지 않음, 본문은 비어 있어야 함).
//   2) 사본을 다시 읽어 ID·소유자를 대조하고, 제목·내용으로 지문(sha256)을 다시 계산해 저장된 지문과 대조합니다.
//      남의 메모이거나 사본이 없으면 404, 사본 지문이 틀리면 409로 중단합니다.
//   3) 그 ID 한 건만 넣거나 고칩니다(다른 메모는 건드리지 않음). 되살린 행을 다시 읽어 ID·소유자·지문이 사본과 같은지 확인합니다.
//   4) 결과를 restore_audit에 한 줄 덧붙입니다(고치기·지우기 불가). 응답과 로그에 메모 본문·토큰·이메일은 넣지 않습니다.
import { createHash } from 'node:crypto';
import { UUID, fail, pathId, requireLogin, send } from '../../../lib/notes-server.mjs';
import { logDeny, markResource } from '../../../lib/zones.mjs';

export const contentSha256 = (title, body) => createHash('sha256').update(`${title}\n${body}`, 'utf8').digest('hex');

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
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  const { db, userId } = login;

  const { id, query } = pathId(request);
  if (query) {
    logDeny('notes', 'POST', 'restore_query_not_allowed');
    return fail(response, 400, 'QUERY_NOT_ALLOWED', '복원 주소에는 쿼리를 붙일 수 없습니다.');
  }
  if (!emptyBody(request.body)) {
    logDeny('notes', 'POST', 'restore_body_not_allowed');
    return fail(response, 400, 'BODY_NOT_ALLOWED', '복원 요청 본문은 비어 있어야 합니다. 내용과 소유자는 사본에서만 가져옵니다.');
  }
  const notFound = async (reason) => {
    logDeny('notes', 'POST', reason);
    if (UUID.test(id)) await audit(db, { note_id: id.toLowerCase(), actor_id: userId, result: 'denied', detail: reason });
    return fail(response, 404, 'NOT_FOUND', '복원할 사본을 찾을 수 없습니다.');
  };
  if (!UUID.test(id)) return notFound('restore_bad_id');
  const noteId = id.toLowerCase();
  markResource(response, 'notes', noteId);

  // 2) 사본 다시 읽기·검증
  const { data: copy, error: copyError } = await db.from('notes_backup')
    .select('id, owner_id, title, body, content_sha256, backup_label').eq('id', noteId).maybeSingle();
  if (copyError) {
    console.error('restore: 사본을 읽지 못했습니다.', copyError?.code ?? 'unknown');
    return fail(response, 502, 'BACKUP_UNAVAILABLE', '사본을 읽지 못했습니다.');
  }
  if (!copy || copy.id !== noteId || copy.owner_id !== userId) return notFound('restore_not_owner_or_missing');
  if (contentSha256(copy.title, copy.body) !== copy.content_sha256) {
    await audit(db, { note_id: noteId, actor_id: userId, result: 'backup_hash_mismatch', detail: copy.backup_label });
    return fail(response, 409, 'BACKUP_INVALID', '사본의 내용 지문이 맞지 않아 복원을 중단했습니다.');
  }

  // 3) 그 한 건만 되살리기
  const { data: current, error: currentError } = await db.from('notes')
    .select('id, owner_id, title, body').eq('id', noteId).maybeSingle();
  if (currentError) {
    console.error('restore: 현재 메모를 읽지 못했습니다.', currentError?.code ?? 'unknown');
    return fail(response, 502, 'NOTES_UNAVAILABLE', '현재 메모를 읽지 못했습니다.');
  }
  if (current && current.owner_id !== userId) {
    await audit(db, { note_id: noteId, actor_id: userId, result: 'conflict_other_owner', detail: copy.backup_label });
    return fail(response, 409, 'OWNER_CONFLICT', '같은 ID의 메모가 다른 소유자에게 있어 복원하지 않았습니다.');
  }
  let result = 'already_matches';
  if (!current) {
    const { error } = await db.from('notes').insert({ id: noteId, owner_id: userId, title: copy.title, body: copy.body });
    if (error) {
      console.error('restore: 메모를 넣지 못했습니다.', error?.code ?? 'unknown');
      return fail(response, 502, 'RESTORE_FAILED', '메모를 되살리지 못했습니다.');
    }
    result = 'restored';
  } else if (contentSha256(current.title, current.body) !== copy.content_sha256) {
    const { error } = await db.from('notes').update({ title: copy.title, body: copy.body })
      .eq('id', noteId).eq('owner_id', userId);
    if (error) {
      console.error('restore: 메모를 고치지 못했습니다.', error?.code ?? 'unknown');
      return fail(response, 502, 'RESTORE_FAILED', '메모를 되살리지 못했습니다.');
    }
    result = 'restored';
  }

  // 되살린 행을 다시 읽어 ID·소유자·지문 대조
  const { data: after, error: afterError } = await db.from('notes')
    .select('id, owner_id, title, body').eq('id', noteId).eq('owner_id', userId).maybeSingle();
  const verified = !afterError && after && after.id === copy.id && after.owner_id === copy.owner_id
    && contentSha256(after.title, after.body) === copy.content_sha256;
  if (!verified) result = 'restore_verify_failed';
  const audited = await audit(db, { note_id: noteId, actor_id: userId, result, detail: copy.backup_label });
  console.info(`restore result=${result} audited=${audited}`);
  if (!verified) return fail(response, 500, 'RESTORE_VERIFY_FAILED', '되살린 메모가 사본과 같은지 확인하지 못했습니다.');
  return send(response, 200, {
    id: noteId,
    result,
    idMatches: true,
    ownerMatches: true,
    contentSha256: copy.content_sha256,
    backupLabel: copy.backup_label,
    audited,
  });
}
