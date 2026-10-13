// GET /api/notes  : 로그인한 사용자의 메모 배열 [{id,title,body}]
// POST /api/notes : {id?, title, body} 추가 → 201 {id}
// owner_id는 서버가 확인한 사용자 ID로만 채웁니다.
// 10단계: 새 메모를 만들면 그 처음 내용을 비공개 사본 표 notes_backup에 한 건 남기고(덧붙이기만 가능),
// 다시 읽어 내용 해시를 확인합니다. 복원(POST /api/restore/notes/:id)은 이 처음 사본을 기준으로 합니다.
import { randomUUID } from 'node:crypto';
import { contentSha256 } from '../../lib/backup-verify.mjs';
import { UUID, dbError, fail, invalidNote, readBody, requireLogin, send } from '../../lib/notes-server.mjs';
import { markResource } from '../../lib/zones.mjs';

export default async function handler(request, response) {
  if (request.method !== 'GET' && request.method !== 'POST') {
    response.setHeader('Allow', 'GET, POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET·POST 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;

  if (request.method === 'GET') {
    markResource(response, 'notes');
    const { data, error } = await login.db
      .from('notes')
      .select('id, title, body')
      .eq('owner_id', login.userId)
      .order('created_at', { ascending: true });
    if (error) return dbError(response, error);
    return send(response, 200, data);
  }

  const body = readBody(request);
  const problem = invalidNote(body);
  if (problem) return fail(response, 400, 'INVALID_NOTE', problem);
  if (body.id !== undefined && (typeof body.id !== 'string' || !UUID.test(body.id))) {
    return fail(response, 400, 'INVALID_ID', 'id는 UUID 형식이어야 합니다.');
  }
  const id = (body.id ?? randomUUID()).toLowerCase();
  const title = body.title.trim();
  const { error } = await login.db
    .from('notes')
    .insert({ id, title, body: body.body, owner_id: login.userId });
  if (error?.code === '23505') return fail(response, 409, 'ID_TAKEN', '이미 있는 id입니다.');
  if (error) return dbError(response, error);
  markResource(response, 'notes', id);
  const backedUp = await backupOnCreate(login.db, { id, owner_id: login.userId, title, body: body.body });
  return send(response, 201, { id, backedUp });
}

// 처음 사본 남기기 → 다시 읽어 ID·소유자·내용 해시 확인. 실패해도 메모 만들기는 그대로 두고 로그만 남깁니다.
async function backupOnCreate(db, note) {
  const contentHash = contentSha256(note.title, note.body);
  const { error } = await db.from('notes_backup')
    .insert({ ...note, content_sha256: contentHash, backup_label: 'on-create' });
  if (error && error.code !== '23505') {
    console.error('notes: 사본을 남기지 못했습니다.', error?.code ?? 'unknown');
    return false;
  }
  const { data: copy } = await db.from('notes_backup')
    .select('id, owner_id, title, body, content_sha256').eq('id', note.id).maybeSingle();
  const ok = Boolean(copy) && copy.id === note.id && copy.owner_id === note.owner_id
    && copy.content_sha256 === contentHash && contentSha256(copy.title, copy.body) === contentHash;
  if (!ok) console.error('notes: 남긴 사본을 다시 읽어 확인하지 못했습니다.');
  return ok;
}
