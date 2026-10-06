// GET /api/notes/:id    : 본인 메모 {id,title,body}, 아니면 404
// PUT /api/notes/:id    : 본문 {title, body}로 본인 메모만 수정, 아니면 404
// DELETE /api/notes/:id : 본인 메모만 삭제, 아니면 404 (삭제 뒤 GET도 404)
// 4단계: 서버가 토큰으로 확인한 사용자 ID와 DB의 owner_id를 비교합니다.
//   - URL·쿼리·본문의 owner_id는 믿지 않습니다. owner_id는 이 API로 바꿀 수 없습니다.
//   - 남의 메모는 "없는 메모"와 똑같이 404로 거부해서 존재 여부도 알려 주지 않습니다.
import { UUID, dbError, fail, invalidNote, readBody, requireLogin, send } from '../../lib/notes-server.mjs';

const notFound = (response) => fail(response, 404, 'NOT_FOUND', '메모를 찾을 수 없습니다.');

// 본인 소유의 행만 찾습니다. 남의 행이거나 없으면 null.
async function findOwned(db, id, userId) {
  return db.from('notes').select('id, title, body, owner_id')
    .eq('id', id).eq('owner_id', userId).maybeSingle();
}

export default async function handler(request, response) {
  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET·PUT·DELETE 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  const { db, userId } = login;

  const id = String(request.query?.id ?? '');
  if (!UUID.test(id)) return notFound(response);

  // 기존 행의 소유자가 본인인지 먼저 확인합니다(GET·PUT·DELETE 공통).
  const { data: existing, error: findError } = await findOwned(db, id, userId);
  if (findError) return dbError(response, findError);
  if (!existing || existing.owner_id !== userId) return notFound(response);

  if (request.method === 'GET') {
    return send(response, 200, { id: existing.id, title: existing.title, body: existing.body });
  }

  if (request.method === 'PUT') {
    const body = readBody(request);
    const problem = invalidNote(body);
    if (problem) return fail(response, 400, 'INVALID_NOTE', problem);
    // 새 행의 소유자도 본인이어야 합니다. 다른 소유자로 바꾸려는 요청은 거부합니다.
    for (const key of ['owner_id', 'ownerId', 'userId', 'user_id']) {
      if (key in body && body[key] !== userId) {
        return fail(response, 403, 'OWNER_CHANGE_FORBIDDEN', '메모의 소유자는 바꿀 수 없습니다.');
      }
    }
    const { data, error } = await db
      .from('notes').update({ title: body.title.trim(), body: body.body })
      .eq('id', id).eq('owner_id', userId)
      .select('id, title, body, owner_id');
    if (error) return dbError(response, error);
    const row = data?.[0];
    if (!row || row.owner_id !== userId) return notFound(response);
    return send(response, 200, { id: row.id, title: row.title, body: row.body });
  }

  const { data, error } = await db
    .from('notes').delete().eq('id', id).eq('owner_id', userId).select('id');
  if (error) return dbError(response, error);
  return data?.length ? send(response, 200, { id, deleted: true }) : notFound(response);
}
