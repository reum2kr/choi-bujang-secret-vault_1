// GET /api/notes/:id    : {id,title,body}, 없으면 404
// PUT /api/notes/:id    : {title, body}로 수정, 없으면 404
// DELETE /api/notes/:id : 삭제, 없으면 404 (삭제 뒤 GET도 404)
// ⚠ 3단계에서는 로그인 여부만 검사하고 소유자 검사는 하지 않습니다.
//   그래서 B가 A의 메모 id를 알면 읽고·고치고·지울 수 있습니다. 4단계에서 막습니다.
import { UUID, dbError, fail, invalidNote, readBody, requireLogin, send } from '../../lib/notes-server.mjs';

const notFound = (response) => fail(response, 404, 'NOT_FOUND', '메모를 찾을 수 없습니다.');

export default async function handler(request, response) {
  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET·PUT·DELETE 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;

  const id = String(request.query?.id ?? '');
  if (!UUID.test(id)) return notFound(response);

  if (request.method === 'GET') {
    const { data, error } = await login.db
      .from('notes').select('id, title, body').eq('id', id).maybeSingle();
    if (error) return dbError(response, error);
    return data ? send(response, 200, data) : notFound(response);
  }

  if (request.method === 'PUT') {
    const body = readBody(request);
    const problem = invalidNote(body);
    if (problem) return fail(response, 400, 'INVALID_NOTE', problem);
    const { data, error } = await login.db
      .from('notes').update({ title: body.title.trim(), body: body.body })
      .eq('id', id).select('id, title, body');
    if (error) return dbError(response, error);
    return data?.length ? send(response, 200, data[0]) : notFound(response);
  }

  const { data, error } = await login.db
    .from('notes').delete().eq('id', id).select('id');
  if (error) return dbError(response, error);
  return data?.length ? send(response, 200, { id, deleted: true }) : notFound(response);
}
