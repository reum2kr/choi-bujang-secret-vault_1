// GET /api/notes  : 로그인한 사용자의 메모 배열 [{id,title,body}]
// POST /api/notes : {id?, title, body} 추가 → 201 {id}
// owner_id는 서버가 확인한 사용자 ID로만 채웁니다.
import { randomUUID } from 'node:crypto';
import { UUID, dbError, fail, invalidNote, readBody, requireLogin, send } from '../../lib/notes-server.mjs';

export default async function handler(request, response) {
  if (request.method !== 'GET' && request.method !== 'POST') {
    response.setHeader('Allow', 'GET, POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET·POST 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;

  if (request.method === 'GET') {
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
  const { error } = await login.db
    .from('notes')
    .insert({ id, title: body.title.trim(), body: body.body, owner_id: login.userId });
  if (error?.code === '23505') return fail(response, 409, 'ID_TAKEN', '이미 있는 id입니다.');
  if (error) return dbError(response, error);
  return send(response, 201, { id });
}
