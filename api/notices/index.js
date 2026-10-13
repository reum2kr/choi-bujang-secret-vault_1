// GET /api/notices : 로그인한 사용자 누구나 강사 공지 목록 [{id,title,body}]
// 공지 구역(notices)은 메모 구역(notes)과 다른 테이블·자원 ID를 씁니다.
import { dbError, fail, requireLogin, send } from '../../lib/notes-server.mjs';
import { markResource } from '../../lib/zones.mjs';

export default async function handler(request, response) {
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  markResource(response, 'notices');
  const { data, error } = await login.db
    .from('notices').select('id, title, body').order('created_at', { ascending: true });
  if (error) return dbError(response, error);
  return send(response, 200, data);
}
