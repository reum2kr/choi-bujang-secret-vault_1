// GET /api/notices : 강사만 강사 공지 목록 [{id,title,body}]. 일반 학생은 403
// 공지 구역(notices)은 메모 구역(notes)과 다른 테이블·자원 ID를 씁니다.
import { dbError, fail, isInstructor, requireLogin, send } from '../../lib/notes-server.mjs';
import { logDeny, markResource } from '../../lib/zones.mjs';

export default async function handler(request, response) {
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  markResource(response, 'notices');
  let allowed = false;
  try {
    allowed = await isInstructor(login.db, login.userId);
  } catch (error) {
    return dbError(response, error);
  }
  if (!allowed) {
    logDeny('notices', 'GET', 'not_instructor');
    return fail(response, 403, 'INSTRUCTOR_REQUIRED', '강사 공지 구역은 강사만 볼 수 있습니다.');
  }
  const { data, error } = await login.db
    .from('notices').select('id, title, body').order('created_at', { ascending: true });
  if (error) return dbError(response, error);
  return send(response, 200, data);
}
