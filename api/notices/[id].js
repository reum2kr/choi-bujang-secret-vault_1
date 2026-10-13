// GET /api/notices/:id : 로그인한 사용자 누구나 공지 한 건 {id,title,body}, 없으면 404
// PUT /api/notices/:id : 강사만 {title, body}로 수정. 일반 학생은 403
// 8단계 제작 3: 강사 여부는 DB의 instructors 표에 저장된 사용자 ID로만 판단합니다.
//   화면 메뉴나 요청 본문의 role·isInstructor 같은 값은 믿지 않습니다.
import { UUID, dbError, fail, invalidNote, pathId, readBody, requireLogin, send } from '../../lib/notes-server.mjs';
import { logDeny, markResource } from '../../lib/zones.mjs';

const notFound = (response) => fail(response, 404, 'NOT_FOUND', '공지를 찾을 수 없습니다.');

async function isInstructor(db, userId) {
  const { data, error } = await db.from('instructors').select('user_id').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return data?.user_id === userId;
}

export default async function handler(request, response) {
  if (!['GET', 'PUT'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET·PUT 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  const { db, userId } = login;

  const { id, query } = pathId(request);
  if (query) {
    logDeny('notices', request.method, 'query_not_allowed');
    return fail(response, 400, 'QUERY_NOT_ALLOWED', '한 건 주소에는 쿼리를 붙일 수 없습니다.');
  }
  if (!UUID.test(id)) {
    logDeny('notices', request.method, 'bad_id');
    return notFound(response);
  }
  markResource(response, 'notices', id);

  if (request.method === 'GET') {
    const { data, error } = await db.from('notices').select('id, title, body').eq('id', id).maybeSingle();
    if (error) return dbError(response, error);
    return data ? send(response, 200, data) : notFound(response);
  }

  // PUT: 저장된 강사 권한을 먼저 대조합니다. 본문에 role이 있어도 무시합니다.
  let allowed = false;
  try {
    allowed = await isInstructor(db, userId);
  } catch (error) {
    return dbError(response, error);
  }
  if (!allowed) {
    logDeny('notices', 'PUT', 'not_instructor');
    return fail(response, 403, 'INSTRUCTOR_REQUIRED', '강사만 공지를 수정할 수 있습니다.');
  }
  const body = readBody(request);
  const problem = invalidNote(body);
  if (problem) return fail(response, 400, 'INVALID_NOTICE', problem);
  const { data, error } = await db.from('notices')
    .update({ title: body.title.trim(), body: body.body, updated_by: userId, updated_at: new Date().toISOString() })
    .eq('id', id).select('id, title, body');
  if (error) return dbError(response, error);
  return data?.length ? send(response, 200, data[0]) : notFound(response);
}
