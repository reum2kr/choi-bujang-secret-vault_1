// 11단계 제작 1·2: GET /api/device/status → 이 기기의 승인 상태(서버 등록부 기준)
// 로그인이 필요합니다. 응답에는 승인 여부·상태·요청 코드만 있고 메모나 토큰은 없습니다.
// 앱 설치 여부, 요청 머리글·쿼리의 값은 승인 근거로 쓰지 않습니다.
import { fail, requireLogin, send } from '../../lib/notes-server.mjs';
import { deviceState, readDeviceCookie, stateBody } from '../../lib/device-server.mjs';

export default async function handler(request, response) {
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'GET 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  const s = await deviceState(login.db, login.userId, readDeviceCookie(request));
  if (!s.ok) return fail(response, 502, 'DEVICE_STATE_UNAVAILABLE', '기기 승인 상태를 확인하지 못했습니다. 자료를 열지 않습니다.');
  return send(response, 200, stateBody(s));
}
