// 11단계 기기 승인 (Vercel Hobby 요금제의 서버 함수 12개 한도 때문에 두 경로를 한 함수에 둡니다. 주소는 그대로입니다.)
//  GET  /api/device/status  → 이 기기의 승인 상태(서버 등록부 기준). 응답에는 승인 여부·상태·요청 코드만 있습니다.
//  POST /api/device/request → 승인 요청(항상 「승인 대기」로만 기록, 절대 승인하지 않음). 본문은 비어 있어야 하고
//                             approved·role·deviceId 같은 값을 보내면 400. 승인은 SQL Editor의 approve_vault_device로만 됩니다.
// 로그인이 필요합니다. 앱 설치 여부, 요청 머리글·쿼리의 값은 승인 근거로 쓰지 않습니다.
import { fail, readBody, requireLogin, send } from '../../lib/notes-server.mjs';
import { deviceHash, deviceState, newDeviceValue, readDeviceCookie, setDeviceCookie, stateBody } from '../../lib/device-server.mjs';

function emptyBody(raw) {
  if (raw === undefined || raw === null || raw === '') return true;
  const body = readBody({ body: raw });
  return Boolean(body) && Object.keys(body).length === 0;
}

// 경로의 마지막 칸만 봅니다. Vercel이 붙이는 ?action=… 외의 쿼리는 받지 않습니다.
function routeOf(request) {
  const raw = typeof request.url === 'string' ? request.url : '';
  const [path, query = ''] = raw.split('?');
  const action = path.split('/').filter(Boolean).pop() ?? '';
  const extra = [...new URLSearchParams(query).entries()].filter(([k, v]) => !(k === 'action' && v === action));
  return { action, extraQuery: extra.length > 0 };
}

async function status(request, response) {
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

async function requestApproval(request, response, extraQuery) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  if (!emptyBody(request.body) || extraQuery) {
    return fail(response, 400, 'DEVICE_INPUT_NOT_ALLOWED', '승인 요청에는 값을 보낼 수 없습니다. 승인 여부는 서버가 정합니다.');
  }
  let value = readDeviceCookie(request);
  if (!value) {
    value = newDeviceValue();
    setDeviceCookie(response, value);
  }
  // 이미 요청했거나 결정된 기기는 그대로 둡니다(승인·취소 상태를 이 요청으로 바꾸지 않음). 처음일 때만 「승인 대기」로 넣습니다.
  const before = await deviceState(login.db, login.userId, value);
  if (!before.ok) return fail(response, 502, 'DEVICE_STATE_UNAVAILABLE', '기기 승인 상태를 확인하지 못했습니다.');
  if (before.state === 'unregistered') {
    const { error } = await login.db.from('vault_devices')
      .insert({ device_hash: deviceHash(value), owner_id: login.userId, status: 'pending' });
    if (error && error.code !== '23505') {
      console.error('device: 승인 요청을 기록하지 못했습니다.', error?.code ?? 'unknown');
      return fail(response, 502, 'DEVICE_REQUEST_FAILED', '승인 요청을 기록하지 못했습니다.');
    }
  }
  const s = await deviceState(login.db, login.userId, value);
  if (!s.ok) return fail(response, 502, 'DEVICE_STATE_UNAVAILABLE', '기기 승인 상태를 확인하지 못했습니다.');
  return send(response, 202, stateBody(s));
}

export default async function handler(request, response) {
  const { action, extraQuery } = routeOf(request);
  if (action === 'status') return status(request, response);
  if (action === 'request') return requestApproval(request, response, extraQuery);
  return fail(response, 404, 'NOT_FOUND', '없는 경로입니다.');
}
