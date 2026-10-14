// 11단계 제작 2: POST /api/device/request → 이 기기의 승인을 요청(승인 대기로 등록)
// 로그인이 필요합니다. 본문은 비어 있어야 하며 approved·role·deviceId 같은 값을 보내면 400으로 거부합니다.
// 이 요청은 절대 승인하지 않습니다. 결과는 항상 「승인 대기」이고, 승인은 SQL Editor의 approve_vault_device로만 됩니다.
import { fail, readBody, requireLogin, send } from '../../lib/notes-server.mjs';
import { deviceHash, deviceState, newDeviceValue, readDeviceCookie, setDeviceCookie, stateBody } from '../../lib/device-server.mjs';

function emptyBody(raw) {
  if (raw === undefined || raw === null || raw === '') return true;
  const body = readBody({ body: raw });
  return Boolean(body) && Object.keys(body).length === 0;
}

export default async function handler(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 받습니다.');
  }
  const login = await requireLogin(request, response);
  if (!login) return;
  if (!emptyBody(request.body) || (typeof request.url === 'string' && request.url.includes('?'))) {
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
