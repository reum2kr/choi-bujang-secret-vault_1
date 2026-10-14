// 11단계: 기기 승인 상태는 서버가 등록부(vault_devices)에서 읽어 정합니다.
// 기기 ID는 서버가 만든 무작위 값이고, 브라우저에는 httpOnly 쿠키로만 둡니다(자바스크립트·localStorage·서비스 워커 캐시에 없음).
// 등록부에는 그 값의 SHA-256만 저장합니다. 기기 개인키는 만들지 않습니다.
// 서버는 「승인 대기」 요청을 넣고 상태를 읽기만 합니다. 승인은 SQL Editor의 approve_vault_device로만 됩니다.
import { createHash, randomBytes } from 'node:crypto';

export const DEVICE_COOKIE = 'vault_device';
const DEVICE_VALUE = /^[A-Za-z0-9_-]{43}$/u;
const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

export function readDeviceCookie(request) {
  const header = typeof request.headers?.cookie === 'string' ? request.headers.cookie : '';
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === DEVICE_COOKIE) {
      const value = rest.join('=');
      return DEVICE_VALUE.test(value) ? value : null;
    }
  }
  return null;
}

export function newDeviceValue() {
  return randomBytes(32).toString('base64url');
}

export function deviceHash(value) {
  return sha256(value);
}

export function setDeviceCookie(response, value) {
  response.setHeader('Set-Cookie', `${DEVICE_COOKIE}=${value}; Path=/api/device; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000`);
}

// 등록부에서 이 기기(쿠키)와 로그인 사용자의 상태를 읽습니다. 승인은 status가 정확히 'approved'일 때만입니다.
export async function deviceState(db, userId, value) {
  if (!value) return { ok: true, approved: false, state: 'unregistered', requestCode: null };
  const hash = deviceHash(value);
  const { data, error } = await db.from('vault_devices')
    .select('status').eq('device_hash', hash).eq('owner_id', userId).maybeSingle();
  if (error) return { ok: false };
  const state = data?.status ?? 'unregistered';
  return { ok: true, approved: state === 'approved', state, requestCode: data ? hash.slice(0, 12) : null };
}

export function stateBody(s) {
  return {
    approved: s.approved === true,
    state: s.state,
    reason: s.approved === true ? 'device_registered' : 'device_not_registered',
    requestCode: s.requestCode,
    decidedBy: 'server',
  };
}
