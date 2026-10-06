// 로그인·로그아웃을 서버에서 대신 처리합니다. 화면 코드에는 Supabase 주소·키가 없습니다.
// SUPABASE_URL, SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고 응답·로그에 넣지 않습니다.
// 화면에는 짧게 쓰는 access token만 주고, refresh token은 JS가 읽을 수 없는 httpOnly 쿠키에 둡니다.
import { createClient } from '@supabase/supabase-js';
import { fail, send } from './notes-server.mjs';

const COOKIE = 'vault_refresh';
const COOKIE_PATH = '/api/auth';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7일

// 요청마다 새 클라이언트를 만들어 사용자 세션이 서로 섞이지 않게 합니다.
export function authClient(response) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) {
    console.error('auth: 서버 환경변수가 설정되지 않았습니다.');
    fail(response, 500, 'SERVER_NOT_CONFIGURED', '서버 설정을 확인해 주세요.');
    return null;
  }
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

// 브라우저 폼이 아닌 다른 사이트에서 몰래 보내는 요청을 줄이기 위해 JSON + 사용자 정의 헤더만 받습니다.
export function postOnly(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    fail(response, 405, 'METHOD_NOT_ALLOWED', 'POST 요청만 받습니다.');
    return false;
  }
  if (request.headers['x-vault-request'] !== '1') {
    fail(response, 403, 'BAD_REQUEST_ORIGIN', '화면에서 보낸 요청만 받습니다.');
    return false;
  }
  return true;
}

export function readRefreshCookie(request) {
  const raw = request.headers.cookie ?? '';
  for (const part of raw.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === COOKIE) return decodeURIComponent(rest.join('='));
  }
  return null;
}

export function setRefreshCookie(response, token) {
  response.setHeader('Set-Cookie',
    `${COOKIE}=${encodeURIComponent(token)}; Path=${COOKIE_PATH}; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`);
}

export function clearRefreshCookie(response) {
  response.setHeader('Set-Cookie',
    `${COOKIE}=; Path=${COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
}

// 화면에 돌려줄 값만 고릅니다. refresh token은 절대 본문에 넣지 않습니다.
export function sendSession(response, session) {
  setRefreshCookie(response, session.refresh_token);
  return send(response, 200, {
    accessToken: session.access_token,
    expiresAt: session.expires_at,
    email: session.user?.email ?? '',
  });
}
