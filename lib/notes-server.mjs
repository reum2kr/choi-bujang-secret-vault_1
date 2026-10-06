// 메모 API 공통 부분. api/ 아래가 아니라서 그 자체로는 공개 주소가 되지 않습니다.
// 토큰 검사는 시작 틀의 src/verify-login.mjs만 사용합니다(고치지 않음).
// SUPABASE_URL, SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고 응답·로그에 넣지 않습니다.
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
export const TITLE_MAX = 100;
export const BODY_MAX = 2000;

let verifyLogin;
let supabase;

export function send(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  return response.status(status).json(payload);
}

export function fail(response, status, error, message) {
  return send(response, status, { error, message });
}

// 로그인 확인. 실패하면 응답을 이미 보낸 뒤 null을 돌려줍니다.
// 브라우저가 보낸 userId·role·owner_id 같은 값은 보지 않고, 토큰 검사 결과만 믿습니다.
export async function requireLogin(request, response) {
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    console.error('notes: 서버 환경변수가 설정되지 않았습니다.');
    fail(response, 500, 'SERVER_NOT_CONFIGURED', '서버 설정을 확인해 주세요.');
    return null;
  }
  let login = null;
  try {
    verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
    login = await verifyLogin(request.headers.authorization);
  } catch {
    console.error('notes: 로그인 검사기를 만들지 못했습니다. identityProvider 설정을 확인하세요.');
    fail(response, 500, 'LOGIN_VERIFIER_ERROR', '로그인 검사 설정을 확인해 주세요.');
    return null;
  }
  if (!login) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    fail(response, 401, 'LOGIN_REQUIRED', '로그인한 사용자만 자료를 볼 수 있습니다.');
    return null;
  }
  supabase ??= createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return { userId: login.userId, db: supabase };
}

export function readBody(request) {
  const raw = request.body;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch { /* 아래에서 형식 오류로 처리 */ }
  }
  return null;
}

// title·body를 검사합니다. 문제가 있으면 오류 문구, 없으면 null.
export function invalidNote(body) {
  if (!body) return 'JSON 본문이 필요합니다.';
  if (typeof body.title !== 'string' || !body.title.trim() || body.title.length > TITLE_MAX) {
    return `title은 1~${TITLE_MAX}자 문자열이어야 합니다.`;
  }
  if (typeof body.body !== 'string' || body.body.length > BODY_MAX) {
    return `body는 ${BODY_MAX}자 이하 문자열이어야 합니다.`;
  }
  return null;
}

export function dbError(response, error) {
  console.error('notes: 데이터베이스 요청이 실패했습니다.', error?.code ?? 'unknown');
  return fail(response, 502, 'NOTES_UNAVAILABLE', '자료를 처리하지 못했습니다.');
}
