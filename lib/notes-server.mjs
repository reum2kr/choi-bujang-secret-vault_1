// 메모 API 공통 부분. api/ 아래가 아니라서 그 자체로는 공개 주소가 되지 않습니다.
// 토큰 검사는 시작 틀의 src/verify-login.mjs만 사용합니다(고치지 않음).
// SUPABASE_URL, SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고 응답·로그에 넣지 않습니다.
import { createHash } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { decodeJwt, decodeProtectedHeader } from 'jose';
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
    console.warn(`login_fail ${describeAuth(request.headers.authorization)}`);
    response.setHeader('WWW-Authenticate', 'Bearer');
    fail(response, 401, 'LOGIN_REQUIRED', '로그인한 사용자만 자료를 볼 수 있습니다.');
    return null;
  }
  supabase ??= createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  if (login.kind === 'judge') console.info(`login_ok kind=judge identity=${login.identity}`);
  // kind·identity는 검증된 토큰에서만 옵니다(심판 시험 계정은 a·b). 10단계 복원은 심판 시험 계정 중 B만 받습니다.
  return { userId: ownerKey(login), db: supabase, kind: login.kind, identity: login.identity ?? null };
}

// 진단용: 로그인 실패 이유를 짧게 남깁니다. 토큰 원문·sub·이메일은 남기지 않습니다.
function describeAuth(header) {
  if (typeof header !== 'string' || !header) return 'auth=none';
  if (!/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(header)) {
    return `auth=present shape=bad scheme=${header.split(' ')[0].slice(0, 12)} len=${header.length}`;
  }
  try {
    const token = header.slice(7);
    const head = decodeProtectedHeader(token);
    const claims = decodeJwt(token);
    let issuer = 'other';
    if (claims.iss === config.judgeIssuer) issuer = 'judge';
    else if (claims.iss === config.identityProvider?.issuer) issuer = 'student';
    let audHost = 'none';
    try { audHost = new URL(config.publicAppUrl).hostname === claims.aud ? 'match' : 'mismatch'; } catch { audHost = 'unknown'; }
    const now = Math.floor(Date.now() / 1000);
    return [
      'auth=bearer', `iss=${issuer}`, `alg=${head.alg}`, `aud=${issuer === 'judge' ? audHost : 'n/a'}`,
      `role=${typeof claims.aleph_role === 'string' ? claims.aleph_role.slice(0, 12) : '-'}`,
      `identity=${typeof claims.aleph_identity === 'string' ? claims.aleph_identity.slice(0, 4) : '-'}`,
      `exp=${Number.isInteger(claims.exp) ? (claims.exp > now ? 'valid' : 'expired') : '-'}`,
      `age=${Number.isInteger(claims.iat) ? now - claims.iat : '-'}`,
    ].join(' ');
  } catch {
    return 'auth=bearer decode=failed';
  }
}

// 8단계: 자료의 주인 열쇠. 학생 로그인은 Supabase 사용자 번호 그대로,
// 심판 시험 계정은 검증된 sub에 시험 신원(a/b)까지 묶어 A와 B가 절대 같은 주인이 되지 않게 합니다.
export function ownerKey(login) {
  if (login?.kind !== 'judge') return login.userId;
  const hex = createHash('sha256').update(`aleph-judge-owner:${login.userId}:${login.identity}`).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

// 8단계: 한 건 주소의 자료 ID는 쿼리가 아니라 실제 경로의 마지막 칸에서만 읽습니다.
// /api/notes/<id>?id=<다른 값> 처럼 쿼리로 ID를 바꿔치기하거나 기능을 고르는 요청은 받지 않습니다.
export function pathId(request) {
  const raw = typeof request.url === 'string' ? request.url : '';
  if (!raw) return { id: String(request.query?.id ?? ''), query: false };
  const [path, query = ''] = raw.split('?');
  const last = path.split('/').filter(Boolean).pop() ?? '';
  let id = '';
  try { id = decodeURIComponent(last); } catch { id = ''; }
  // Vercel은 [id].js에 넘길 때 경로의 ID를 ?id=…로 스스로 붙입니다. 그 값이 경로 ID와 같으면 정상으로 봅니다.
  // 그 밖의 쿼리(다른 id 값, owner_id 같은 다른 이름)는 쿼리로 자료·기능을 고르려는 요청으로 보고 거부합니다.
  const params = new URLSearchParams(query);
  const extra = [...params.entries()].filter(([key, value]) => !(key === 'id' && value === id));
  return { id, query: extra.length > 0 };
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

// 8단계: 강사 여부는 DB의 instructors 표에 저장된 주인 열쇠로만 판단합니다(요청의 role은 믿지 않음).
export async function isInstructor(db, userId) {
  const { data, error } = await db.from('instructors').select('user_id').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return data?.user_id === userId;
}
