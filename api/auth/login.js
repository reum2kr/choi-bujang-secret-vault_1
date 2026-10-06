// POST /api/auth/login  {email, password} → {accessToken, expiresAt, email}
import { fail, readBody } from '../../lib/notes-server.mjs';
import { authClient, postOnly, sendSession } from '../../lib/auth-server.mjs';

const REASONS = {
  invalid_credentials: '이메일 또는 비밀번호가 맞지 않습니다.',
  email_not_confirmed: '이메일 인증이 아직 끝나지 않은 계정입니다.',
  user_banned: '사용이 정지된 계정입니다.',
  over_request_rate_limit: '시도가 너무 많습니다. 잠시 뒤 다시 해 주세요.',
};

export default async function handler(request, response) {
  if (!postOnly(request, response)) return;
  const body = readBody(request);
  const email = typeof body?.email === 'string' ? body.email.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (!email || email.length > 320 || !password || password.length > 200) {
    return fail(response, 400, 'INVALID_LOGIN_INPUT', '이메일과 비밀번호를 입력해 주세요.');
  }
  const supabase = authClient(response);
  if (!supabase) return;

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error || !data?.session) {
    const code = error?.code ?? 'unknown';
    const status = code === 'over_request_rate_limit' ? 429 : 401;
    return fail(response, status, 'LOGIN_FAILED', REASONS[code] ?? '로그인하지 못했습니다.');
  }
  return sendSession(response, data.session);
}
