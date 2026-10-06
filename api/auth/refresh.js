// POST /api/auth/refresh → httpOnly 쿠키의 refresh token으로 새 access token 발급
import { fail } from '../../lib/notes-server.mjs';
import { authClient, clearRefreshCookie, postOnly, readRefreshCookie, sendSession } from '../../lib/auth-server.mjs';

export default async function handler(request, response) {
  if (!postOnly(request, response)) return;
  const refreshToken = readRefreshCookie(request);
  if (!refreshToken) return fail(response, 401, 'NO_SESSION', '로그인 기록이 없습니다.');
  const supabase = authClient(response);
  if (!supabase) return;

  const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
  if (error || !data?.session) {
    clearRefreshCookie(response);
    return fail(response, 401, 'SESSION_EXPIRED', '로그인이 만료되었습니다. 다시 로그인해 주세요.');
  }
  return sendSession(response, data.session);
}
