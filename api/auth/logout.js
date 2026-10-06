// POST /api/auth/logout → 서버에서 세션을 끊고 refresh 쿠키를 지웁니다.
import { send } from '../../lib/notes-server.mjs';
import { authClient, clearRefreshCookie, postOnly, readRefreshCookie } from '../../lib/auth-server.mjs';

export default async function handler(request, response) {
  if (!postOnly(request, response)) return;
  const refreshToken = readRefreshCookie(request);
  clearRefreshCookie(response);
  if (refreshToken) {
    const supabase = authClient(response);
    if (!supabase) return;
    // refresh token으로 세션을 다시 얻은 뒤 그 세션을 끊습니다. 실패해도 쿠키는 이미 지웠습니다.
    const { data } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
    const accessToken = data?.session?.access_token;
    if (accessToken) {
      await supabase.auth.admin.signOut(accessToken, 'local').catch(() => {});
    }
  }
  return send(response, 200, { loggedOut: true });
}
