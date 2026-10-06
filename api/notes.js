// 3단계: 로그인한 사람에게만 가상 메모를 돌려줍니다.
// 토큰 검사는 시작 틀의 src/verify-login.mjs 도우미만 사용합니다(고치지 않음).
// SUPABASE_URL, SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고
// 키 값은 응답·로그·브라우저 파일 어디에도 내보내지 않습니다.
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

let verifyLogin;
function getVerifier(secretKey) {
  verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
  return verifyLogin;
}

function deny(response, status, error, message) {
  return response.status(status).json({ error, message });
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return deny(response, 405, 'METHOD_NOT_ALLOWED', 'GET 요청만 받습니다.');
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    console.error('notes: 서버 환경변수가 설정되지 않았습니다.');
    return deny(response, 500, 'SERVER_NOT_CONFIGURED', '서버 설정을 확인해 주세요.');
  }

  // 브라우저가 보낸 userId·role 같은 값은 보지 않습니다. 토큰 검사 결과만 믿습니다.
  let login = null;
  try {
    login = await getVerifier(secretKey)(request.headers.authorization);
  } catch {
    console.error('notes: 로그인 검사기를 만들지 못했습니다. identityProvider 설정을 확인하세요.');
    return deny(response, 500, 'LOGIN_VERIFIER_ERROR', '로그인 검사 설정을 확인해 주세요.');
  }
  if (!login) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    return deny(response, 401, 'LOGIN_REQUIRED', '로그인한 사용자만 자료를 볼 수 있습니다.');
  }

  const supabase = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await supabase
    .from('notes')
    .select('title, content')
    .order('id', { ascending: true });

  if (error) {
    console.error('notes: 자료를 읽지 못했습니다.', error.code ?? 'unknown');
    return deny(response, 502, 'NOTES_UNAVAILABLE', '자료를 읽지 못했습니다.');
  }
  return response.status(200).json({ notes: data });
}
