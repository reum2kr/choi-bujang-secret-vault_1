// 2단계: 가상 메모를 Supabase에서 서버 쪽으로만 읽어 화면에 넘겨 줍니다.
// SUPABASE_URL, SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키 값은 응답·로그·브라우저 파일 어디에도 내보내지 않습니다.
import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    console.error('notes: 서버 환경변수가 설정되지 않았습니다.');
    return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
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
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
  return response.status(200).json({ notes: data });
}
