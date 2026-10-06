// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
function appUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

async function anonymousGet(app, path, headers = {}) {
  const response = await fetch(new URL(path, app), {
    headers, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000),
  });
  let notes = null;
  let error = null;
  try {
    const data = await response.json();
    notes = Array.isArray(data) ? data.length : Array.isArray(data?.notes) ? data.notes.length : null;
    error = typeof data?.error === 'string' ? data.error.slice(0, 40) : null;
  } catch {
    // A non-JSON response is recorded as "no notes", not as a success.
  }
  if (!response.ok) notes = null;
  return { status: response.status, notes, error };
}

export async function runAttackChecks(config) {
  const app = appUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 1) {
    const response = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let visible = false;
    if (response.ok) {
      try {
        const data = await response.json();
        visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
          && data.notes.length > 0;
      } catch {
        // A non-JSON response is a failed check, not a successful deployment.
      }
    }
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  if (config.step === 2) {
    // 실제로 보낸 비로그인 요청의 결과만 적습니다. 메모 본문은 기록하지 않습니다.
    const oldFile = await anonymousGet(app, '/data.json');
    const api = await anonymousGet(app, '/api/notes');
    const oldFileBlocked = oldFile.status === 404 || oldFile.notes === 0;
    return [
      { attackId: 'anonymous_note_read',
        expected: '공개 /data.json에서 가상 메모가 보이지 않음 (404 또는 0건)',
        observed: oldFileBlocked
          ? `비로그인 /data.json 요청에서 메모가 보이지 않음 (HTTP ${oldFile.status})`
          : `비로그인 /data.json 요청에서 메모 ${oldFile.notes ?? '?'}건이 보임 (HTTP ${oldFile.status})` },
      { attackId: 'anonymous_api_read',
        expected: '남은 약점: 로그인이 없어 /api/notes는 아직 메모를 돌려줌 (3단계에서 차단 예정)',
        observed: `비로그인 /api/notes 요청 결과 HTTP ${api.status}, 메모 ${api.notes ?? 0}건` },
    ];
  }

  if (config.step === 3) {
    // 실제로 보낸 요청의 결과만 적습니다. 메모 본문·토큰은 기록하지 않습니다.
    const oldFile = await anonymousGet(app, '/data.json');
    const noLogin = await anonymousGet(app, '/api/notes');
    const forged = await anonymousGet(app, '/api/notes', {
      Authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.forged',
    });
    const denied = (r) => (r.status === 401 || r.status === 403) && r.notes === null;
    const describe = (r) => `HTTP ${r.status}${r.error ? ` ${r.error}` : ''}${r.notes === null ? ', 메모 없음' : `, 메모 ${r.notes}건`}`;
    return [
      { attackId: 'anonymous_note_read',
        expected: '공개 /data.json에서 가상 메모가 보이지 않음 (404 또는 0건)',
        observed: `비로그인 /data.json 요청 결과 HTTP ${oldFile.status}${oldFile.notes ? `, 메모 ${oldFile.notes}건` : ', 메모 없음'}` },
      { attackId: 'anonymous_api_read',
        expected: '로그인 없는 /api/notes 목록 요청은 401·403 JSON 오류로 거부',
        observed: `비로그인 /api/notes 요청 결과 ${describe(noLogin)}${denied(noLogin) ? ' (거부됨)' : ' (거부되지 않음)'}` },
      { attackId: 'forged_token_read',
        expected: '서명이 없는 위조 토큰의 /api/notes 요청은 401·403으로 거부',
        observed: `위조 토큰 /api/notes 요청 결과 ${describe(forged)}${denied(forged) ? ' (거부됨)' : ' (거부되지 않음)'}` },
      { attackId: 'login_a_crud',
        expected: 'A 로그인 뒤 가상 메모 추가·수정·삭제 성공, 삭제 뒤 GET 404',
        observed: '미실행: 계정 비밀번호를 코드에 넣지 않아 이 스크립트로는 보내지 않음. 학생이 화면에서 직접 확인' },
      { attackId: 'cross_user_note_write',
        expected: '남은 약점: 소유자 검사가 없어 B가 A 메모 id로 수정 가능 (4단계에서 차단·기록 예정)',
        observed: '미실행: B 계정 점검은 4단계에서 기록' },
    ];
  }

  throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
}
