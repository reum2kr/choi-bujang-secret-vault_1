// 보너스 xdr-02 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import·파일 읽기/쓰기·네트워크 없이 이 파일 안의 상수와 계산만 씁니다.
// 판정기 연결과 알림 기록은 respond.mjs 가 맡습니다.

// xdr/web-injection/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'sql_injection_in_params',
    technique: 'T1190',
    condition: '요청 인자 안에 SQL 구문을 이어 붙이는 표기(따옴표 뒤 OR/AND 참 조건, UNION SELECT, 주석 --, 세미콜론 뒤 추가 문장)가 있음',
    evidence: 'MITRE ATT&CK T1190: 공개된 웹 앱의 입력 칸에 SQL 구문을 넣어 데이터베이스 질의를 바꾸는 것이 대표적인 외부 공개 앱 악용이다(MOVEit 사고가 이 방식).',
  }),
  Object.freeze({
    name: 'script_injection_in_params',
    technique: 'T1190',
    condition: '요청 인자 안에 스크립트 태그나 이벤트 처리기 표기(<script, javascript:, onerror=)가 있음',
    evidence: 'MITRE ATT&CK T1190: 웹 앱이 입력을 걸러내지 않으면 넣은 스크립트가 다른 사용자 화면에서 실행되는 약점을 악용한다.',
  }),
  Object.freeze({
    name: 'path_traversal_repeat',
    technique: 'T1190',
    condition: '요청 인자 안에 경로를 거슬러 올라가는 ../ (또는 인코딩된 %2e%2e%2f)가 두 번 이상 이어짐',
    evidence: 'MITRE ATT&CK T1190: 파일 경로 입력에 ../ 를 반복해 웹 앱이 허용하지 않은 상위 폴더 파일을 읽게 하는 악용이다.',
  }),
  Object.freeze({
    name: 'command_injection_in_params',
    technique: 'T1190',
    condition: '요청 인자 안에 운영체제 명령을 이어 붙이는 구분자(; | && ` $( )) 뒤에 명령어가 붙음',
    evidence: 'MITRE ATT&CK T1190: 웹 앱이 입력을 운영체제 명령에 그대로 넘기면 구분자로 명령을 덧붙여 서버에서 실행시키는 악용이다.',
  }),
  Object.freeze({
    name: 'repeated_injection_same_source',
    technique: 'T1190',
    condition: '같은 출발 주소에서 위 주입 표기가 들어간 요청이 5번 이상 반복됨',
    evidence: 'MITRE ATT&CK T1190: 공격자는 취약점을 찾을 때까지 같은 주소에서 주입 형태를 바꿔 가며 반복해 보낸다. 한 번뿐인 표기는 오입력일 수 있다.',
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const REPEAT_MIN = 5;

const round = (n) => Math.round(Math.min(1, Math.max(0, n)) * 100) / 100;
const toInt = (value) => {
  const n = Number.parseInt(String(value ?? '').replace(/[^0-9]/gu, ''), 10);
  return Number.isFinite(n) ? n : 0;
};

// URL 인코딩을 두 번까지 풀어 봅니다(이중 인코딩 대비). 실패하면 원문을 씁니다.
function decodeTwice(text) {
  let out = text;
  for (let i = 0; i < 2; i += 1) {
    try { out = decodeURIComponent(out.replace(/\+/gu, ' ')); } catch { break; }
  }
  return out;
}

// 실제 주입 문자열의 모양 (요청 인자에서만 봅니다)
const REAL = {
  sql: [
    /'\s*(?:or|and)\s+['"\w]+\s*=\s*['"\w]+/iu,
    /\bunion\b[\s/*]+(?:all\s+)?select\b/iu,
    /;\s*(?:drop|delete|insert|update|select)\b/iu,
    /'\s*(?:--|#|\/\*)/u,
    /\b(?:sleep|benchmark|pg_sleep)\s*\(/iu,
  ],
  script: [/<\s*script\b/iu, /javascript\s*:/iu, /\bon(?:error|load|mouseover)\s*=/iu, /<\s*(?:img|svg|iframe)\b[^>]*\bon\w+\s*=/iu],
  traversal: [/(?:\.\.[\\/]){2,}/u, /(?:%2e%2e(?:%2f|%5c|\/)){2,}/iu],
  cmd: [/[;&|]\s*(?:cat|ls|id|whoami|curl|wget|nc|bash|sh)\b/iu, /\$\([^)]*\)/u, /`[^`]+`/u],
};

// 수업용 경보의 문서 표기(doc-...) — 실제 문자열 대신 쓴 이름표입니다.
const DOC_MARKER = {
  sql: /doc-sql/iu,
  script: /doc-script/iu,
  traversal: /doc-up-repeat/iu,
  cmd: /doc-cmd/iu,
  mixed: /doc-mixed/iu,
};

// 설명문에서 주입이 "있다"고 말하는 표현
const DESC = {
  sql: /SQL\s*(?:구문|표기|표식)|데이터베이스\s*조회를\s*이어/iu,
  script: /스크립트\s*(?:삽입|표기|표식)/u,
  traversal: /경로를?\s*(?:여러\s*단계\s*)?거슬러|경로\s*이탈/u,
  cmd: /명령\s*구분자/u,
};
const DESC_NEGATED = /표식은\s*아닙니다|공격\s*표기는\s*없|수업\s*(?:단어|명|공지)/u;
const REPEATED = /(\d+)\s*번\s*(?:반복|들어|나왔|있)/u;

function families(alert) {
  const rule = alert?.rule ?? {};
  const data = alert?.data ?? {};
  const url = typeof data.url === 'string' ? data.url : '';
  const query = decodeTwice(url.includes('?') ? url.slice(url.indexOf('?') + 1) : '');
  const description = typeof rule.description === 'string' ? rule.description : '';
  const negated = DESC_NEGATED.test(description);

  const found = new Set();
  for (const [kind, list] of Object.entries(REAL)) {
    if (list.some((re) => re.test(query))) found.add(kind);
  }
  for (const [kind, re] of Object.entries(DOC_MARKER)) {
    if (re.test(query)) {
      if (kind === 'mixed') { found.add('sql'); found.add('script'); } else found.add(kind);
    }
  }
  if (!negated) {
    for (const [kind, re] of Object.entries(DESC)) if (re.test(description)) found.add(kind);
  }
  const repeatText = REPEATED.exec(description);
  const count = Math.max(toInt(data.count), repeatText ? toInt(repeatText[1]) : 0, 1);
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  return {
    found,
    count,
    level: Number.isFinite(Number(rule.level)) ? Number(rule.level) : 0,
    tagged: mitre.some((id) => id === 'T1190' || id.startsWith('T1190.')),
    singleOnly: /반복(?:은|되지)\s*(?:없|않)/u.test(description),
  };
}

const NAME = {
  sql: 'sql_injection_in_params',
  script: 'script_injection_in_params',
  traversal: 'path_traversal_repeat',
  cmd: 'command_injection_in_params',
};

export function decide(alert) {
  const f = families(alert && typeof alert === 'object' ? alert : {});
  const names = [...new Set([...f.found].map((k) => NAME[k]))];

  // 명확한 공격: 주입 표기 + 같은 주소에서 반복
  if (names.length && f.count >= REPEAT_MIN && !f.singleOnly) {
    let c = 0.86;
    if (f.level >= 10) c += 0.04;
    if (f.count >= 10) c += 0.03;
    if (names.length >= 2) c += 0.03;
    if (!f.tagged) c -= 0.03;
    return { action: c >= BLOCK_AT ? 'block' : 'alert', confidence: round(c),
      reason: `repeated_injection_same_source + ${names.join(' + ')}: 주입 표기 ${f.count}번 반복 (T1190)` };
  }

  // 애매한 시도: 주입 표기가 있지만 반복이 적음
  if (names.length) {
    const c = Math.min(0.8, 0.6 + (f.count - 1) * 0.04 + (f.level >= 8 ? 0.05 : 0));
    return { action: 'alert', confidence: round(c),
      reason: `${names.join(' + ')}: 주입 표기 ${f.count}번 — 반복이 적어 알림만 (T1190)` };
  }

  // 웹 악용 의심으로 올라왔지만 뚜렷한 표기가 없음 → 지켜볼 대상
  if (f.tagged) {
    const c = Math.min(0.7, 0.5 + Math.max(0, f.level - 4) * 0.03);
    return { action: 'alert', confidence: round(c),
      reason: 'repeated_injection_same_source 미달: T1190 의심 경보지만 주입 표기·반복이 없어 알림만' };
  }

  // 정상 이벤트
  return { action: 'record', confidence: round(0.05 + Math.min(f.level, 5) * 0.02),
    reason: 'none: 주입 표기나 웹 악용 의심 표시가 없는 정상 요청' };
}
