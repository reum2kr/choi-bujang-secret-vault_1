// 보너스 known-cve 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import·파일 읽기/쓰기·네트워크 없이 이 파일 안의 상수와 계산만 씁니다.
// 판정기 연결과 알림 기록은 respond.mjs 가 맡습니다.
// 경보 안의 조회 구문은 문자열로 비교만 하고, 해석·실행·변형하지 않습니다.

// xdr/known-cve/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'jndi_lookup_in_header',
    technique: 'T1190',
    condition: '요청 머리글(useragent·referer 등) 안에 ${jndi:<ldap|ldaps|rmi|dns|iiop|corba|nds|http>:// 형태의 완전한 원격 조회 구문이 있음',
    evidence: 'CVE-2021-44228: 로그에 남는 머리글 값의 ${jndi:ldap://…} 조회 구문을 Log4j 가 해석해 원격 코드를 불러오며, 이는 MITRE ATT&CK T1190(공개 앱 악용)에 해당한다.',
  }),
  Object.freeze({
    name: 'jndi_lookup_in_params',
    technique: 'T1190',
    condition: '요청 주소의 인자(? 뒤, URL 인코딩을 풀어서) 안에 ${jndi:<프로토콜>:// 형태의 완전한 원격 조회 구문이 있음',
    evidence: 'CVE-2021-44228: 검색어·로그인 인자처럼 로그에 기록되는 입력 칸에 같은 조회 구문을 넣어도 원격 조회가 일어나므로 T1190 악용 형태다.',
  }),
  Object.freeze({
    name: 'known_scanner_trace',
    technique: 'T1190',
    condition: "머리글이나 설명에 알려진 취약점 점검 도구의 흔적(nuclei·nikto·sqlmap·masscan·zgrab 등의 이름 또는 '알려진 취약점 점검 흔적' 표기)이 있음",
    evidence: 'MITRE ATT&CK T1190·T1595.002: 공격자는 공개 앱 악용 전에 알려진 취약점 점검 도구로 대상을 훑으며, 이 흔적만으로는 공격 성공을 뜻하지 않아 조회 구문과 함께일 때만 차단 근거를 더한다.',
  }),
  Object.freeze({
    name: 'repeated_jndi_same_source',
    technique: 'T1190',
    condition: '같은 출발 주소에서 원격 조회 구문이 든 요청이 여러 번(count 2 이상) 반복되거나 여러 머리글·인자에 동시에 있음',
    evidence: 'CVE-2021-44228 대량 악용 시기에 공격자는 같은 주소에서 머리글·인자를 바꿔 가며 조회 구문을 반복해 보냈다(T1190). 반복은 오입력이 아니라는 근거를 더한다.',
  }),
  Object.freeze({
    name: 'cve_mention_without_lookup',
    technique: 'T1190',
    condition: '취약점 이름(CVE-2021-44228)·jndi 단어·잘린 조회 조각·점검 도구와 비슷한 이름만 있고 완전한 ${jndi:<프로토콜>:// 구문은 없음',
    evidence: 'CVE-2021-44228 악용에는 완전한 조회 구문이 필요하므로, 이름이나 조각만 있는 요청은 T1190 의심으로 알림만 하고 막지 않는다.',
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

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

// ${lower:j}·${::-j}·${env:X:-j} 처럼 한 글자씩 감춘 표기를 그 글자로 바꿔 비교합니다(비교용 사본만 만듦).
function unhide(text) {
  let out = text;
  for (let i = 0; i < 6; i += 1) {
    const next = out
      .replace(/\$\{\s*(?:lower|upper)\s*:\s*([^${}])\s*\}/giu, '$1')
      .replace(/\$\{[^${}]*?:-([^${}]*)\}/gu, '$1');
    if (next === out) break;
    out = next;
  }
  return out;
}

// 완전한 원격 조회 구문: ${jndi:<프로토콜>:/
const LOOKUP = /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|corba|nds|nis|https?)\s*:\s*\//iu;
// 조회 구문의 조각(완전하지 않음)이나 이름만 있는 표기
const MENTION = /jndi|cve-?2021-?44228|log4shell|log4j|\$\{|lookup/iu;
// 알려진 취약점 점검 도구 이름
const SCANNER = /\b(?:nuclei|nikto|sqlmap|masscan|zgrab|nmap|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|interactsh)\b/iu;

// 설명문 표현
const DESC_LOOKUP = /(?:CVE-2021-44228\s*(?:형태|표기)|원격\s*조회\s*구문|조회\s*구문)[^.]*(?:있습니다|있음|들어왔|반복|그대로)/u;
const DESC_SCANNER = /(?:알려진\s*)?취약점\s*점검\s*(?:흔적|도구)(?!와\s*비슷)/u;
const DESC_NEGATED = /(?:구문은|구문이)\s*(?:없|아닙)|완전한\s*구문은\s*아닙|글자만|비슷한|악용\s*구문은\s*없/u;
const DESC_REPEAT = /(\d+)\s*(?:번|건|회)\s*(?:반복|들어|나왔|있)/u;
const DESC_MULTI = /여러\s*머리글|머리글과\s*주소/u;

const HEADER_KEYS = ['useragent', 'user_agent', 'referer', 'referrer', 'x_api_version', 'x-api-version', 'header', 'headers'];

function signals(alert) {
  const rule = alert?.rule ?? {};
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const description = typeof rule.description === 'string' ? rule.description : '';
  const negated = DESC_NEGATED.test(description);

  const url = typeof data.url === 'string' ? data.url : '';
  const params = unhide(decodeTwice(url.includes('?') ? url.slice(url.indexOf('?') + 1) : url));

  const headerTexts = [];
  const otherTexts = [];
  for (const [key, value] of Object.entries(data)) {
    if (key === 'url' || key === 'srcip' || key === 'srcuser' || key === 'dstuser' || key === 'count') continue;
    const text = typeof value === 'string' ? value : value && typeof value === 'object' ? JSON.stringify(value) : '';
    if (!text) continue;
    (HEADER_KEYS.includes(key.toLowerCase()) ? headerTexts : otherTexts).push(unhide(decodeTwice(text)));
  }
  const headers = headerTexts.join('\n');
  const others = otherTexts.join('\n');

  const inHeader = LOOKUP.test(headers) || LOOKUP.test(others);
  const inParams = LOOKUP.test(params);
  const descLookup = !negated && DESC_LOOKUP.test(description);
  const scanner = SCANNER.test(headers) || SCANNER.test(others) || (!negated && DESC_SCANNER.test(description));
  const mention = MENTION.test(`${params}\n${headers}\n${others}`) || /CVE-|jndi|조회\s*(?:구문|형태)|점검\s*도구|취약점|라이브러리/iu.test(description);

  const repeatText = DESC_REPEAT.exec(description);
  const count = Math.max(toInt(data.count), repeatText ? toInt(repeatText[1]) : 0, 1);
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  return {
    inHeader, inParams, descLookup, scanner, mention, count,
    multi: (inHeader && inParams) || DESC_MULTI.test(description),
    level: Number.isFinite(Number(rule.level)) ? Number(rule.level) : 0,
    tagged: mitre.some((id) => id === 'T1190' || id.startsWith('T1190.')),
  };
}

export function decide(alert) {
  const s = signals(alert && typeof alert === 'object' ? alert : {});
  const hits = [];
  if (s.inHeader) hits.push('jndi_lookup_in_header');
  if (s.inParams) hits.push('jndi_lookup_in_params');

  // 명확한 공격: 완전한 원격 조회 구문이 머리글·인자에 실제로 있음
  if (hits.length) {
    let c = 0.88;
    if (s.level >= 10) c += 0.04;
    if (s.tagged) c += 0.02;
    if (s.count >= 2 || s.multi) { c += 0.03; hits.push('repeated_jndi_same_source'); }
    if (s.scanner) { c += 0.02; hits.push('known_scanner_trace'); }
    return { action: 'block', confidence: round(c), reason: `${hits.join(' + ')} (CVE-2021-44228, T1190)` };
  }

  // 구문 원문은 없지만 경보 설명이 조회 구문이 "있다"고 하고, 수준이 높은 T1190 경보
  if (s.descLookup && s.tagged && s.level >= 10) {
    const c = 0.85 + (s.count >= 2 || s.multi ? 0.03 : 0) + (s.scanner ? 0.02 : 0);
    return { action: 'block', confidence: round(c), reason: 'jndi_lookup_in_params: 경보 설명에 CVE-2021-44228 조회 구문 있음 (T1190)' };
  }

  // 애매한 시도: 이름·조각·점검 도구 흔적만 있거나, T1190 의심 경보지만 완전한 구문은 없음
  if (s.scanner || s.descLookup || s.tagged || s.mention) {
    let c = 0.55 + Math.max(0, Math.min(s.level, 9) - 5) * 0.03;
    if (s.scanner) c += 0.05;
    if (s.count >= 2) c += 0.03;
    c = Math.min(0.8, Math.max(ALERT_AT, c));
    const name = s.scanner ? 'known_scanner_trace' : 'cve_mention_without_lookup';
    return { action: c >= BLOCK_AT ? 'block' : 'alert', confidence: round(c), reason: `${name}: 완전한 원격 조회 구문이 없어 알림만 (T1190)` };
  }

  // 정상 이벤트
  return { action: 'record', confidence: round(0.05 + Math.min(s.level, 5) * 0.02), reason: 'none: 조회 구문·취약점 이름·점검 흔적이 없는 정상 요청' };
}
