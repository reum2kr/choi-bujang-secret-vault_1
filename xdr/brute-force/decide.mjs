// 보너스 xdr-01 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import·파일 읽기/쓰기·네트워크 없이 이 파일 안의 상수와 계산만 씁니다.
// 판정기 연결과 알림 기록은 respond.mjs 가 맡습니다.

// xdr/brute-force/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'rapid_failures_same_source',
    technique: 'T1110.001',
    condition: '같은 출발 주소에서 짧은 시간(대략 5분 이내)에 로그인 실패가 15건 이상 이어지고, 그 사이 성공이 없음',
    evidence: 'MITRE ATT&CK T1110.001 Password Guessing: 비밀번호를 반복해 추측하면 한 주소에서 짧은 시간에 실패가 몰린다.',
  }),
  Object.freeze({
    name: 'password_spraying_many_accounts',
    technique: 'T1110.003',
    condition: '같은 출발 주소가 서로 다른 계정 5개 이상에 같은 비밀번호로 로그인 실패를 넣음',
    evidence: 'MITRE ATT&CK T1110.003 Password Spraying: 흔한 비밀번호 하나를 여러 계정에 대입해 계정 잠금을 피한다.',
  }),
  Object.freeze({
    name: 'low_volume_failures',
    technique: 'T1110',
    condition: '같은 주소·같은 계정의 로그인 실패가 3~14건이거나 2~4개 계정에 실패가 나뉨. 그 뒤 성공했다면 오타일 가능성도 함께 봄',
    evidence: 'MITRE ATT&CK T1110 Brute Force: 대입 공격의 초기·저속 단계는 사용자 오타와 겉모습이 같아 알림으로만 남기고 지켜본다.',
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const RAPID_MIN = 15;     // 이 이상 실패면 명확한 대입
const SPRAY_MIN = 5;      // 이 이상 계정이면 명확한 스프레이
const LOW_MIN = 3;        // 이 이상 실패면 지켜볼 시도

const round = (n) => Math.round(Math.min(1, Math.max(0, n)) * 100) / 100;
const toInt = (value) => {
  const n = Number.parseInt(String(value ?? '').replace(/[^0-9]/gu, ''), 10);
  return Number.isFinite(n) ? n : 0;
};

// 경보에서 판단에 쓸 신호만 뽑습니다. 원본 alert 는 고치지 않습니다.
function signals(alert) {
  const rule = alert && typeof alert === 'object' ? alert.rule ?? {} : {};
  const data = alert && typeof alert === 'object' ? alert.data ?? {} : {};
  const description = typeof rule.description === 'string' ? rule.description : '';
  const level = Number.isFinite(Number(rule.level)) ? Number(rule.level) : 0;
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const bruteTagged = mitre.some((id) => id === 'T1110' || id.startsWith('T1110.'));

  const mentionsFailure = /실패|fail/iu.test(description);
  const endedInSuccess = /성공|success/iu.test(description);
  const sameSecret = /같은\s*비밀번호|same\s*password/iu.test(description);

  // 실패 건수: data.count, 설명의 "실패 N건" 중 큰 값
  const fromDescription = [...description.matchAll(/(?:실패\D{0,6})?(\d+)\s*건/gu)].map((m) => toInt(m[1]));
  const failures = mentionsFailure ? Math.max(toInt(data.count), 0, ...fromDescription) : 0;

  // 대상 계정 수: data.accounts 목록, 설명의 "계정 N개", "여러 계정"
  const listed = typeof data.accounts === 'string'
    ? new Set(data.accounts.split(/[,\s]+/u).filter(Boolean)).size : 0;
  const fromText = [...description.matchAll(/계정\s*(\d+)\s*개/gu)].map((m) => toInt(m[1]));
  const many = /여러\s*계정|계정\s*이름을\s*바꿔/u.test(description) ? SPRAY_MIN : 0;
  const twoAccounts = /두\s*계정/u.test(description) ? 2 : 0;
  const accounts = Math.max(listed, many, twoAccounts, ...fromText);

  return { level, bruteTagged, mentionsFailure, endedInSuccess, sameSecret, failures, accounts };
}

export function decide(alert) {
  const s = signals(alert);

  // 정상 이벤트: 대입 표시가 없고 실패도 거의 없음
  if ((!s.bruteTagged && s.failures < LOW_MIN && s.accounts < 2) || (!s.mentionsFailure && s.accounts < 2)) {
    return { action: 'record', confidence: round(0.05 + Math.min(s.level, 5) * 0.02),
      reason: 'none: 로그인 실패 몰림이나 여러 계정 대입 신호가 없는 정상 이벤트' };
  }

  // 명확한 공격 1: 여러 계정에 같은 비밀번호 대입 (스프레이)
  if (s.accounts >= SPRAY_MIN) {
    let c = 0.86;
    if (s.sameSecret) c += 0.04;
    if (s.level >= 10) c += 0.04;
    if (s.accounts >= 10 || s.failures >= 20) c += 0.03;
    if (s.endedInSuccess) c -= 0.05;
    return { action: c >= BLOCK_AT ? 'block' : 'alert', confidence: round(c),
      reason: `password_spraying_many_accounts: 계정 ${s.accounts}개 이상에 대입 (T1110.003)` };
  }

  // 명확한 공격 2: 짧은 시간 같은 주소 실패 몰림
  if (s.failures >= RAPID_MIN) {
    let c = 0.86;
    if (s.level >= 10) c += 0.04;
    if (s.failures >= 40) c += 0.03;
    if (s.failures >= 60) c += 0.02;
    if (s.endedInSuccess && !/성공은\s*없/u.test(String(alert?.rule?.description ?? ''))) c -= 0.1;
    return { action: c >= BLOCK_AT ? 'block' : 'alert', confidence: round(c),
      reason: `rapid_failures_same_source: 로그인 실패 ${s.failures}건이 몰림 (T1110.001)` };
  }

  // 애매한 시도: 적은 실패나 소수 계정 → 알림만
  if (s.failures >= LOW_MIN || s.accounts >= 2) {
    let c = 0.55 + Math.min(s.failures, 14) * 0.015 + (s.accounts >= 2 ? 0.05 : 0);
    if (s.endedInSuccess) c -= 0.03;
    c = Math.min(c, 0.8);
    return { action: 'alert', confidence: round(Math.max(c, ALERT_AT)),
      reason: `low_volume_failures: 실패 ${s.failures}건${s.accounts >= 2 ? `, 계정 ${s.accounts}개` : ''} — 오타일 수도 있어 알림만 (T1110)` };
  }

  // 대입 표시는 있지만 실패가 1~2건: 기록만
  return { action: 'record', confidence: round(0.3 + s.failures * 0.05),
    reason: 'none: 대입 패턴 기준(실패 3건)에 못 미침' };
}
