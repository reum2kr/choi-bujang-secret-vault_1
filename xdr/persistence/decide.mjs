// 보너스 persistence 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import·파일 읽기/쓰기·네트워크 없이 이 파일 안의 상수와 계산만 씁니다.
// 판정기 연결(격리 규칙)과 알림 기록은 respond.mjs 가 맡습니다.

// xdr/persistence/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'unsigned_new_service',
    technique: 'T1543.003',
    condition: '서명이 없다고 확인된 서비스가 새로 등록되거나, 기존 서비스의 실행 파일이 서명 없는 파일로 바뀜',
    evidence: 'MITRE ATT&CK T1543.003: 공격자는 Windows 서비스를 만들거나 실행 파일 경로를 바꿔 재부팅 뒤에도 악성 프로그램이 시스템 권한으로 다시 실행되게 한다.',
  }),
  Object.freeze({
    name: 'unfamiliar_scheduled_task',
    technique: 'T1053.005',
    condition: '처음 보는(평소 목록에 없는) 예약 작업이 임의 문자열 이름이거나, 평소와 다른 시각(수업 시간 밖)에 실행되거나, 임시 폴더의 프로그램을 실행함',
    evidence: 'MITRE ATT&CK T1053.005: 공격자는 예약 작업을 만들어 정해진 시각이나 로그온 때 악성 프로그램을 반복 실행해 지속성을 얻는다(SUNBURST 사고에서도 예약 작업으로 도구를 실행했다).',
  }),
  Object.freeze({
    name: 'startup_folder_change',
    technique: 'T1547.001',
    condition: '시작 폴더(Start Menu\\Programs\\Startup)나 시작 프로그램 목록에 평소 목록에 없는 실행 파일이 추가됨',
    evidence: 'MITRE ATT&CK T1547.001: 시작 폴더에 넣은 프로그램은 사용자가 로그온할 때마다 자동 실행되므로 지속성 확보에 쓰인다(경보에서는 T1543 으로 함께 분류됨).',
  }),
  Object.freeze({
    name: 'persistence_from_temp_path',
    technique: 'T1543',
    condition: '서비스·예약 작업·시작 항목이 가리키는 실행 파일이 임시 폴더(AppData\\Local\\Temp, Windows\\Temp)에 있음',
    evidence: 'MITRE ATT&CK T1543·T1053: 정상 설치 프로그램은 Program Files 등 고정 위치에 두며, 임시 폴더 실행 파일을 지속 실행 항목으로 등록하는 것은 악성 지속성의 흔한 흔적이다.',
  }),
  Object.freeze({
    name: 'not_in_baseline_repeated',
    technique: 'T1543',
    condition: '평소 목록(기준선)에 없는 지속 실행 항목이 다시 켜도 남도록 등록되거나, 같은 출발 주소에서 2건 이상 이어지거나, 여러 지속 방식(서비스·예약 작업·시작 항목)이 같은 파일을 함께 가리킴',
    evidence: 'MITRE ATT&CK T1543·T1053: SUNBURST 처럼 숨은 백도어는 기준선 밖의 항목을 여러 방식으로 겹쳐 심어 하나가 지워져도 살아남게 한다.',
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

const round = (n) => Math.round(Math.min(1, Math.max(0, n)) * 100) / 100;
const toInt = (value) => {
  const n = Number.parseInt(String(value ?? '').replace(/[^0-9]/gu, ''), 10);
  return Number.isFinite(n) ? n : 0;
};

// 경로 모양
const TEMP_PATH = /[\\/](?:AppData[\\/]Local[\\/])?Temp[\\/]|[\\/]Windows[\\/]Temp[\\/]|^\/tmp\//iu;
const STARTUP_PATH = /Start\s*Menu[\\/]Programs[\\/]Startup[\\/]|[\\/]Startup[\\/]/iu;
const EXE_PATH = /\.(?:exe|dll|scr|ps1|vbs|bat|cmd|js)$/iu;

// 설명문 표현
const D = {
  service: /서비스(?:가|를)?\s*(?:등록|새로)|새\s*서비스|서비스\s*등록|서비스\s*실행\s*파일이\s*바뀌|평소\s*목록에\s*없는\s*서비스/u,
  task: /예약\s*작업/u,
  startup: /시작\s*(?:폴더|프로그램|항목)/u,
  unsigned: /서명\s*(?:이\s*)?없|서명\s*없는/u,
  unfamiliar: /처음\s*보는|평소\s*목록에\s*없|임의\s*문자열|수업\s*시간\s*밖|평소와\s*다른\s*시각/u,
  survive: /다시\s*켜도\s*남|재부팅\s*(?:뒤|후)에도/u,
  multi: /(?:시작\s*프로그램|서비스|예약\s*작업)과\s*(?:시작\s*프로그램|서비스|예약\s*작업)이\s*같은/u,
  repeat: /(\d+)\s*(?:건|번|회)/u,
  sequence: /연속|반복/u,
};
// 기존·평소대로·서명된·읽기만처럼 정상 상태를 말하는 표현, 그리고 지속 등록이 "없다"는 부정
const BENIGN = /기존\s*(?:수업\s*도구\s*)?(?:서비스|예약\s*작업)|평소\s*(?:시각|저장소)에?\s*(?:그대로|에서)|서명된\s*채로|읽기만|로그인했습니다|로그아웃했습니다|화면이\s*열렸습니다/u;
const NEGATED_PERSIST = /(?:서비스\s*등록|등록)은\s*없|실행된\s*기록은\s*없|실행\s*파일은\s*그대로|같은\s*파일로\s*다시/u;

function signals(alert) {
  const rule = alert?.rule ?? {};
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const syscheck = alert?.syscheck && typeof alert.syscheck === 'object' ? alert.syscheck : {};
  const description = typeof rule.description === 'string' ? rule.description : '';
  const path = String(data.path ?? syscheck.path ?? data.file ?? data.image ?? '');
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const repeatText = D.sequence.test(description) ? D.repeat.exec(description) : null;
  const negated = NEGATED_PERSIST.test(description);

  const mech = new Set();
  if (D.service.test(description) && !negated) mech.add('service');
  if (D.task.test(description) && !negated) mech.add('task');
  if ((D.startup.test(description) && !negated) || STARTUP_PATH.test(path)) mech.add('startup');

  const mentioned = D.task.test(description) ? 'task' : D.startup.test(description) || STARTUP_PATH.test(path) ? 'startup'
    : /서비스/u.test(description) ? 'service' : null;
  return {
    mech,
    mentioned,
    unsigned: D.unsigned.test(description),
    temp: TEMP_PATH.test(path) && EXE_PATH.test(path),
    startupPath: STARTUP_PATH.test(path) && EXE_PATH.test(path),
    unfamiliar: D.unfamiliar.test(description),
    survive: D.survive.test(description),
    multi: D.multi.test(description) || mech.size >= 2,
    count: Math.max(toInt(data.count), repeatText ? toInt(repeatText[1]) : 0, 1),
    benign: BENIGN.test(description),
    level: Number.isFinite(Number(rule.level)) ? Number(rule.level) : 0,
    tagged: mitre.some((id) => /^T(?:1543|1053|1547)(?:\.|$)/u.test(id)),
  };
}

export function decide(alert) {
  const s = signals(alert && typeof alert === 'object' ? alert : {});

  // 정상: 기존 항목이 평소대로 돌거나, 읽기·로그인 같은 일상 기록
  if (s.benign && !s.unsigned && !s.temp && !s.unfamiliar) {
    return { action: 'record', confidence: round(0.05 + Math.min(s.level, 5) * 0.02),
      reason: 'none: 평소 목록의 서명된·기존 항목이거나 지속 등록이 없는 정상 기록' };
  }

  const hits = [];
  if (s.mech.has('service') && s.unsigned) hits.push('unsigned_new_service');
  if (s.mech.has('task') && (s.unfamiliar || s.temp)) hits.push('unfamiliar_scheduled_task');
  if (s.mech.has('startup') && (s.unfamiliar || s.startupPath)) hits.push('startup_folder_change');
  if (s.mech.size && s.temp) hits.push('persistence_from_temp_path');
  if (s.mech.size && (s.survive || s.count >= 2 || s.multi || s.unfamiliar)) hits.push('not_in_baseline_repeated');

  // 명확한 공격: 지속 실행 방식 + 서로 다른 강한 신호 2개 이상 (또는 수준 10 이상에서 1개)
  if (s.mech.size && hits.length) {
    let c = 0.7 + hits.length * 0.08;
    if (s.level >= 10) c += 0.07;
    if (s.tagged) c += 0.02;
    if (hits.length >= 2 || s.level >= 10) {
      c = Math.max(c, BLOCK_AT);
      return { action: 'block', confidence: round(c), reason: `${hits.join(' + ')} (T1543·T1053)` };
    }
    return { action: 'alert', confidence: round(Math.min(c, 0.84)), reason: `${hits[0]}: 강한 신호가 하나뿐이라 알림만 (T1543·T1053)` };
  }

  // 애매한 시도: 지속 실행 관련 경보지만 서명 없음·임시 폴더·기준선 밖 신호가 뚜렷하지 않음
  if (s.mech.size || s.tagged || s.temp || s.unsigned || s.unfamiliar) {
    const c = Math.min(0.8, Math.max(ALERT_AT, 0.52 + Math.max(0, Math.min(s.level, 9) - 4) * 0.04 + (s.temp ? 0.05 : 0)));
    const name = s.mentioned === 'task' ? 'unfamiliar_scheduled_task' : s.mentioned === 'startup' ? 'startup_folder_change'
      : s.temp ? 'persistence_from_temp_path' : 'unsigned_new_service';
    if (s.level <= 3 && !s.temp && !s.unsigned && !s.unfamiliar) {
      return { action: 'record', confidence: round(0.1 + s.level * 0.03), reason: `none: ${name} 분류지만 수준이 낮고 이상 신호가 없음` };
    }
    return { action: 'alert', confidence: round(c), reason: `${name} 미달: 서명 없음·임시 폴더·기준선 밖 신호가 뚜렷하지 않아 알림만` };
  }

  // 정상 이벤트
  return { action: 'record', confidence: round(0.05 + Math.min(s.level, 5) * 0.02),
    reason: 'none: 서비스·예약 작업·시작 항목 변경이 없는 정상 기록' };
}
