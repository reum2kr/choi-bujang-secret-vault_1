// 보너스 privilege 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import·파일 읽기/쓰기·네트워크 없이 이 파일 안의 상수와 계산만 씁니다.
// 판정기 연결(세션 회수 규칙)과 알림 기록은 respond.mjs 가 맡습니다.

// xdr/privilege/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'admin_group_addition',
    technique: 'T1078',
    condition: '평범한 계정이 관리자 그룹(administrators·admins·sudo·wheel 등)에 추가되거나, 빠졌다가 곧 다시 들어오거나, 같은 주소에서 여러 계정이 한꺼번에 추가됨',
    evidence: 'MITRE ATT&CK T1078(·T1098.007): 공격자는 손에 넣은 정상 계정을 관리자 그룹에 넣어 권한을 높이고 그 권한을 계속 유지한다.',
  }),
  Object.freeze({
    name: 'unfamiliar_admin_command',
    technique: 'T1068',
    condition: '방금 관리자가 된 계정, 처음 보는 주소, 또는 다른 계정의 권한으로 관리자 명령이 실행되거나 세션이 관리자 권한으로 바뀜',
    evidence: 'MITRE ATT&CK T1068: 공격자는 약점을 악용해 얻은 높은 권한으로 곧바로 관리자 명령을 실행하며, 평소 쓰지 않던 주소·계정에서 나온 관리자 명령은 그 흔적이다.',
  }),
  Object.freeze({
    name: 'off_hours_privilege_use',
    technique: 'T1078',
    condition: '업무·수업 시간 밖(또는 업무처럼 보이지 않는 시각)에 관리자 그룹 추가나 관리자 권한 사용이 일어남',
    evidence: 'MITRE ATT&CK T1078: 도용된 정상 계정은 실제 사용자가 없는 시간에 쓰이는 경우가 많아, 평소와 다른 시각의 권한 사용은 계정 도용 탐지 신호로 쓰인다.',
  }),
  Object.freeze({
    name: 'group_add_then_admin_command',
    technique: 'T1068',
    condition: '같은 계정이 관리자 그룹에 들어간 직후 관리자 명령을 실행하는 것처럼, 권한 상승과 권한 사용이 한 경보·짧은 간격에 함께 있음',
    evidence: 'MITRE ATT&CK T1068·T1078: 권한 상승은 그 권한을 쓰기 위한 것이므로, 상승과 사용이 붙어 있으면 실수가 아니라 의도된 가로채기일 가능성이 높다.',
  }),
  Object.freeze({
    name: 'privilege_signal_without_escalation',
    technique: 'T1068',
    condition: '권한 상승 창·관리자 명령·그룹 변경 경보가 있지만 취소·실패·관리자 그룹 아님·평소 주소처럼 실제 상승이나 낯선 사용이 확인되지 않음',
    evidence: 'MITRE ATT&CK T1068·T1078: 탐지 신호 하나만으로는 정상 관리 작업과 구분되지 않으므로, 상승이 확인되지 않은 경보는 알림만 하고 세션을 거두지 않는다.',
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

const round = (n) => Math.round(Math.min(1, Math.max(0, n)) * 100) / 100;
const toInt = (value) => {
  const n = Number.parseInt(String(value ?? '').replace(/[^0-9]/gu, ''), 10);
  return Number.isFinite(n) ? n : 0;
};

const ADMIN_GROUP = /^(?:administrators?|admins?|domain\s*admins|enterprise\s*admins|sudo(?:ers)?|wheel|root)$/iu;

const D = {
  groupAdd: /관리자\s*그룹(?:에|으로)\s*(?:추가|들어)|다시\s*관리자로\s*들어|관리자\s*그룹\s*추가/u,
  notAdminGroup: /관리자\s*그룹은\s*아닙|관리자\s*그룹이\s*아닙/u,
  command: /관리자\s*명령|권한\s*명령/u,
  session: /(?:세션|계정)이\s*관리자\s*권한으로\s*바뀌/u,
  unfamiliar: /처음\s*보는\s*주소|처음\s*봅니다|원격\s*주소/u,
  offHours: /(?:수업|업무)\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|평소와\s*다른\s*시각|새벽|심야/u,
  justPromoted: /방금\s*관리자가\s*된|곧바로|직후|다시\s*관리자로/u,
  otherAccount: /다른\s*계정의\s*권한/u,
  manyAccounts: /계정\s*(\d+)\s*개/u,
  both: /그룹\s*추가와\s*명령\s*실행|그룹에\s*들어가고\s*곧바로/u,
  weak: /권한\s*상승|관리자|그룹|계정\s*종류/u,
  // 상승이 실제로 일어나지 않았거나 평소대로인 표현
  defused: /취소됐|실패|이어서\s*명령은\s*없|변경은\s*없|평소\s*주소|설명만|읽기만|조회했습니다|조회한\s*뒤/u,
};

function signals(alert) {
  const rule = alert?.rule ?? {};
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const description = typeof rule.description === 'string' ? rule.description : '';
  const group = String(data.group ?? data.target_group ?? '').trim();
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const many = D.manyAccounts.exec(description);

  const adminGroup = ADMIN_GROUP.test(group);
  const groupAdd = !D.notAdminGroup.test(description) && (D.groupAdd.test(description) || (adminGroup && /추가|들어/u.test(description)));
  const command = D.command.test(description);
  const session = D.session.test(description);
  const defused = D.defused.test(description);

  // 경보 시각(현지 시각 표기 기준)이 07~22시 밖이면 시간 밖으로 봅니다.
  const hourMatch = /T(\d{2}):/u.exec(String(alert?.timestamp ?? ''));
  const hour = hourMatch ? Number(hourMatch[1]) : null;

  return {
    groupAdd, command, session, defused,
    unfamiliar: D.unfamiliar.test(description),
    offHours: D.offHours.test(description) || (hour !== null && (hour < 7 || hour >= 22)),
    justPromoted: D.justPromoted.test(description),
    otherAccount: D.otherAccount.test(description),
    both: D.both.test(description) || (groupAdd && command),
    count: Math.max(toInt(data.count), many ? toInt(many[1]) : 0, 1),
    weak: D.weak.test(description) || Boolean(group),
    level: Number.isFinite(Number(rule.level)) ? Number(rule.level) : 0,
    tagged: mitre.some((id) => /^T(?:1068|1078|1098|1548)(?:\.|$)/u.test(id)),
  };
}

export function decide(alert) {
  const s = signals(alert && typeof alert === 'object' ? alert : {});
  const escalated = s.groupAdd || s.command || s.session;

  const hits = [];
  if (s.groupAdd && (s.count >= 2 || s.unfamiliar || s.justPromoted || s.both || s.offHours)) hits.push('admin_group_addition');
  if ((s.command || s.session) && (s.justPromoted || s.unfamiliar || s.otherAccount)) hits.push('unfamiliar_admin_command');
  if (escalated && s.offHours) hits.push('off_hours_privilege_use');
  if (s.both) hits.push('group_add_then_admin_command');

  // 명확한 공격: 실제 권한 상승·사용 + 낯선 주소·시간 밖·직후 사용·다른 계정·여러 계정 중 하나 이상, 그리고 취소·실패가 아님
  if (escalated && hits.length && !s.defused) {
    let c = 0.83 + hits.length * 0.04;
    if (s.level >= 10) c += 0.04;
    if (s.tagged) c += 0.02;
    if (c >= BLOCK_AT) return { action: 'block', confidence: round(c), reason: `${hits.join(' + ')} (T1068·T1078)` };
    return { action: 'alert', confidence: round(c), reason: `${hits.join(' + ')}: 확신도가 낮아 알림만 (T1068·T1078)` };
  }

  // 애매한 시도: 권한 관련 경보지만 상승이 확인되지 않거나 낯선 신호가 없음
  if ((s.tagged || escalated) && s.level >= 4) {
    let c = 0.52 + Math.max(0, Math.min(s.level, 9) - 4) * 0.04;
    if (escalated && !s.defused) c += 0.04;
    return { action: 'alert', confidence: round(Math.min(0.8, Math.max(ALERT_AT, c))),
      reason: 'privilege_signal_without_escalation: 상승·낯선 사용이 확인되지 않아 알림만 (T1068·T1078)' };
  }

  // 정상 이벤트
  return { action: 'record', confidence: round(0.05 + Math.min(s.level, 5) * 0.02),
    reason: 'none: 관리자 그룹 추가나 낯선 관리자 권한 사용이 없는 정상 기록' };
}
