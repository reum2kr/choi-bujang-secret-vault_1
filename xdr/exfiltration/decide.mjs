// 보너스 exfiltration 제작 3 · 판단 모듈
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부릅니다.
// 그래서 import·파일 읽기/쓰기·네트워크 없이 이 파일 안의 상수와 계산만 씁니다.
// 판정기 연결(목적지 차단 규칙)과 알림 기록은 respond.mjs 가 맡습니다.

// xdr/exfiltration/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'bulk_transfer_new_destination',
    technique: 'T1048',
    condition: '처음 보는(평소와 다른) 외부 목적지로 대용량(50MB 이상) 또는 많은 파일(50건 이상, 자료실 전체)이 한꺼번에 나감',
    evidence: 'MITRE ATT&CK T1048: 공격자는 평소 업무에 쓰지 않는 목적지·프로토콜로 모은 자료를 한 번에 내보내며, 낯선 목적지로 가는 대용량 전송은 대표적인 유출 흔적이다.',
  }),
  Object.freeze({
    name: 'off_hours_archive_exfil',
    technique: 'T1048',
    condition: '업무·수업 시간 밖에 대용량 전송이 일어나거나, 압축 파일이 처음 보는 주소로 올라감',
    evidence: 'MITRE ATT&CK T1048·T1560: 공격자는 자료를 압축해 묶은 뒤 감시가 적은 시간에 외부로 옮긴다.',
  }),
  Object.freeze({
    name: 'repeated_transfer_same_destination',
    technique: 'T1041',
    condition: '같은 목적지로 대용량 전송이 5번 이상 반복되거나 연속으로 이어짐',
    evidence: 'MITRE ATT&CK T1041·T1030: 공격자는 탐지를 피하려고 자료를 나눠 같은 목적지로 여러 번 보낸다.',
  }),
  Object.freeze({
    name: 'c2_channel_or_unusual_port',
    technique: 'T1041',
    condition: '명령 통로나 평소에 쓰지 않던 포트로 큰 파일·자료 이름이 전송됨',
    evidence: 'MITRE ATT&CK T1041: 공격자는 이미 열어 둔 명령·제어 통로에 자료를 실어 내보내고, T1048 처럼 평소와 다른 포트·프로토콜을 쓰기도 한다.',
  }),
  Object.freeze({
    name: 'transfer_anomaly_unconfirmed',
    technique: 'T1048',
    condition: '낯선 주소·평소보다 큰 전송·압축 파일 같은 신호가 하나 있지만, 크기가 작거나 한 번뿐이거나 실패·아직 전송 없음·평소 목적지라 유출이 확인되지 않음',
    evidence: 'MITRE ATT&CK T1041·T1048: 백업·수업 자료 동기화 같은 정상 전송과 겹치는 약한 신호는 알림만 하고 목적지를 막지 않는다.',
  }),
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const LARGE_BYTES = 50_000_000;   // 50MB 이상은 대용량
const MID_BYTES = 1_000_000;      // 1MB 이상은 눈여겨볼 크기
const MANY_FILES = 50;
const REPEAT_MIN = 5;

const round = (n) => Math.round(Math.min(1, Math.max(0, n)) * 100) / 100;
const toInt = (value) => {
  const n = Number.parseInt(String(value ?? '').replace(/[^0-9]/gu, ''), 10);
  return Number.isFinite(n) ? n : 0;
};

const D = {
  newDest: /처음\s*보는|처음\s*봅|외부\s*주소|평소와\s*다른\s*주소/u,
  usualDest: /평소\s*목적지|수업\s*자료\s*주소|목적지는\s*자료실/u,
  offHours: /(?:수업|업무)\s*시간\s*밖|새벽|심야/u,
  archive: /압축\s*파일/u,
  channel: /명령\s*통로|평소에\s*쓰지\s*않던\s*포트|다른\s*프로토콜/u,
  whole: /자료실\s*전체|전체가\s*외부/u,
  repeat: /(\d+)\s*번\s*(?:반복|입니다|있)|반복|연속/u,
  notSent: /실패|외부\s*전송은\s*아직\s*없|전송은\s*없|큰\s*파일은\s*아닙|일부만/u,
};

function signals(alert) {
  const rule = alert?.rule ?? {};
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const description = typeof rule.description === 'string' ? rule.description : '';
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const bytes = toInt(data.bytes ?? data.size ?? data.bytes_out);
  const files = toInt(data.files);
  const repeatText = /(\d+)\s*번/u.exec(description);
  const count = Math.max(toInt(data.count), repeatText ? toInt(repeatText[1]) : 0, 1);
  const hourMatch = /T(\d{2}):/u.exec(String(alert?.timestamp ?? ''));
  const hour = hourMatch ? Number(hourMatch[1]) : null;

  return {
    bytes, files, count,
    hasDest: Boolean(data.dstip ?? data.dst ?? data.destination),
    large: bytes >= LARGE_BYTES,
    mid: bytes >= MID_BYTES,
    manyFiles: files >= MANY_FILES || D.whole.test(description),
    newDest: D.newDest.test(description),
    usualDest: D.usualDest.test(description),
    offHours: D.offHours.test(description) || (hour !== null && (hour < 7 || hour >= 22)),
    archive: D.archive.test(description),
    channel: D.channel.test(description),
    repeated: count >= REPEAT_MIN || (D.repeat.test(description) && count >= 2) || /연속/u.test(description),
    notSent: D.notSent.test(description) || bytes === 0,
    level: Number.isFinite(Number(rule.level)) ? Number(rule.level) : 0,
    tagged: mitre.some((id) => /^T(?:1041|1048|1567|1020|1030)(?:\.|$)/u.test(id)),
  };
}

export function decide(alert) {
  const s = signals(alert && typeof alert === 'object' ? alert : {});

  // 명확한 유출: 실제로 나간 대용량(또는 많은 파일) 전송 + 낯선 목적지·시간 밖·압축·반복·명령 통로 중 하나 이상
  const bulk = s.large || s.manyFiles;
  if (bulk && s.hasDest && !s.notSent && !s.usualDest) {
    const hits = [];
    if (s.newDest || s.manyFiles) hits.push('bulk_transfer_new_destination');
    if (s.offHours || (s.archive && s.newDest)) hits.push('off_hours_archive_exfil');
    if (s.repeated) hits.push('repeated_transfer_same_destination');
    if (s.channel) hits.push('c2_channel_or_unusual_port');
    if (hits.length) {
      let c = 0.84 + hits.length * 0.04;
      if (s.level >= 10) c += 0.03;
      if (s.tagged) c += 0.02;
      if (s.bytes >= 200_000_000) c += 0.02;
      return { action: c >= BLOCK_AT ? 'block' : 'alert', confidence: round(c), reason: `${hits.join(' + ')} (T1041·T1048)` };
    }
  }

  // 애매한 시도: 전송 이상 신호가 있지만 작거나 한 번뿐이거나 실패·평소 목적지
  const anomaly = s.newDest || s.archive || s.channel || s.offHours || s.mid || bulk;
  if ((anomaly || s.tagged) && !(s.level <= 3 && !s.mid && !s.newDest && !s.offHours && !s.archive)) {
    let c = 0.52 + Math.max(0, Math.min(s.level, 9) - 4) * 0.04;
    if (s.newDest) c += 0.04;
    if (s.mid) c += 0.03;
    return { action: 'alert', confidence: round(Math.min(0.8, Math.max(ALERT_AT, c))),
      reason: 'transfer_anomaly_unconfirmed: 크기·횟수·목적지 신호가 약해 알림만 (T1041·T1048)' };
  }

  // 정상 이벤트
  return { action: 'record', confidence: round(0.05 + Math.min(s.level, 5) * 0.02),
    reason: 'none: 평소 목적지로 가는 작은 전송이나 읽기 기록' };
}
