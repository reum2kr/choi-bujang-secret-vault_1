// 보너스 exfiltration 제작 4 · 알림과 차단(목적지 차단)
// decide.mjs 의 판단 결과를 받아
//   - block 후보만 ZTNA 판정기의 거부 규칙 목록(xdr/exfiltration/deny-rules.json)에 "그 목적지로 나가는 전송 차단" 규칙으로 넣고
//   - block·alert 를 xdr/alerts.log 에 한 줄씩 쌓습니다.
// decide.mjs 는 판단만 하고, 파일 쓰기·판정기 연결은 이 파일만 합니다.
// 판정기의 기존 규칙(src/decider.mjs 의 RULE_IDS·decide)은 고치지 않습니다.
// 실행: node xdr/exfiltration/respond.mjs
//
// 정상 사용자를 막지 않기 위해:
//   - 규칙은 목적지 주소(dstip)만 막습니다. 계정·출발 주소는 막지 않으므로 같은 사용자의 평소 요청은 그대로 통과합니다.
//   - 같은 묶음에서 정상(record)이나 알림(alert) 전송이 간 목적지(자료실·수업 자료 주소 등)는 막지 않습니다.
//   - 사설·루프백 대역과 자료실 목적지는 막지 않습니다.
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

export const RULE_PREFIX = 'xdr.exfiltration.deny_destination';
const BLOCK_MINUTES = 60;          // 차단 규칙은 1시간 뒤 만료
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u;

// 절대 막지 않을 목적지: 사설·루프백 대역. 필요하면 여기에만 추가합니다.
const NEVER_BLOCK_DST = [/^10\./u, /^127\./u, /^192\.168\./u, /^172\.(1[6-9]|2\d|3[01])\./u];

const isoPlus = (iso, minutes) => new Date(Date.parse(iso) + minutes * 60_000).toISOString();
const dstOf = (alert) => String(alert?.data?.dstip ?? '');

/**
 * 경보 묶음을 판단하고 목적지 차단 규칙 후보와 알림 줄을 만듭니다. 파일은 쓰지 않습니다.
 * @param alerts Wazuh 모양 경보 배열
 * @param now    규칙 만료 시각 계산 기준(ISO). 기본값은 지금.
 */
export async function plan(alerts, now = new Date().toISOString()) {
  const decided = [];
  for (const alert of alerts) decided.push({ alert, out: await decide(alert) });

  // 정상·알림 전송이 간 목적지는 평소 쓰는 곳일 수 있으므로 막지 않습니다.
  const keepDst = new Set(decided.filter(({ out }) => out.action !== 'block').map(({ alert }) => dstOf(alert)).filter(Boolean));

  const rules = new Map();   // 목적지 하나에 규칙 하나, 근거 경보는 모읍니다.
  const skipped = [];
  const logLines = [];
  for (const { alert, out } of decided) {
    const id = String(alert?.id ?? '');
    const dst = dstOf(alert);
    const src = String(alert?.data?.srcip ?? '');
    if (out.action === 'alert') {
      logLines.push(`${now} ALERT exfiltration ${id} src=${src || '-'} dst=${dst || '-'} bytes=${Number(alert?.data?.bytes ?? 0)} conf=${out.confidence} ${out.reason}`);
    }
    if (out.action !== 'block') continue;

    const reasonSkip = !IPV4.test(dst) ? '목적지 주소 형식이 아님'
      : NEVER_BLOCK_DST.some((p) => p.test(dst)) ? '내부 목적지라 막지 않음'
      : keepDst.has(dst) ? '같은 목적지에 정상·알림 전송이 있어 막지 않음'
      : null;
    if (reasonSkip) {
      skipped.push({ alertId: id, dstip: dst, why: reasonSkip });
      logLines.push(`${now} ALERT exfiltration ${id} src=${src || '-'} dst=${dst || '-'} conf=${out.confidence} 차단 보류(${reasonSkip}) ${out.reason}`);
      continue;
    }

    const existing = rules.get(dst);
    if (existing) {
      existing.alertIds.push(id);
      existing.confidence = Math.max(existing.confidence, out.confidence);
    } else {
      rules.set(dst, {
        ruleId: `${RULE_PREFIX}.${dst.replaceAll('.', '_')}`,
        decision: 'deny',
        match: { dstip: dst },
        createdAt: now,
        expiresAt: isoPlus(now, BLOCK_MINUTES),
        alertIds: [id],
        confidence: out.confidence,
        reason: out.reason,
      });
    }
    logLines.push(`${now} BLOCK exfiltration ${id} src=${src || '-'} dst=${dst} bytes=${Number(alert?.data?.bytes ?? 0)} conf=${out.confidence} 목적지 차단 ${out.reason}`);
  }
  return { rules: [...rules.values()], skipped, logLines, decided };
}

/** 목적지 차단 규칙으로 전송 하나를 검사합니다(만료된 규칙은 무시). 판정기에 꽂을 확인 단계입니다. */
export function isDenied(rules, dstip, at = new Date().toISOString()) {
  const t = Date.parse(at);
  return rules.find((r) => r.match?.dstip === dstip
    && Date.parse(r.createdAt) <= t && t < Date.parse(r.expiresAt)) ?? null;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'exfiltration.json'), 'utf8'));
  const now = new Date().toISOString();
  const { rules, skipped, logLines, decided } = await plan(fixture.alerts ?? [], now);

  await writeFile(join(root, 'xdr', 'exfiltration', 'deny-rules.json'), `${JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1', moduleKey: 'exfiltration', generatedAt: now, rules,
  }, null, 2)}\n`, 'utf8');
  await mkdir(join(root, 'xdr'), { recursive: true });
  if (logLines.length) await appendFile(join(root, 'xdr', 'alerts.log'), `${logLines.join('\n')}\n`, 'utf8');

  // 시험 경보를 다시 흘려 봅니다: 각 경보의 목적지가 지금 막히는지 확인
  let wrongBlocks = 0;
  let missed = 0;
  for (const { alert, out } of decided) {
    const denied = Boolean(isDenied(rules, alert?.data?.dstip, now));
    if (denied && out.action !== 'block') wrongBlocks += 1;
    if (!denied && out.action === 'block' && !skipped.some((s) => s.alertId === String(alert?.id))) missed += 1;
  }
  console.log(`목적지 차단 규칙 ${rules.length}개 · 보류 ${skipped.length}건 · 알림 줄 ${logLines.length}줄`);
  console.log(`다시 흘리기: 명확한 유출 목적지 차단 ${rules.length}곳, 정상·애매 전송을 막은 경우 ${wrongBlocks}건, 놓친 차단 ${missed}건`);
  if (wrongBlocks || missed) process.exitCode = 1;
}
