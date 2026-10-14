// 보너스 privilege 제작 4 · 알림과 차단(세션 회수)
// decide.mjs 의 판단 결과를 받아
//   - block 후보만 ZTNA 판정기의 거부 규칙 목록(xdr/privilege/deny-rules.json)에 "그 계정의 그 주소 세션 회수" 규칙으로 넣고
//   - block·alert 를 xdr/alerts.log 에 한 줄씩 쌓습니다.
// decide.mjs 는 판단만 하고, 파일 쓰기·판정기 연결은 이 파일만 합니다.
// 판정기의 기존 규칙(src/decider.mjs 의 RULE_IDS·decide)은 고치지 않습니다.
// 실행: node xdr/privilege/respond.mjs
//
// 정상 사용자를 막지 않기 위해:
//   - 규칙은 계정 + 출발 주소 둘 다 맞을 때만 적용합니다. 같은 계정이 평소 주소에서 쓰는 세션은 그대로 둡니다.
//   - 같은 묶음에서 정상(record)으로 판단된 계정·주소 조합은 막지 않습니다.
//   - 운영용 계정(admin01·svc-lab 등)은 여기서 거두지 않고 알림만 남깁니다.
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

export const RULE_PREFIX = 'xdr.privilege.revoke_session';
const BLOCK_MINUTES = 60;          // 회수 규칙은 1시간 뒤 만료
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u;
const ACCOUNT = /^[A-Za-z0-9._-]{1,40}$/u;

// 절대 막지 않을 주소(사설·루프백)와 계정(운영용). 필요하면 여기에만 추가합니다.
const NEVER_BLOCK_IP = [/^10\./u, /^127\./u, /^192\.168\./u, /^172\.(1[6-9]|2\d|3[01])\./u];
const NEVER_REVOKE_ACCOUNT = new Set(['admin01', 'svc-lab', 'system', 'root']);

const isoPlus = (iso, minutes) => new Date(Date.parse(iso) + minutes * 60_000).toISOString();
const keyOf = (user, ip) => `${user}@${ip}`;

/**
 * 경보 묶음을 판단하고 세션 회수 규칙 후보와 알림 줄을 만듭니다. 파일은 쓰지 않습니다.
 * @param alerts Wazuh 모양 경보 배열
 * @param now    규칙 만료 시각 계산 기준(ISO). 기본값은 지금.
 */
export async function plan(alerts, now = new Date().toISOString()) {
  const decided = [];
  for (const alert of alerts) decided.push({ alert, out: await decide(alert) });

  const normalPairs = new Set(decided
    .filter(({ out }) => out.action === 'record')
    .map(({ alert }) => keyOf(alert?.data?.srcuser, alert?.data?.srcip)));

  const rules = new Map();   // 계정·주소 조합 하나에 규칙 하나, 근거 경보는 모읍니다.
  const skipped = [];
  const logLines = [];
  for (const { alert, out } of decided) {
    const id = String(alert?.id ?? '');
    const ip = String(alert?.data?.srcip ?? '');
    const user = String(alert?.data?.srcuser ?? '');
    if (out.action === 'alert') {
      logLines.push(`${now} ALERT privilege ${id} user=${user || '-'} src=${ip || '-'} conf=${out.confidence} ${out.reason}`);
    }
    if (out.action !== 'block') continue;

    const reasonSkip = !IPV4.test(ip) ? '주소 형식이 아님'
      : !ACCOUNT.test(user) ? '계정 형식이 아님'
      : NEVER_BLOCK_IP.some((p) => p.test(ip)) ? '내부 주소라 거두지 않음'
      : NEVER_REVOKE_ACCOUNT.has(user) ? '운영용 계정이라 알림만'
      : normalPairs.has(keyOf(user, ip)) ? '같은 계정·주소에 정상 이벤트가 있어 거두지 않음'
      : null;
    if (reasonSkip) {
      skipped.push({ alertId: id, srcuser: user, srcip: ip, why: reasonSkip });
      logLines.push(`${now} ALERT privilege ${id} user=${user || '-'} src=${ip || '-'} conf=${out.confidence} 회수 보류(${reasonSkip}) ${out.reason}`);
      continue;
    }

    const key = keyOf(user, ip);
    const existing = rules.get(key);
    if (existing) {
      existing.alertIds.push(id);
      existing.confidence = Math.max(existing.confidence, out.confidence);
    } else {
      rules.set(key, {
        ruleId: `${RULE_PREFIX}.${user.replace(/[^A-Za-z0-9]/gu, '_')}.${ip.replaceAll('.', '_')}`,
        decision: 'deny',
        action: 'revoke_session',
        match: { srcuser: user, srcip: ip },
        createdAt: now,
        expiresAt: isoPlus(now, BLOCK_MINUTES),
        alertIds: [id],
        confidence: out.confidence,
        reason: out.reason,
      });
    }
    logLines.push(`${now} BLOCK privilege ${id} user=${user} src=${ip} conf=${out.confidence} 세션 회수 ${out.reason}`);
  }
  return { rules: [...rules.values()], skipped, logLines, decided };
}

/** 회수 규칙으로 요청 하나를 검사합니다(만료된 규칙은 무시). 판정기에 꽂을 확인 단계입니다. */
export function isDenied(rules, srcuser, srcip, at = new Date().toISOString()) {
  const t = Date.parse(at);
  return rules.find((r) => r.match?.srcuser === srcuser && r.match?.srcip === srcip
    && Date.parse(r.createdAt) <= t && t < Date.parse(r.expiresAt)) ?? null;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'privilege.json'), 'utf8'));
  const now = new Date().toISOString();
  const { rules, skipped, logLines, decided } = await plan(fixture.alerts ?? [], now);

  await writeFile(join(root, 'xdr', 'privilege', 'deny-rules.json'), `${JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1', moduleKey: 'privilege', generatedAt: now, rules,
  }, null, 2)}\n`, 'utf8');
  await mkdir(join(root, 'xdr'), { recursive: true });
  if (logLines.length) await appendFile(join(root, 'xdr', 'alerts.log'), `${logLines.join('\n')}\n`, 'utf8');

  // 시험 경보를 다시 흘려 봅니다: 각 경보의 계정·주소 세션이 지금 거둬지는지 확인
  let wrongBlocks = 0;
  let missed = 0;
  for (const { alert, out } of decided) {
    const denied = Boolean(isDenied(rules, alert?.data?.srcuser, alert?.data?.srcip, now));
    if (denied && out.action !== 'block') wrongBlocks += 1;
    if (!denied && out.action === 'block' && !skipped.some((s) => s.alertId === String(alert?.id))) missed += 1;
  }
  console.log(`회수 규칙 ${rules.length}개 · 보류 ${skipped.length}건 · 알림 줄 ${logLines.length}줄`);
  console.log(`다시 흘리기: 명확한 공격 세션 회수 ${rules.length}곳, 정상·애매 세션을 거둔 경우 ${wrongBlocks}건, 놓친 회수 ${missed}건`);
  if (wrongBlocks || missed) process.exitCode = 1;
}
