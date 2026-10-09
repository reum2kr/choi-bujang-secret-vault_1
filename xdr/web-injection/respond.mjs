// 보너스 xdr-02 제작 4 · 알림과 차단
// decide.mjs 의 판단 결과를 받아
//   - block 후보만 ZTNA 판정기의 거부 규칙 목록(xdr/web-injection/deny-rules.json)에 넣고
//   - block·alert 를 xdr/alerts.log 에 한 줄씩 쌓습니다.
// decide.mjs 는 판단만 하고, 파일 쓰기·판정기 연결은 이 파일만 합니다.
// 판정기의 기존 규칙(src/decider.mjs 의 RULE_IDS·decide)은 고치지 않습니다.
// 실행: node xdr/web-injection/respond.mjs
// 알림 줄에는 주입 문자열이 남지 않도록 요청 주소의 경로만 적고 쿼리는 버립니다.
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

export const RULE_PREFIX = 'xdr.web_injection.deny_source';
const BLOCK_MINUTES = 60;          // 차단 규칙은 1시간 뒤 만료
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/u;

// 절대 막지 않을 주소: 사설·루프백 대역(내부 사용자·관리 경로). 필요하면 여기에만 추가합니다.
const NEVER_BLOCK = [/^10\./u, /^127\./u, /^192\.168\./u, /^172\.(1[6-9]|2\d|3[01])\./u];

const pathOnly = (url) => String(url ?? '').split(/[?#]/u)[0].replace(/[^A-Za-z0-9/_.-]/gu, '').slice(0, 80) || '-';
const isoPlus = (iso, minutes) => new Date(Date.parse(iso) + minutes * 60_000).toISOString();

/**
 * 경보 묶음을 판단하고 거부 규칙 후보와 알림 줄을 만듭니다. 파일은 쓰지 않습니다.
 * @param alerts Wazuh 모양 경보 배열
 * @param now    규칙 만료 시각 계산 기준(ISO). 기본값은 지금.
 */
export async function plan(alerts, now = new Date().toISOString()) {
  const decided = [];
  for (const alert of alerts) {
    decided.push({ alert, out: await decide(alert) });
  }

  // 같은 묶음에서 정상(record)으로 판단된 주소는 정상 사용자 주소로 보고 막지 않습니다.
  const normalIps = new Set(decided
    .filter(({ out }) => out.action === 'record')
    .map(({ alert }) => alert?.data?.srcip)
    .filter(Boolean));

  const rules = new Map();   // 주소 하나에 규칙 하나, 근거 경보는 모읍니다.
  const skipped = [];
  const logLines = [];
  for (const { alert, out } of decided) {
    const id = String(alert?.id ?? '');
    const ip = String(alert?.data?.srcip ?? '');
    if (out.action === 'alert') {
      logLines.push(`${now} ALERT web-injection ${id} src=${ip || '-'} path=${pathOnly(alert?.data?.url)} conf=${out.confidence} ${out.reason}`);
    }
    if (out.action !== 'block') continue;

    const reasonSkip = !IPV4.test(ip) ? '주소 형식이 아님'
      : NEVER_BLOCK.some((p) => p.test(ip)) ? '내부 주소라 막지 않음'
      : normalIps.has(ip) ? '같은 주소에 정상 이벤트가 있어 막지 않음'
      : null;
    if (reasonSkip) {
      skipped.push({ alertId: id, srcip: ip, why: reasonSkip });
      logLines.push(`${now} ALERT web-injection ${id} src=${ip || '-'} path=${pathOnly(alert?.data?.url)} conf=${out.confidence} 차단 보류(${reasonSkip}) ${out.reason}`);
      continue;
    }

    const existing = rules.get(ip);
    if (existing) {
      existing.alertIds.push(id);
      existing.confidence = Math.max(existing.confidence, out.confidence);
    } else {
      rules.set(ip, {
        ruleId: `${RULE_PREFIX}.${ip.replaceAll('.', '_')}`,
        decision: 'deny',
        match: { srcip: ip },
        createdAt: now,
        expiresAt: isoPlus(now, BLOCK_MINUTES),
        alertIds: [id],
        confidence: out.confidence,
        reason: out.reason,
      });
    }
    logLines.push(`${now} BLOCK web-injection ${id} src=${ip} path=${pathOnly(alert?.data?.url)} conf=${out.confidence} ${out.reason}`);
  }
  return { rules: [...rules.values()], skipped, logLines, decided };
}

/** 거부 규칙 목록으로 요청 하나를 검사합니다(만료된 규칙은 무시). 판정기에 꽂을 확인 단계입니다. */
export function isDenied(rules, srcip, at = new Date().toISOString()) {
  const t = Date.parse(at);
  return rules.find((r) => r.match?.srcip === srcip
    && Date.parse(r.createdAt) <= t && t < Date.parse(r.expiresAt)) ?? null;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'web-injection.json'), 'utf8'));
  const now = new Date().toISOString();
  const { rules, skipped, logLines, decided } = await plan(fixture.alerts ?? [], now);

  const rulesFile = join(root, 'xdr', 'web-injection', 'deny-rules.json');
  await writeFile(rulesFile, `${JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1', moduleKey: 'web-injection', generatedAt: now, rules,
  }, null, 2)}\n`, 'utf8');
  await mkdir(join(root, 'xdr'), { recursive: true });
  if (logLines.length) await appendFile(join(root, 'xdr', 'alerts.log'), `${logLines.join('\n')}\n`, 'utf8');

  // 시험 경보를 다시 흘려 봅니다: 각 경보의 주소가 지금 막히는지 확인
  let wrongBlocks = 0;
  let missed = 0;
  for (const { alert, out } of decided) {
    const ip = alert?.data?.srcip;
    const denied = Boolean(isDenied(rules, ip, now));
    if (denied && out.action !== 'block') wrongBlocks += 1;
    if (!denied && out.action === 'block' && !skipped.some((s) => s.srcip === ip)) missed += 1;
  }
  console.log(`거부 규칙 ${rules.length}개 · 보류 ${skipped.length}건 · 알림 줄 ${logLines.length}줄`);
  console.log(`다시 흘리기: 명확한 공격 주소 차단 ${rules.length}곳, 정상·애매 주소를 막은 경우 ${wrongBlocks}건, 놓친 차단 ${missed}건`);
  if (wrongBlocks || missed) process.exitCode = 1;
}
