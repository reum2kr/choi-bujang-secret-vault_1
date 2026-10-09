// 보너스 xdr-02 제작 1 · 경보 읽기 (확인용)
// xdr/fixtures/web-injection.json 의 Wazuh 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑아 보여 줍니다.
// 원본 경보는 읽기만 하고 고치지 않습니다. decide.mjs 는 이 파일을 불러오지 않습니다.
// 실행: node xdr/brute-force/read-alerts.mjs
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// 비밀값처럼 보이는 문자열은 [가림]으로 바꿉니다.
const SECRET_LIKE = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
  /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/giu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/gu,
  /\b(?:sb_secret|sb_publishable|sk|pk|ghp|gho|xox[abp])[_-][A-Za-z0-9_-]{8,}/giu,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+/giu,
  /\b[A-Fa-f0-9]{32,}\b/gu,
];

export function redact(value) {
  if (typeof value !== 'string') return value;
  return SECRET_LIKE.reduce((text, pattern) => text.replace(pattern, '[가림]'), value);
}

export function extract(alert) {
  return {
    id: redact(String(alert?.id ?? '')),
    time: redact(String(alert?.timestamp ?? '')),
    srcip: redact(String(alert?.data?.srcip ?? '')),
    user: redact(String(alert?.data?.srcuser ?? alert?.data?.dstuser ?? '')),
    level: Number.isFinite(Number(alert?.rule?.level)) ? Number(alert.rule.level) : null,
    description: redact(String(alert?.rule?.description ?? '')),
  };
}

export async function readAlerts(file) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  const alerts = Array.isArray(fixture?.alerts) ? fixture.alerts : [];
  return { total: alerts.length, rows: alerts.map(extract) };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const { total, rows } = await readAlerts(join(root, 'xdr', 'fixtures', 'web-injection.json'));
  for (const r of rows) {
    console.log([r.id, r.time, r.srcip, r.user, `level ${r.level}`, r.description].join(' | '));
  }
  console.log(`경보 ${total}건 · 뽑은 줄 ${rows.length}줄 · ${total === rows.length ? '일치' : '불일치'}`);
  if (total !== rows.length) process.exitCode = 1;
}
