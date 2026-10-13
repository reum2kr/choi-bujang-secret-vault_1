// 10단계 제작 1·2: 침해 전에 검증한 안전 정책 사본(policy/safe)과 현재 시험 정책(policy/test/decider.mjs)을 비교하고,
// 확인을 받은 뒤에만 시험 정책을 사본 버전으로 되돌립니다.
//   npm run policy:diff                              → 사본 검증 + 복원할 버전과 변경 범위 미리보기(파일을 바꾸지 않음)
//   npm run policy:restore -- --confirm zone-v10     → 같은 미리보기 뒤 시험 정책 한 파일만 사본으로 되돌림
// 사본이 없거나 지문·Git 기록·안전 요청 묶음 검증 중 하나라도 실패하면 중단합니다.
// 실제 운영 정책(src/decider.mjs)은 읽어서 지문만 보여 주고 절대 쓰지 않습니다. 대상으로 지정하면 거부합니다.
// 운영 반 엔진의 정책 등록부, src/detect.mjs, xdr/ 규칙 같은 다른 서비스 규칙도 읽지도 쓰지도 않습니다.
// 복원 기록은 policy/audit.jsonl 끝에 한 줄씩 덧붙이기만 하고, 기존 기록은 지우거나 고치지 않습니다.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runProbes } from '../policy/probes.mjs';

const root = resolve(import.meta.dirname, '..');
const MANIFEST = join(root, 'policy', 'safe', 'manifest.json');
const AUDIT = join(root, 'policy', 'audit.jsonl');
export const TEST_POLICY = join(root, 'policy', 'test', 'decider.mjs');
export const OPERATING_POLICY = join(root, 'src', 'decider.mjs');
const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

class Stop extends Error {}
const stop = (message) => { throw new Stop(message); };

async function loadDecider(path) {
  // 같은 경로를 여러 번 읽어도 새로 불러오도록 지문을 붙입니다.
  const mod = await import(`${pathToFileURL(path).href}?sha=${sha256(readFileSync(path))}`);
  if (typeof mod.decide !== 'function') stop(`${relative(root, path)}에 decide 함수가 없습니다.`);
  return mod;
}

// ── 사본 검증 ────────────────────────────────────────────────────────────────
// options.snapshotPath는 제출 전 자기 점검이 변조·누락 사본으로 "중단되는지" 시험할 때만 씁니다.
export async function verifySnapshot(options = {}) {
  if (!existsSync(MANIFEST)) stop('안전 정책 사본의 검증 정보(policy/safe/manifest.json)가 없습니다. 복원을 중단합니다.');
  let manifest;
  try { manifest = JSON.parse(readFileSync(MANIFEST, 'utf8')); } catch { stop('manifest.json을 읽을 수 없습니다. 복원을 중단합니다.'); }
  if (manifest?.schema !== 'aleph.policy.snapshot.v1' || typeof manifest.version !== 'string'
    || !/^[a-f0-9]{64}$/u.test(manifest.sha256 ?? '') || manifest.targetPath !== 'policy/test/decider.mjs'
    || typeof manifest.snapshotPath !== 'string' || !manifest.snapshotPath.startsWith('policy/safe/')) {
    stop('manifest.json 형식이 맞지 않습니다. 복원을 중단합니다.');
  }
  const snapshotPath = options.snapshotPath ?? join(root, manifest.snapshotPath);
  if (!existsSync(snapshotPath)) stop(`안전 정책 사본(${manifest.snapshotPath})이 없습니다. 복원을 중단합니다.`);
  const bytes = readFileSync(snapshotPath);
  const actual = sha256(bytes);
  if (actual !== manifest.sha256) stop(`사본 지문이 다릅니다(기록 ${manifest.sha256.slice(0, 12)}…, 실제 ${actual.slice(0, 12)}…). 복원을 중단합니다.`);

  // Git 기록 대조: 기록된 커밋의 src/decider.mjs와 바이트가 같아야 합니다. Git 기록이 없으면 미실행으로 표시합니다.
  let gitCheck = '미실행(Git 기록 없음)';
  if (typeof manifest.sourceCommit === 'string' && /^[a-f0-9]{40}$/u.test(manifest.sourceCommit)) {
    let original = null;
    try {
      original = execFileSync('git', ['show', `${manifest.sourceCommit}:src/decider.mjs`],
        { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch { /* 얕은 복제 등으로 기록이 없을 때 */ }
    if (original) {
      if (sha256(original) !== manifest.sha256) stop(`사본이 커밋 ${manifest.sourceCommit.slice(0, 7)}의 판정기와 다릅니다. 복원을 중단합니다.`);
      gitCheck = `커밋 ${manifest.sourceCommit.slice(0, 7)}의 src/decider.mjs와 같음`;
    }
  }

  // 안전 요청 묶음: 사본은 모든 정상·금지 요청에 기대한 답을 해야 합니다.
  const snapshot = await loadDecider(snapshotPath);
  const ruleIds = Array.isArray(snapshot.RULE_IDS) ? [...snapshot.RULE_IDS] : [];
  if (JSON.stringify(ruleIds) !== JSON.stringify(manifest.ruleIds)) stop('사본의 RULE_IDS가 검증 정보와 다릅니다. 복원을 중단합니다.');
  const probes = await runProbes(snapshot.decide);
  const broken = probes.filter((p) => p.decision !== p.expected);
  if (broken.length) stop(`사본이 안전 요청 ${broken.length}건에서 기대와 다르게 답합니다(${broken.map((p) => p.name).join(', ')}). 복원을 중단합니다.`);
  return { manifest, snapshotPath, bytes, ruleIds, probes, gitCheck };
}

// ── 변경 범위 ────────────────────────────────────────────────────────────────
function lineDiff(before, after, limit = 40) {
  const a = before.split('\n');
  const b = after.split('\n');
  const n = a.length; const m = b.length;
  const lcs = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i -= 1) for (let j = m - 1; j >= 0; j -= 1) {
    lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
  }
  const out = [];
  let i = 0; let j = 0; let removed = 0; let added = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) { i += 1; j += 1; } else if (i < n && (j === m || lcs[i + 1][j] >= lcs[i][j + 1])) {
      removed += 1; if (out.length < limit) out.push(`- ${String(i + 1).padStart(3)} │ ${a[i].slice(0, 110)}`); i += 1;
    } else {
      added += 1; if (out.length < limit) out.push(`+ ${String(j + 1).padStart(3)} │ ${b[j].slice(0, 110)}`); j += 1;
    }
  }
  return { removed, added, lines: out, truncated: removed + added > out.length };
}

export async function diffPolicy(targetPath, options = {}) {
  const safe = await verifySnapshot(options);
  if (!existsSync(targetPath)) stop(`현재 시험 정책(${relative(root, targetPath)})이 없습니다.`);
  const currentBytes = readFileSync(targetPath);
  const current = await loadDecider(targetPath);
  const currentRules = Array.isArray(current.RULE_IDS) ? [...current.RULE_IDS] : [];
  const currentProbes = await runProbes(current.decide);
  const changedProbes = currentProbes
    .map((p, k) => ({ ...p, safe: safe.probes[k].decision, safeReason: safe.probes[k].reasonCode }))
    .filter((p) => p.decision !== p.safe || p.reasonCode !== p.safeReason);
  return {
    safe,
    operatingSha256: existsSync(OPERATING_POLICY) ? sha256(readFileSync(OPERATING_POLICY)) : null,
    currentSha256: sha256(currentBytes),
    identical: sha256(currentBytes) === safe.manifest.sha256,
    rulesAdded: currentRules.filter((r) => !safe.ruleIds.includes(r)),
    rulesRemoved: safe.ruleIds.filter((r) => !currentRules.includes(r)),
    changedProbes,
    text: lineDiff(currentBytes.toString('utf8'), safe.bytes.toString('utf8')),
  };
}

function printPlan(d, targetPath) {
  const w = (line = '') => process.stdout.write(`${line}\n`);
  w(`안전 정책 사본: ${d.safe.manifest.version} (${d.safe.manifest.snapshotPath})`);
  w(`  지문 ${d.safe.manifest.sha256.slice(0, 16)}… 확인 · Git 대조: ${d.safe.gitCheck} · 안전 요청 ${d.safe.probes.length}건 모두 기대대로`);
  w(`현재 시험 정책: ${relative(root, targetPath)} (지문 ${d.currentSha256.slice(0, 16)}…)`);
  w(`실제 운영 정책: src/decider.mjs (지문 ${String(d.operatingSha256).slice(0, 16)}…) — 읽기만 하고 바꾸지 않음`);
  if (d.identical) { w('변경 범위: 없음. 현재 시험 정책이 안전 정책 사본과 같습니다.'); return; }
  w(`변경 범위(되돌리면 바뀌는 것): 줄 ${d.text.removed}개 빠지고 ${d.text.added}개 들어옴`);
  if (d.rulesAdded.length) w(`  사본에 없는 규칙(되돌리면 사라짐): ${d.rulesAdded.join(', ')}`);
  if (d.rulesRemoved.length) w(`  사본에만 있는 규칙(되돌리면 돌아옴): ${d.rulesRemoved.join(', ')}`);
  if (d.changedProbes.length) {
    w(`  응답이 달라지는 요청 ${d.changedProbes.length}건:`);
    for (const p of d.changedProbes) w(`   · ${p.label}: 현재 ${p.decision}${p.reasonCode ? `(${p.reasonCode})` : ''} → 복원 뒤 ${p.safe}(${p.safeReason})`);
  } else {
    w('  응답이 달라지는 안전 요청: 없음(글자만 다름)');
  }
  w('  줄 차이(- 현재에서 빠짐, + 사본에서 들어옴):');
  for (const line of d.text.lines) w(`    ${line}`);
  if (d.text.truncated) w('    … (길어서 일부만 표시)');
}

// ── 되돌리기 ─────────────────────────────────────────────────────────────────
export async function restorePolicy(targetPath, confirm, options = {}) {
  const d = await diffPolicy(targetPath, options);
  printPlan(d, targetPath);
  if (confirm !== d.safe.manifest.version) {
    process.stdout.write(`\n미리보기만 했습니다. 위 항목을 확인했다면 --confirm ${d.safe.manifest.version} 을 붙여 다시 실행하세요.\n`);
    return { restored: false };
  }
  const entry = {
    at: new Date().toISOString(), action: 'policy_restore', version: d.safe.manifest.version,
    target: relative(root, targetPath), beforeSha256: d.currentSha256, afterSha256: d.safe.manifest.sha256,
    operatingPolicySha256: d.operatingSha256,
    changedProbes: d.changedProbes.map((p) => p.name), result: 'already_matches',
  };
  if (resolve(targetPath) === OPERATING_POLICY) stop('실제 운영 정책(src/decider.mjs)은 되돌리지 않습니다.');
  if (!d.identical) {
    writeFileSync(targetPath, d.safe.bytes); // 시험 정책 이 파일 하나만 씁니다.
    const after = readFileSync(targetPath);
    const reloaded = await loadDecider(targetPath);
    const recheck = await runProbes(reloaded.decide);
    const bad = recheck.filter((p) => p.decision !== p.expected);
    entry.result = sha256(after) === d.safe.manifest.sha256 && !bad.length ? 'restored' : 'restore_verify_failed';
  }
  const operatingAfter = existsSync(OPERATING_POLICY) ? sha256(readFileSync(OPERATING_POLICY)) : null;
  entry.operatingPolicyUnchanged = operatingAfter === d.operatingSha256;
  appendFileSync(AUDIT, `${JSON.stringify(entry)}\n`, { flag: 'a' });
  process.stdout.write(`\n복원 결과: ${entry.result} · 감사 기록 policy/audit.jsonl에 한 줄 추가\n`);
  if (entry.result === 'restore_verify_failed') stop('복원 뒤 검증이 실패했습니다. 파일을 확인하세요.');
  return { restored: entry.result === 'restored' };
}

// 대상은 시험 정책 policy/test/decider.mjs가 기본입니다. 연습용으로 저장소 밖 복사본만 --current로 지정할 수 있습니다.
// 실제 운영 정책(src/decider.mjs)과 저장소 안의 다른 파일(다른 서비스 규칙)은 대상으로 받지 않습니다.
function targetFrom(args) {
  const k = args.indexOf('--current');
  const target = resolve(k >= 0 && args[k + 1] ? args[k + 1] : TEST_POLICY);
  if (target === OPERATING_POLICY) stop('실제 운영 정책(src/decider.mjs)은 비교·복원 대상이 아닙니다. 시험 정책만 다룹니다.');
  const inRepo = !relative(root, target).startsWith('..');
  if (inRepo && target !== TEST_POLICY) stop('저장소 안에서는 시험 정책 policy/test/decider.mjs만 되돌릴 수 있습니다.');
  return target;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  try {
    const target = targetFrom(args);
    if (command === 'diff') {
      printPlan(await diffPolicy(target), target);
    } else if (command === 'restore') {
      const k = args.indexOf('--confirm');
      await restorePolicy(target, k >= 0 ? args[k + 1] : undefined);
    } else {
      stop('사용법: node scripts/policy-restore.mjs diff | restore --confirm <버전> [--current <연습용 사본>]');
    }
    process.stdout.write('로컬 정책 파일 비교·복원이며 운영 반 엔진의 정책이나 심판 판정이 아닙니다.\n');
  } catch (error) {
    process.stderr.write(`정책 복원 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
