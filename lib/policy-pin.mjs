// 10단계: 침해 전에 검증한 안전 정책 사본의 고정 지문입니다.
// 사본 검증은 Git 기록이 없는 곳(얕은 복사본, 심판의 격리 사본, 서버 함수)에서도 똑같이 되도록 이 지문으로 합니다.
// 사본(policy/safe/manifest.json, policy/safe/decider.zone-v10r2.mjs)을 바꾸면 지문이 달라져 검증이 실패하고 복원이 멈춥니다.
import { createHash } from 'node:crypto';

export const POLICY_VERSION = 'zone-v10r2';
export const POLICY_REVISION = 1;
// policy/safe/decider.zone-v10r2.mjs 파일의 SHA-256
export const POLICY_SNAPSHOT_SHA256 = 'e9a8ddeb8cc0f650f1a9e5749478927e89d9f0887180be440b1a974505d07932';
// policy/safe/manifest.json 내용(JSON.stringify로 다시 쓴 문자열)의 SHA-256
export const POLICY_MANIFEST_SHA256 = 'c65c0b1839dfa50ec5868e89d150addc15f74b7ab83ff09aff0589d390871b42';

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

// 사본 검증 정보를 다시 읽어 지문·버전·정책 버전·복원 범위를 확인합니다. 하나라도 다르면 { ok:false }.
export function verifyPolicyManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') return { ok: false, reason: 'policy_backup_missing' };
  let digest;
  try { digest = sha256(JSON.stringify(manifest)); } catch { return { ok: false, reason: 'policy_backup_unreadable' }; }
  if (digest !== POLICY_MANIFEST_SHA256) return { ok: false, reason: 'policy_backup_digest_differs' };
  if (manifest.version !== POLICY_VERSION || manifest.sha256 !== POLICY_SNAPSHOT_SHA256
    || manifest.policyRevision !== POLICY_REVISION || !manifest.ruleIds?.includes('restore_verified_policy')) {
    return { ok: false, reason: 'policy_backup_unverified' };
  }
  return { ok: true, version: manifest.version, policyRevision: manifest.policyRevision };
}
