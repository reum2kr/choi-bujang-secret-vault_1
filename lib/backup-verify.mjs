// 10단계: 메모 사본(notes_backup) 검증 규칙. 복원 API와 제출 전 자기 점검이 같은 코드를 씁니다.
// 기준은 침해 전에 검증해 저장소에 커밋한 기록(backup/notes-manifest.json)입니다.
// 사본 표에 함께 저장된 해시만 믿지 않습니다(표를 바꿀 수 있으면 해시도 같이 바꿀 수 있으므로).
// 복원 직전에 사본을 다시 읽어, ID·소유자·내용 해시가 그 기록과 모두 같을 때만 통과시키고, 하나라도 다르면 멈춥니다.
import { createHash } from 'node:crypto';
import manifest from '../backup/notes-manifest.json' with { type: 'json' };

const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');
export const contentSha256 = (title, body) => sha256(`${title}\n${body}`);
export const ownerSha256 = (ownerId) => sha256(String(ownerId));
export const MANIFEST = manifest;

const HEX64 = /^[a-f0-9]{64}$/u;

// 기록 자체 검사: 형식이 틀리거나 침해 전 재계산이 통과하지 않은 항목이 있으면 기록 전체를 믿지 않습니다.
export function manifestProblem(m = manifest) {
  if (m?.schema !== 'aleph.backup.manifest.v1' || typeof m.label !== 'string' || !Array.isArray(m.entries) || !m.entries.length) {
    return 'manifest_invalid';
  }
  const ids = new Set();
  for (const e of m.entries) {
    if (typeof e?.id !== 'string' || !HEX64.test(e.owner_sha256 ?? '') || !HEX64.test(e.content_sha256 ?? '')
      || e.recomputed_ok !== true || ids.has(e.id)) return 'manifest_invalid';
    ids.add(e.id);
  }
  return null;
}

export function manifestEntry(id, m = manifest) {
  return m.entries.find((e) => e.id === id) ?? null;
}

// 복원 전: 기록에 있는 ID인지, 다시 읽은 사본의 ID·소유자·내용 해시가 기록과 같은지, 요청자가 그 소유자인지 확인합니다.
export function verifyCopy(copy, { id, ownerId }, m = manifest) {
  if (manifestProblem(m)) return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'manifest_invalid' };
  const entry = manifestEntry(id, m);
  if (!entry) return { ok: false, status: 404, code: 'NOT_FOUND', reason: 'not_in_verified_backup' };
  if (!copy) return { ok: false, status: 404, code: 'NOT_FOUND', reason: 'backup_row_absent' };
  if (copy.id !== entry.id) return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'backup_id_differs' };
  if (ownerSha256(copy.owner_id) !== entry.owner_sha256) return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'backup_owner_differs' };
  if (copy.owner_id !== ownerId) return { ok: false, status: 404, code: 'NOT_FOUND', reason: 'not_owner' };
  if (typeof copy.title !== 'string' || typeof copy.body !== 'string'
    || copy.content_sha256 !== entry.content_sha256 || contentSha256(copy.title, copy.body) !== entry.content_sha256) {
    return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'backup_hash_differs' };
  }
  return { ok: true, entry, label: m.label };
}

// 복원 뒤: 다시 읽은 행의 ID·소유자·내용 해시가 침해 전 기록과 같아야 합니다.
export function verifyRestored(row, entry) {
  return Boolean(row && entry) && row.id === entry.id && ownerSha256(row.owner_id) === entry.owner_sha256
    && contentSha256(row.title, row.body) === entry.content_sha256;
}
