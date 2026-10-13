// 10단계: 메모 사본(notes_backup) 검증 규칙. 복원 API와 제출 전 자기 점검이 같은 코드를 씁니다.
// 침해 전 메모의 기준은 검증해 저장소에 커밋한 기록(backup/notes-manifest.json)이고,
// 그 뒤에 만든 메모의 기준은 만들 때 서버가 남긴 처음 사본(덧붙이기만 가능한 notes_backup)입니다.
// 복원 직전에 사본을 다시 읽어, ID·소유자·내용 해시가 기준과 모두 같을 때만 통과시키고, 하나라도 다르면 멈춥니다.
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

// 복원 전: 사본을 다시 읽어 ID·소유자·내용 해시를 확인하고, 요청자가 그 소유자인지 확인합니다.
//  · 침해 전 검증 기록(manifest)에 있는 메모: 사본의 ID·소유자 지문·내용 해시가 그 기록과 모두 같아야 합니다.
//  · 기록 뒤에 만든 메모(메모를 만들 때 서버가 남긴 사본): 사본의 제목·내용으로 해시를 다시 계산해, 사본에 저장된 해시와 같아야 합니다.
//    사본 표는 덧붙이기만 되고(고치기·지우기 불가) 메모마다 처음 사본 하나가 기준입니다.
//  사본이 없으면 404, 남의 사본이면 404, 검증이 실패하면 409로 멈춥니다(쓰기 없음).
export function verifyCopy(copy, { id, ownerId }, m = manifest) {
  if (manifestProblem(m)) return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'manifest_invalid' };
  if (!copy) return { ok: false, status: 404, code: 'NOT_FOUND', reason: 'backup_row_absent' };
  if (copy.id !== id) return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'backup_id_differs' };
  const listed = manifestEntry(id, m);
  if (listed && ownerSha256(copy.owner_id) !== listed.owner_sha256) return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'backup_owner_differs' };
  if (copy.owner_id !== ownerId) return { ok: false, status: 404, code: 'NOT_FOUND', reason: 'not_owner' };
  if (typeof copy.title !== 'string' || typeof copy.body !== 'string' || !HEX64.test(copy.content_sha256 ?? '')
    || contentSha256(copy.title, copy.body) !== copy.content_sha256
    || (listed && copy.content_sha256 !== listed.content_sha256)) {
    return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'backup_hash_differs' };
  }
  const entry = listed ?? { id, owner_sha256: ownerSha256(copy.owner_id), content_sha256: copy.content_sha256 };
  return { ok: true, entry, label: listed ? m.label : String(copy.backup_label ?? 'on-create') };
}

// 복원 뒤: 다시 읽은 행의 ID·소유자·내용 해시가 침해 전 기록과 같아야 합니다.
export function verifyRestored(row, entry) {
  return Boolean(row && entry) && row.id === entry.id && ownerSha256(row.owner_id) === entry.owner_sha256
    && contentSha256(row.title, row.body) === entry.content_sha256;
}
