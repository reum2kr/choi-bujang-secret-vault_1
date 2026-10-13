// 10단계: 메모 사본(notes_backup) 검증 규칙. 복원 API와 제출 전 자기 점검이 같은 코드를 씁니다.
// 사본을 다시 읽은 값으로만 판단하며, 하나라도 맞지 않으면 복원하지 않고 멈춥니다.
import { createHash } from 'node:crypto';

export const contentSha256 = (title, body) => createHash('sha256').update(`${title}\n${body}`, 'utf8').digest('hex');

// 복원 전: 사본이 있고, 요청한 ID·검증된 요청자와 같고, 제목·내용으로 다시 계산한 지문이 저장된 지문과 같아야 합니다.
export function verifyCopy(copy, { id, ownerId }) {
  if (!copy) return { ok: false, status: 404, code: 'NOT_FOUND', reason: 'backup_missing' };
  if (copy.id !== id) return { ok: false, status: 404, code: 'NOT_FOUND', reason: 'backup_id_mismatch' };
  if (copy.owner_id !== ownerId) return { ok: false, status: 404, code: 'NOT_FOUND', reason: 'backup_not_owner' };
  if (typeof copy.title !== 'string' || typeof copy.body !== 'string'
    || !/^[a-f0-9]{64}$/u.test(copy.content_sha256 ?? '')
    || contentSha256(copy.title, copy.body) !== copy.content_sha256) {
    return { ok: false, status: 409, code: 'BACKUP_INVALID', reason: 'backup_hash_mismatch' };
  }
  return { ok: true };
}

// 복원 뒤: 다시 읽은 행의 ID·소유자·내용 지문이 사본과 같아야 합니다.
export function verifyRestored(row, copy) {
  return Boolean(row) && row.id === copy.id && row.owner_id === copy.owner_id
    && contentSha256(row.title, row.body) === copy.content_sha256;
}
