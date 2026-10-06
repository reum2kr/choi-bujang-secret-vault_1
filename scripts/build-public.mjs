import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
// 2단계: 메모는 Supabase로 옮겼으므로 공개 data.json을 더 이상 만들지 않습니다.
// 혹시 남아 있는 옛 파일도 배포 결과물에서 지웁니다. 화면은 /api/notes로 읽습니다.
await mkdir(resolve(root, 'public'), { recursive: true });
await rm(resolve(root, 'public', 'data.json'), { force: true });
console.log('공개 data.json을 만들지 않습니다. 메모는 /api/notes 서버 함수로만 읽습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
