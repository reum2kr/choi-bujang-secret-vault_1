// 11단계: 접속 앱의 서비스 워커. 공개 오프라인 안내(/offline.html) 한 장만 캐시합니다.
// 메모 API(/api/...), 로그인, 기기 상태, 첫 화면 같은 보호 화면과 응답은 캐시하지 않고 항상 네트워크로 보냅니다.
// 토큰·기기 ID·메모를 이 워커나 캐시에 저장하지 않습니다.
const CACHE = 'vault-offline-v1';
const OFFLINE_URL = '/offline.html';

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.add(new Request(OFFLINE_URL, { cache: 'reload' }))));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  // 화면 이동(문서 요청)이 네트워크 오류로 실패했을 때만 오프라인 안내를 보여 줍니다. 그 밖의 요청은 손대지 않습니다.
  if (request.mode !== 'navigate') return;
  event.respondWith(fetch(request).catch(() => caches.match(OFFLINE_URL)));
});
