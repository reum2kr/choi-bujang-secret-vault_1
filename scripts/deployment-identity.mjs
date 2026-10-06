const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;
// "GET /api/notes/:id" 같은 메서드+경로만 공개합니다. 키·토큰 같은 값은 들어갈 수 없습니다.
const ROUTE = /^(GET|POST|PUT|PATCH|DELETE) \/[A-Za-z0-9/:._-]{0,120}$/u;

// 쿼리·해시·계정정보가 없는 HTTPS 주소만 공개합니다. 비밀값이 섞일 자리를 남기지 않습니다.
function plainHttpsUrl(value) {
  if (typeof value !== 'string' || value.length > 300) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return null;
    return url.href;
  } catch {
    return null;
  }
}

// 3단계부터 쓰는 공개 설정(허용 경로·로그인 발급자·원본 자료 주소·복구 경로)을 골라 담습니다.
function publicSettings(config) {
  const settings = {};
  if (Array.isArray(config.allowedRoutes) && config.allowedRoutes.length) {
    settings.allowedRoutes = config.allowedRoutes.filter((route) => typeof route === 'string' && ROUTE.test(route));
  }
  const idp = config.identityProvider;
  if (idp && typeof idp === 'object') {
    const issuer = plainHttpsUrl(idp.issuer);
    const jwksUrl = plainHttpsUrl(idp.jwksUrl);
    if (issuer && jwksUrl && typeof idp.audience === 'string' && /^[a-zA-Z0-9._:-]{1,120}$/u.test(idp.audience)) {
      settings.identityProvider = { issuer: idp.issuer, audience: idp.audience, jwksUrl: idp.jwksUrl };
    }
  }
  const originalApiUrl = plainHttpsUrl(config.originalApiUrl);
  if (originalApiUrl) settings.originalApiUrl = config.originalApiUrl;
  if (typeof config.restoreRoute === 'string' && ROUTE.test(config.restoreRoute)) {
    settings.restoreRoute = config.restoreRoute;
  }
  return settings;
}

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;
  if (env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '') || !Number.isInteger(config?.step) || config.step < 1 || config.step > 12
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || typeof config.sampleMarker !== 'string'
      || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 aleph.config.json의 단계를 확인하세요.');
  }
  return {
    schema: 'aleph.defense.deployment.v1',
    step: config.step,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    ...publicSettings(config),
  };
}
