# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 2단계 기록: 자료를 코드 밖으로 옮김

- 가상 메모 네 건은 학습용 Supabase 테이블 `public.notes`로 옮겼습니다. 테이블 구조·권한 SQL은 `supabase/notes.sql`에 있고, 메모 값은 공개 저장소에 다시 남기지 않으려고 파일에 두지 않았습니다. `owner_id uuid` 칸은 3단계 로그인용 자리이고, RLS는 켜져 있으며 `anon`·`authenticated` 권한은 회수했습니다.
- 빌드는 더 이상 `public/data.json`을 만들지 않습니다. 루트 `data.json`의 메모도 비웠습니다. `/aleph.json` 생성은 그대로 유지합니다.
- 화면은 `api/notes.js` 서버 함수(`/api/notes`)를 통해 메모를 읽습니다. 함수는 Vercel 환경변수 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 읽고, 키는 브라우저 파일·응답·로그에 넣지 않습니다. 두 값은 Vercel → Settings → Environment Variables에 직접 넣고 다시 배포합니다.

### 아직 남은 약점

- **서버 함수 주소는 공개돼 있습니다.** 로그인 확인이 없으므로 `/api/notes` 주소를 아는 사람은 누구나 가상 메모를 읽을 수 있습니다. 키를 숨긴 것이지 접근을 막은 것은 아닙니다. 3단계 로그인에서 막아야 합니다.

### 메모 문장이 남아 있는지 확인하는 절차

검색어는 Supabase Table Editor의 `notes` → `content` 칸에서 메모 본문 한 줄을 복사해 씁니다. README 자신이 검색에 걸리지 않도록 검색어는 여기 적지 않습니다.

1. **현재 배포 정적 파일**: 시크릿 창(비로그인)에서 아래를 엽니다.
   - `https://choi-bujang-secret-vault1-ten.vercel.app/data.json` → **404**여야 합니다.
   - 첫 화면에서 마우스 오른쪽 → **페이지 소스 보기** → Ctrl+F로 검색 → **0건**이어야 합니다. 화면에 보이는 카드는 `/api/notes`에서 받아 그린 것이라 소스에는 없습니다.
   - 캐시가 의심되면 주소 끝에 `?1`을 붙여 다시 엽니다.
2. **GitHub 최신 파일**: GitHub 위쪽 검색창에 `repo:reum2kr/choi-bujang-secret-vault_1` 뒤에 한 칸 띄우고 복사한 본문을 붙여 **Code** 결과가 0건인지 봅니다(검색 색인 반영에 몇 분 걸릴 수 있음). 로컬 clone이 있다면 `git grep -n "<복사한 본문>" HEAD` 결과가 비어 있어야 합니다.

### 확인 결과 기록 (2026-10-06)

- 현재 배포: `/data.json` 404 확인, 첫 화면 소스에 메모 문장 없음, `/aleph.json`은 열림.
- GitHub 최신 파일: 이 수정 커밋 이후 `git grep` 결과 0건이 목표입니다. 이번 수정 전에는 `supabase/notes.sql`에 메모 문장이 있었습니다.
- 공개 API: `/api/notes`는 **로그인 없이 메모 네 건을 그대로 돌려줍니다.** 아직 막지 못한 약점입니다.

### 과거 노출은 해소되지 않았습니다

- 옛 공개 커밋(`657b56a`, `0ca0dc9`, `662a2d3` 등)에는 메모 문장이 그대로 남아 있습니다. 저장소가 공개인 한 누구나 History에서 볼 수 있습니다.
- 1단계의 옛 배포(미리보기 주소 포함)도 Vercel에 남아 있는 동안에는 옛 `/data.json`을 내줄 수 있습니다.
- 이미 공개된 동안 누군가 복사해 갔을 수도 있습니다. 최신 파일에서 지운 것은 **앞으로의 노출을 줄인 것**이지 과거 노출을 없앤 것이 아닙니다. 실제 자료였다면 내용 변경·관련자 통지·이력 정리까지 따로 검토해야 합니다.

## 2단계 저장점

- 현재 작동: 첫 화면은 `/api/notes` 서버 함수로 가상 메모 네 건을 보여 줍니다. `/data.json`은 404이고, `/aleph.json`은 빌드할 때 계속 생성됩니다. 모든 경로에 `X-Content-Type-Options: nosniff` 등 보안 헤더가 붙습니다.
- `aleph.config.json`: `step` 2, 실제 저장소·배포 주소를 넣었습니다. 로그인 발급자·허용 경로·원본 API 주소는 아직 해당 단계가 아니어서 비워 둡니다.
- `src/attack-check.mjs`: 2단계에서는 비로그인 `/data.json`(메모가 없어야 함)과 비로그인 `/api/notes`(아직 열려 있는 약점)를 실제로 요청해 결과만 기록합니다. 심판 판정이 아닙니다.
- 다시 실행하는 방법: Vercel 환경변수 `SUPABASE_URL`·`SUPABASE_SECRET_KEY`를 넣고 main에 push하면 자동 배포됩니다. 제출 묶음은 git·Node 22가 있는 곳(로컬 또는 Codespaces)에서 `npm ci` 뒤 `bundle-notes.json`을 만들고 `npm run bundle`로 만듭니다. `bundle-notes.json`과 `artifacts/`는 커밋하지 않습니다.

## 3단계 기록: 진짜 로그인을 붙임

- 첫 화면에 Supabase Auth 이메일·비밀번호 로그인·로그아웃을 붙였습니다(공식 SDK, 공개용 URL·publishable key만 화면 코드에 있음). 로그인 실패 이유를 화면에 보여 줍니다.
- 자료 API는 시작 틀의 `src/verify-login.mjs`로 토큰을 검사합니다(도우미는 고치지 않음). 브라우저가 보낸 userId·role·owner_id는 믿지 않습니다. 토큰이 없거나 검사에 실패하면 메모 없이 `401 {"error":"LOGIN_REQUIRED"}`를 돌려줍니다.
- `aleph.config.json`의 `identityProvider`에 Supabase 발급자·대상·공개키 주소를 적었습니다(비밀 키 없음).
- 메모 API (`api/notes/index.js`, `api/notes/[id].js`, 공통 `lib/notes-server.mjs`)
  - `GET /api/notes`: 로그인 사용자(owner_id)의 메모 배열 `[{id,title,body}]`
  - `POST /api/notes`: `{id?, title, body}` → `201 {id}` (id는 UUID, 없으면 서버가 만듦). owner_id는 서버가 확인한 사용자 ID로 저장
  - `GET·PUT·DELETE /api/notes/:id`: 한 건 `{id,title,body}`, 없으면 404, 지운 뒤 GET도 404
- 테이블 변경 SQL은 `supabase/03-notes-uuid.sql`(id를 UUID로, content를 body로)입니다. 2단계에서 넣은 가상 메모 네 건은 owner_id가 비어 있어 로그인 사용자 목록에는 나오지 않습니다.

### 아직 남은 약점

- **소유자 검사가 없습니다.** 로그인만 하면 다른 사람 메모의 id를 알 때 읽기·수정·삭제가 됩니다(B가 A의 메모를 고칠 수 있음). 4단계에서 막고 기록합니다.
- 옛 커밋·옛 배포에 남은 과거 노출은 2단계 기록과 같이 해소되지 않았습니다.

## 3단계 저장점

- `step` 3. `identityProvider`, `allowedRoutes`(GET·POST `/api/notes`, GET·PUT·DELETE `/api/notes/:id`)를 구현과 맞췄습니다. 원본 API 주소는 5단계 항목이라 비워 둡니다.
- `src/attack-check.mjs`의 3단계 점검: 비로그인 `/data.json`, 비로그인 `/api/notes`, 위조 토큰 `/api/notes`를 실제로 요청해 결과만 기록합니다. A의 추가·수정·삭제와 B의 타인 메모 접근은 비밀번호를 코드에 넣지 않으므로 미실행으로 남깁니다. 심판 판정이 아닙니다.
- 다시 실행하는 방법: Supabase SQL Editor에서 `supabase/notes.sql` → `supabase/03-notes-uuid.sql` 순서로 실행하고, Authentication에서 테스트 계정을 만든 뒤 Vercel 환경변수 `SUPABASE_URL`·`SUPABASE_SECRET_KEY`를 넣고 main에 push합니다. 제출 묶음은 Codespaces 등에서 `git pull` → `npm ci` → `bundle-notes.json` 작성 → `npm run bundle`.

## 4단계 기록: 로그인해도 내 자료만

- 소유자 연결: `supabase/04-owners.sql`로 기존 가상 메모 세 건은 A, 남은 한 건은 B의 시험 메모로 owner_id를 연결했습니다. 이메일은 공개 저장소에 남기지 않도록 `<A_EMAIL>`·`<B_EMAIL>` 자리표시자로 두고 SQL Editor에서만 채웠습니다.
- API 소유자 검사(`api/notes/[id].js`): 토큰으로 확인한 사용자 ID와 DB의 owner_id를 비교합니다. 남의 메모 GET·PUT·DELETE는 없는 메모와 똑같이 404로 거부해 존재 여부도 알려 주지 않습니다. 수정은 기존 행과 새 행의 소유자가 모두 본인이어야 하고, 본문으로 owner_id를 다른 사람으로 바꾸려 하면 403입니다. URL·쿼리·본문의 owner_id는 믿지 않고, 추가는 확인된 ID로 저장합니다.
- DB 권한(`supabase/04-rls.sql`): `REVOKE ALL … FROM PUBLIC, anon, authenticated` 뒤 authenticated에만 SELECT·INSERT·UPDATE·DELETE를 GRANT했습니다. 정책은 SELECT·DELETE USING, INSERT WITH CHECK, UPDATE USING+WITH CHECK 모두 `auth.uid() = owner_id`입니다. 서버 함수가 쓰는 service_role 권한은 그대로입니다.
- 적용 전후 `has_table_privilege` 대조: 전 anon 없음·authenticated 없음 → 후 anon 없음·authenticated SELECT, INSERT, UPDATE, DELETE.

### 아직 남은 약점과 한계

- 앱 API는 RLS를 우회하는 서버 전용 키로 DB를 읽으므로, A/B 구분은 API의 소유자 검사가 지킵니다. RLS는 Data API를 직접 부르는 경우의 두 번째 방어선입니다.
- authenticated 역할로 Data API를 직접 부르는 경우는 심판이 재현할 수 없어 점수에서 제외되며, 이 저장소의 자동 점검도 anon 키 직접 조회만 확인합니다.
- 옛 커밋·옛 배포의 과거 노출은 2단계 기록과 같이 해소되지 않았습니다.

## 4단계 저장점

- `step` 4. `identityProvider`, `allowedRoutes`(GET·POST `/api/notes`, GET·PUT·DELETE `/api/notes/:id`)는 구현과 같습니다.
- `src/attack-check.mjs`의 4단계 점검: 비로그인·위조 토큰 `/api/notes`, anon(publishable) 키로 Supabase Data API `notes` 직접 조회를 실제로 요청해 결과만 기록합니다. B의 타인 메모 접근과 소유자 변경은 계정 비밀번호를 코드에 넣지 않으므로 미실행이며, 화면에서 직접 확인합니다. 심판 판정이 아닙니다.
- 다시 실행하는 방법: SQL Editor에서 `notes.sql` → `03-notes-uuid.sql` → `04-owners.sql`(이메일 채워서) → `04-rls.sql` 순서로 실행하고, main에 push합니다. 제출 묶음은 Codespaces에서 `git pull` → `npm ci` → `bundle-notes.json` 작성 → `npm run bundle`.

## 5단계 기록: 자료 요청을 서버 한곳으로

- 제작 1 점검: 브라우저 코드(`public/index.html`)에서 메모 자료를 Supabase에 직접 읽거나 고치는 호출은 없었습니다(로그인 Auth 호출만 있었음). 파일 변경 없음.
- 제작 2 DB 권한(`supabase/05-revoke-direct.sql`): `notes` 테이블에서 PUBLIC·anon·authenticated의 직접 권한을 모두 거뒀습니다. 서버 함수용 service_role 권한과 RLS(켜짐)는 유지합니다. 적용 전후 `has_table_privilege`: 전 anon 없음·authenticated SELECT, INSERT, UPDATE, DELETE → 후 anon 없음·authenticated 없음.
- `aleph.config.json`의 `originalApiUrl`: 쿼리 없는 원본 자료 경로 `https://yojoqbnplvwsmqaohjfr.supabase.co/rest/v1/notes`. 공개 키로 직접 불러도 권한이 없어 메모가 나오지 않습니다.
- 추가: 로그인·로그인 유지·로그아웃도 서버 함수로 옮겼습니다(`api/auth/login.js`, `refresh.js`, `logout.js`, 공통 `lib/auth-server.mjs`). 화면 코드에는 자료 저장소 주소·공개 키·SDK가 없고, 브라우저는 같은 사이트의 `/api/...`만 부릅니다. access token은 화면 메모리에만 두고, refresh token은 `HttpOnly; Secure; SameSite=Strict` 쿠키(`Path=/api/auth`)로만 다룹니다. 로그인 관련 POST는 `X-Vault-Request: 1` 헤더가 있어야 받습니다.
- 서버 함수의 로그인 검사(`verify-login`)·소유자 검사와 서버 전용 설정(`SUPABASE_URL`, `SUPABASE_SECRET_KEY`)은 그대로입니다.

### 아직 남은 약점과 한계

- 모든 자료 접근이 서버 전용 키를 쓰는 서버 함수 한곳에 모였으므로, 그 키가 새면 피해가 큽니다. 키는 Vercel 환경변수에만 두고, 노출되면 즉시 새 키로 바꾼 뒤 옛 키를 지웁니다(3단계에서 한 번 교체함).
- 로그인 시도 횟수 제한은 Supabase Auth의 기본 제한에 의존합니다.
- 옛 커밋·옛 배포의 과거 노출은 해소되지 않았습니다.

## 5단계 저장점

- `step` 5. `identityProvider`, `allowedRoutes`(자료 API 5개), `originalApiUrl`을 구현과 맞췄습니다.
- `src/attack-check.mjs`의 5단계 점검: 비로그인·위조 토큰 `/api/notes`, anon 키로 `originalApiUrl` 직접 조회, 첫 화면 코드의 저장소 주소·키 문자열 검사를 실제 요청으로 기록합니다. B의 타인 메모 접근은 미실행(화면에서 직접 확인)입니다. 심판 판정이 아닙니다.
- 다시 실행하는 방법: SQL Editor에서 `notes.sql` → `03-notes-uuid.sql` → `04-owners.sql`(이메일 채워서) → `04-rls.sql` → `05-revoke-direct.sql` 순서로 실행하고 main에 push합니다. 제출 묶음은 Codespaces에서 `git pull` → `npm ci` → `bundle-notes.json` 작성 → `npm run bundle`.

## 보너스 xdr-01: 무차별 로그인 공격을 잡아 냄

- 판정기 위치: ZTNA 판정기는 `src/decider.mjs`이고 규칙 이름은 같은 파일의 `RULE_IDS`(현재 `starter.deny`)에 있습니다. 이번 보너스는 판정기 규칙을 대신하지 않고, 확인 단계 하나를 더하는 부품만 만듭니다.
- `xdr/brute-force/read-alerts.mjs`(제작 1): `xdr/fixtures/brute-force.json`에서 시각·출발 주소·계정·규칙 수준·설명만 뽑아 봅니다. 비밀값처럼 보이는 문자열은 `[가림]`으로 바꿉니다. 원본 경보는 고치지 않고, `decide.mjs`는 이 파일을 불러오지 않습니다. 경보 28건 = 뽑은 줄 28줄.
- `xdr/brute-force/patterns.json`(제작 2): MITRE ATT&CK T1110 근거 패턴 세 개(`rapid_failures_same_source` T1110.001, `password_spraying_many_accounts` T1110.003, `low_volume_failures` T1110).
- `xdr/brute-force/decide.mjs`(제작 3): 패턴을 맨 위 상수로 옮겨 적고 `decide(alert)` 하나를 내보냅니다. import·파일 입출력·네트워크가 없습니다. 확신도 0.85 이상 block, 0.5 이상 alert, 그 아래 record.
- `xdr/brute-force/respond.mjs`(제작 4): block 후보만 `xdr/brute-force/deny-rules.json`의 거부 규칙(주소 하나당 하나, 1시간 만료, 근거 경보 번호 포함)으로 넣고, block·alert를 `xdr/alerts.log`에 한 줄씩 쌓습니다. 같은 묶음에 정상 이벤트가 있는 주소와 내부 대역은 막지 않습니다. `isDenied(rules, srcip, at)`가 판정기에 꽂을 확인 단계입니다.
- 결과(제작 5): `npm run xdr:run -- brute-force` → block 10 · alert 9 · record 9, 정상 이벤트를 block한 경우 0건. `node xdr/brute-force/respond.mjs` 다시 흘리기 → 거부 규칙 9개(주소 9곳), 정상·애매 주소를 막은 경우 0건.

### 한계

- 현재 판정기 요청 계약(`docs/DECIDER_REQUEST.md`)에는 출발 주소 항목이 없어서, 거부 규칙을 실제 접속 판정에 바로 적용할 수는 없습니다. 운영 엔진이 주소를 계약에 넣어 줄 때 `isDenied`를 판정기 앞 단계로 연결합니다.
- 판단은 경보에 적힌 건수·계정 수·설명에 기대므로, 경보 형식이 크게 바뀌면 패턴 조건을 다시 맞춰야 합니다.
