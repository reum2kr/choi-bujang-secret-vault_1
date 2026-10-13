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

## 보너스 xdr-02: 웹 주입 공격을 잡아 냄

- 판정기 위치는 xdr-01과 같습니다(`src/decider.mjs`의 `RULE_IDS`, 현재 `starter.deny`). 판정기 규칙은 고치지 않고 확인 단계 부품만 더합니다.
- `xdr/web-injection/read-alerts.mjs`(제작 1): 시각·출발 주소·계정·규칙 수준·설명만 뽑고 비밀값처럼 보이는 문자열은 `[가림]`. 경보 26건 = 뽑은 줄 26줄. `decide.mjs`는 이 파일을 불러오지 않습니다.
- `xdr/web-injection/patterns.json`(제작 2): MITRE ATT&CK T1190 근거 패턴 다섯 개(`sql_injection_in_params`, `script_injection_in_params`, `path_traversal_repeat`, `command_injection_in_params`, `repeated_injection_same_source`).
- `xdr/web-injection/decide.mjs`(제작 3): 패턴 상수 + `decide(alert)`. import·파일 입출력·네트워크 없음. 요청 인자를 두 번까지 URL 디코딩해 실제 주입 모양과 수업용 문서 표기(`doc-…`)를 함께 보고, 같은 주소에서 5번 이상 반복되면 block, 한 번뿐이면 alert, T1190 표시도 주입 표기도 없으면 record.
- `xdr/web-injection/respond.mjs`(제작 4): block 후보만 `xdr/web-injection/deny-rules.json` 거부 규칙(주소당 하나, 1시간 만료, 근거 경보 번호)으로 넣고 block·alert를 `xdr/alerts.log`에 쌓습니다. 로그에는 주입 문자열이 남지 않도록 요청 경로만 적고 쿼리는 버립니다. 같은 묶음에 정상 이벤트가 있는 주소와 내부 대역은 막지 않습니다.
- 결과(제작 5): `npm run xdr:run -- web-injection` → block 8 · alert 9 · record 9, 정상 이벤트를 block한 경우 0건. 다시 흘리기 → 거부 규칙 7개(주소 7곳), 정상·애매 주소를 막은 경우 0건.
- 한계: xdr-01과 같이 판정기 요청에 출발 주소가 없어 거부 규칙은 별도 파일과 `isDenied` 확인 단계로 둡니다. 한 번뿐인 주입 시도는 일부러 막지 않고 알림만 남기므로, 반복이 적은 정밀 공격은 사람이 알림을 보고 판단해야 합니다.

## 6단계 기록: 등록한 기기만 자료실에 들어옴

- 판정 요청의 `subjectId`는 확인된 가명 사용자 ID, `deviceId`는 확인된 기기 ID, `deviceRegistered`는 등록 여부, `method`는 HTTP 동작, `route`는 허용 경로 모양입니다. 인증서·CA·서명 키는 만들지 않았고 Git에도 없습니다.
- `deviceRegistered`가 정확히 `true`가 아니면 `deny · device_not_registered`입니다. 등록 기기이고 `subjectId`가 있으며 GET 자료실 읽기 경로(`GET /notes`, `GET /notes/:id`, `/api` 접두사 허용)면 `allow · approved`; 그 밖은 기존 `starter.deny`가 거부합니다. 기존 자료실 주소와 브라우저 화면은 바꾸지 않았습니다.
- 확인 순서: 저장소 루트에서 `npm run decider:test`를 실행해 `통과 · 등록 기기의 정상 요청`과 `통과 · 미등록 기기의 가상 요청`을 확인합니다. 가상 요청 연습이며 심판 통과 증거가 아닙니다. 설치할 접속 프로그램은 없고, 미등록 기기 공격은 심판이 확인합니다.

## 6단계 저장점

- `step` 6입니다. `identityProvider`·`allowedRoutes`·`originalApiUrl`은 5단계 그대로입니다.
- `RULE_IDS`는 구현된 `starter.deny`와 `device_registered` 두 개입니다. `attack-check`의 6단계 점검은 5단계 점검에 판정기의 등록·미등록 가상 요청 응답 두 건을 더한 것이며, 심판 판정이 아닙니다.
- 다시 실행하는 방법: `npm ci` → `npm run decider:test` → `bundle-notes.json` 작성 → `npm run bundle`.

## 7단계 기록: 평소와 다른 접속은 다시 확인함

- 제작 1 (입력 검사, `readContext`): 판정기는 엔진이 넘긴 `signals.source`가 `judge_fixture`(심판의 가상 사건)일 때만 지역·네트워크·시각과 `recentEvents`를 사건 근거로 씁니다. `none`이나 모르는 출처(예: 클라이언트 헤더)는 신뢰하지 않고, 빠지거나 형식이 틀린 지역·시각·네트워크·행동은 정상값으로 채우지 않고 "모름"으로 둡니다. 요청에 덧붙인 `geo`·`headers` 같은 계약 밖 값은 읽지 않습니다. `judge_fixture` 신호도 실제 위치 증거로 쓰지 않습니다.
- 제작 2 (`step_up_required`): 새벽(0~5시) + 처음 보는 네트워크(`unusual`) + 최근 5분 안에 10건 이상인 사건이 **모두 겹칠 때만** `step_up` · `step_up_required`로 다시 로그인을 요구합니다. 지역 하나만으로는 판단하지 않고, 영구 차단(`deny`)이 아니며 사유는 `reasonCode`와 `ruleIds`에 남습니다. 기존 `device_registered` 규칙(미등록 기기 거부)은 그대로 먼저 적용됩니다.
- 제작 3 (재로그인 계약): `docs/DECIDER_REQUEST.md`에는 엔진이 검증한 재로그인 정보 `stepUp {verified, authAgeSeconds}`가 있습니다. 판정기는 복합 사건이면 `step_up`으로 자료를 주지 않고, 엔진이 확인한 새 로그인(`verified: true`, 5분 이내) 뒤 들어온 새 요청만 다시 판정해 `allow`합니다. `verified`만 있고 나이가 없거나 5분이 지난 경우는 계속 `step_up`입니다. 토큰 원문은 판정기·로그·제출 묶음에 남기지 않습니다. 실제 엔진의 재로그인 흐름으로 차단·허용을 실측하는 것은 이 저장소에서 보낼 수 없어 미실행입니다.
- 확인 순서: `npm run decider:test` → `통과 · 등록 기기의 정상 요청`, `통과 · 미등록 기기의 가상 요청`, `통과 · 복합 이상 접속`, `통과 · 다시 확인한 복합 이상 접속` 네 줄. `npm run fixture:7` → `정상 사건: allow`, `복합 이상 사건: step_up`. 모두 가상 요청 연습이며 심판 통과 증거가 아닙니다.

## 7단계 저장점

- `step` 7. `identityProvider`·`allowedRoutes`·`originalApiUrl`은 그대로입니다. `RULE_IDS`는 실제 구현한 `starter.deny`, `device_registered`, `step_up_required` 세 개입니다.
- `src/attack-check.mjs`의 7단계 점검: 5·6단계 점검에 더해 판정기에 정상·복합 이상·재로그인 뒤·위조 출처 가상 사건을 넣어 본 응답과, 실제 재로그인 흐름 미실행을 기록합니다. 심판 판정이 아닙니다.
- 다시 실행하는 방법: `npm ci` → `npm run decider:test` → `npm run fixture:7` → `bundle-notes.json` 작성 → `npm run bundle`.

## 8단계 기록: 자료마다 갈 수 있는 구역을 나눔

- 제작 1 (자원 ID, `lib/zones.mjs`): 메모 구역은 목록 `notes`·한 건 `note:<id>`, 강사 공지 구역은 목록 `notices`·한 건 `notice:<id>`로 구별합니다. 자료 API는 응답 머리글 `X-Resource-Id`에 이 값을 붙이고, 본문 모양 `{id,title,body}`와 기존 메모 주소(`/api/notes`, `/api/notes/:id`)는 그대로입니다. 공지는 새 표 `notices`와 새 주소 `/api/notices`, `/api/notices/:id`에 있습니다(`supabase/08-notices.sql`). 화면 메뉴는 바꾸지 않았습니다.
- 제작 2 (판정기 구역 규칙, `src/decider.mjs`): 엔진이 확인한 사용자(`subjectId`)·기기(`deviceRegistered`)·메서드·정확한 경로(`route`와 `path`가 서로 맞아야 함)만 봅니다.
  - `zone_notes_self`: `GET /notes/:id`, `PUT /notes/:id` 허용(자기 메모 한 건 구역). 메모 한 건의 주인 비교는 자료 API가 검증된 사용자와 저장된 owner_id로 합니다.
  - `zone_notes_no_bulk`: 메모 전체 목록(`GET /notes`)처럼 여러 사람의 자료를 한꺼번에 여는 경로는 `deny · route_not_allowed`.
  - `zone_notices_instructor`: 강사 공지 구역(`GET /notices`, `GET /notices/:id`, `PUT /notices/:id`)은 강사만의 구역이라 `deny · instructor_required`. 판정 요청 계약에 엔진이 확인한 강사 역할이 없어(`request.role` 없음) 판정기는 모든 요청자를 일반 학생으로 보고 거부합니다.
  - `zone_route_allowlist`: 경로표에 없는 경로, route·path·메서드가 어긋난 요청, 쿼리가 붙은 요청, `:id` 자리에 `export`·`admin` 같은 기능 이름이나 더 깊은 경로가 오면 `deny · route_not_allowed`. `/api` 접두사는 있어도 됩니다.
  - 이전 규칙(`device_registered`, `step_up_required`, 로그인 주체 없음 → `starter.deny`)은 그대로이며 구역 규칙보다 먼저 또는 함께 적용됩니다.
- 제작 3 (자료 API 재대조): 메모 API는 검증된 사용자와 저장된 `owner_id`를 다시 대조해 남의 메모는 404, 공지 API(목록·한 건 읽기·수정)는 DB `instructors` 표에 저장된 사용자만 허용하고 일반 학생은 `403 INSTRUCTOR_REQUIRED`입니다. 화면 메뉴나 요청 본문의 `role`·`isInstructor`는 믿지 않습니다. 거부하면 `zone_deny zone=… method=… reason=…` 한 줄만 서버 로그에 남기고, 사용자 ID·토큰·본문은 남기지 않습니다.
- 가짜 DB 로컬 시험: A 자기 메모 읽기·수정 200, B의 A 메모 읽기·수정·삭제 404, 학생의 공지 목록·읽기·수정 403(본문에 `role: instructor`를 넣어도 403), 강사 계정의 공지 읽기·수정 200, 공지 ID로 메모 API를 불러도 404.

### 8단계 보강 (심판 S08_OTHER_ZONE_ALLOWED 뒤)

심판에서 「다른 구역 메모를 API로 조회」가 통해, 조회 경로에서 새어 나갈 수 있는 길 세 가지를 모두 막았습니다(정상 요청 동작은 같음).
- 한 건 주소(`/api/notes/:id`, `/api/notices/:id`)의 자료 ID는 쿼리가 아니라 실제 경로의 마지막 칸에서만 읽고, 쿼리가 붙으면 `400 QUERY_NOT_ALLOWED`로 거부합니다(`/api/notes/<A 메모>?id=<다른 값>` 바꿔치기 차단).
- 자료의 주인 열쇠(`ownerKey`): 학생 로그인은 Supabase 사용자 번호 그대로, 심판 시험 계정은 검증된 `sub`에 시험 신원(a/b)까지 묶어 A와 B가 같은 주인으로 보이지 않게 했습니다.
- 판정기는 엔진이 확인한 `service`도 봅니다. 메모 경로는 `notes` 서비스만, 공지 경로는 `notes`·`notices`만 받고 다른 구역 서비스면 `route_not_allowed`로 거부합니다.
- 두 번째 재제출에서도 같은 코드가 나와, 카드에 없던 "학생의 공지 읽기 허용"을 뺐습니다. 카드의 구역 규칙은 자기 메모 읽기·수정과 강사 공지 수정뿐이므로, 강사 공지 구역은 읽기도 강사만 들어갈 수 있게 판정기(`instructor_required`)와 API(403) 모두 막았습니다. `RULE_IDS`에서 `zone_notices_read`를 지웠습니다.
- 네 번째 재제출 뒤 원인을 찾았습니다. 빌드가 만든 `/aleph.json`의 `publicAppUrl`이 배포마다 바뀌는 긴 주소(`VERCEL_URL`)였고, 이 주소는 Vercel 배포 보호 때문에 `/api/notes`를 열면 Vercel 로그인 화면으로 넘어갑니다(302). 그래서 심판의 로그인한 공격 요청은 앱에 닿지 못했고(로그에는 로그인 없는 요청만 남음), 조회 요청은 로그인 화면을 따라가 200을 받았습니다. `scripts/deployment-identity.mjs`가 운영(`VERCEL_ENV=production`) 배포에서는 `aleph.config.json`의 짧은 주소(`https://choi-bujang-secret-vault1-ten.vercel.app/`)를 공개하도록 고쳤습니다. 미리보기 배포는 지금처럼 긴 주소를 씁니다.
- 로그의 User Agent(`ALEPH-Defense-Judge/1 (read-only)`)로 심판의 API 요청이 읽기 전용·비로그인뿐임을 확인했습니다. 구역 판정은 판정기에서 납니다.
- 최종 원인(심판 안내): 판정기가 메모 전체 목록(`GET /notes`)처럼 여러 사람의 자료를 한꺼번에 여는 경로를 허용하고 있었습니다. `zone_notes_no_bulk`로 목록 경로를 거부하고, 자기 메모는 한 건(`GET`·`PUT /notes/:id`)만 허용합니다. 반 공지·강사 자료 쓰기(POST·PUT·PATCH·DELETE)는 모두 거부합니다. 메모 한 건의 주인 비교는 자료 API가 하므로, 추측으로 넣었던 판정기의 주인 기억·경로 속 주체 ID 비교 규칙은 뺐습니다.
- Vercel은 `[id].js` 함수에 경로의 ID를 `?id=…`로 붙여 넘기므로, 그 값이 경로 ID와 같으면 정상으로 보고 그 밖의 쿼리만 `400 QUERY_NOT_ALLOWED`로 거부하도록 고쳤습니다.

### 아직 남은 한계

- 강사 역할이 판정 요청 계약에 없어서, 판정기를 거치는 경로에서는 강사도 공지를 고칠 수 없습니다. 운영 엔진이 강사 역할을 계약으로 제공하면 `zone_notices_instructor`를 그 값으로 허용하도록 바꿉니다.
- 판정기를 거치는 경로에서는 메모 전체 목록을 볼 수 없습니다. 브라우저 화면은 판정기를 거치지 않는 기존 서버 함수(본인 메모만 돌려줌)를 쓰므로 화면의 목록은 그대로입니다.
- 메모 삭제(`DELETE /notes/:id`)와 추가(`POST /notes`)는 이번 구역 규칙에 넣지 않아 판정기에서는 거부됩니다. 브라우저 화면은 판정기를 거치지 않는 기존 서버 함수를 쓰므로 화면 동작은 그대로입니다.

## 8단계 저장점

- `step` 8. `allowedRoutes`에 `GET /api/notices`, `GET /api/notices/:id`, `PUT /api/notices/:id`를 더했습니다. `RULE_IDS`는 실제 구현한 `starter.deny`, `device_registered`, `step_up_required`, `zone_route_allowlist`, `zone_notes_self`, `zone_notes_no_bulk`, `zone_notices_instructor`입니다.
- `src/attack-check.mjs`의 8단계 점검: 7단계 점검에 판정기 구역 규칙 가상 요청 네 건과 실제 배포의 비로그인 `/api/notices` 요청을 더하고, 토큰이 필요한 직접 API 교차 요청은 미실행으로 남깁니다. 심판 판정이 아닙니다.
- 다시 실행하는 방법: SQL Editor에서 `supabase/08-notices.sql` 실행(강사 지정은 선택) → `npm ci` → `npm run decider:test` → `bundle-notes.json` 작성 → `npm run bundle`.

## 9단계 기록: 도플갱어를 찾고 권한을 거둡니다

- 제작 1 (사건 입력 정리, `src/detect.mjs`의 `readEvent`): 가상 조회 사건에서 가명 사용자(`identity.sub`, 없으면 계약 이름 `subjectId`), 기기(`deviceId`), 요청 종류(`method`, `route`), 판정(`decision`), 엔진이 출처를 밝힌 네트워크(`signals.network`), 시각(`at`)만 골라 새 객체로 만듭니다. 메모 본문, 토큰, 이메일·실명은 복사하지 않습니다. `@`나 공백이 들어간 값은 가명으로 받지 않으며, 형식이 틀린 사건은 버리고 대신 채우지 않습니다.
- 제작 2 (복합 의심 규칙 `detect_burst_read`): 같은 가명 사용자와 같은 기기의 GET 조회가 어느 10분 구간에서든 120건을 넘고, 그 조회가 평소와 다른 네트워크(`unusual`)에서 왔을 때만 의심으로 봅니다.
  - 평소 네트워크의 많은 조회(정상 기기), 처음 보는 네트워크의 적은 조회, 지역만 다른 조회는 의심이 아닙니다. 지역은 읽지 않습니다.
  - 정확히 120건은 제외합니다. 다른 사용자나 다른 기기의 조회는 합치지 않고, 10분 밖의 조회는 같은 묶음으로 세지 않습니다.
  - 출처가 클라이언트 헤더처럼 믿을 수 없는 네트워크 값은 "모름"으로 둡니다. 네트워크 정보가 없는 연습 사건(`docs/DETECT_EVENTS.md` 형식)에는 다량 조회 기준만 적용합니다.
- 제작 3 (별도 탐지 결과): 의심이면 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId }`를 돌려줍니다. `deviceId`는 엔진이 기기를 알려 준 경우에만 들어갑니다. 대상은 처음 기준을 넘은 사용자·기기 한 묶음뿐이고, 같은 사용자의 정상 기기는 제안에 넣지 않습니다. 의심이 아니면 `{ action: 'observe' }`입니다.
  - 접속 허용/거부 응답(`src/decider.mjs`의 다섯 항목)은 바꾸지 않았습니다.
  - 회수 API를 만들거나 기기 권한을 바꾸지 않습니다. 실제 회수와 걸린 시간은 심판이 확인합니다.
- 로컬 확인: `npm run detect:test` 6건 통과. 이것은 가상 사건 연습이며, 실제 반 엔진의 사건 전달이나 접속 회수가 연결됐다는 뜻이 아닙니다.

## 9단계 저장점

- `step` 9. `identityProvider`, `allowedRoutes`, `originalApiUrl`은 8단계 그대로입니다. 판정기 `RULE_IDS`도 8단계 그대로입니다(판정기는 바꾸지 않았음). 탐지 규칙 이름은 `src/detect.mjs`의 `DETECT_RULE_IDS`(`detect_burst_read`)에 따로 둡니다.
- `src/attack-check.mjs`의 9단계 점검: 8단계 점검에 탐지 함수 가상 사건 결과 두 줄(정상 쪽 세 경우를 한 줄로, 도플갱어 기기의 다량 조회 한 줄)과 실제 회수 집행 미실행 한 줄을 더합니다. 제출 점검은 20개까지라, 7단계 가상 사건 네 건은 결과를 그대로 둔 채 한 줄로 합쳤습니다(합계 20개). 심판 판정이 아닙니다.
- 다시 실행하는 방법: `npm ci` → `npm run detect:test` → `npm run decider:test` → `bundle-notes.json` 작성 → `npm run bundle`.

## 10단계 기록: 백업에서 자료실을 되살립니다

### 판정 조건별 근거 (2026-10-13 실제 실행 결과)

아래 결과는 모두 실제로 실행해서 얻은 값입니다. 하지 않은 시험은 미실행으로 적었습니다. 실행 순서(2026-10-13, KST):
1. 21:21 시험 정책 복원: Supabase SQL Editor에서 `supabase/10-policy-backup.sql` → `supabase/10-policy-restore-test.sql`
2. 21:30 메모 한 건 복원: 커밋 `02b2867` 배포를 대상으로 `npm run bundle` 실행(복원 점검이 먼저 실행됨)
3. 21:30 복원 뒤 재시험: 같은 `npm run bundle`에서 한 건 복원이 끝난 **뒤에** 1~9단계 정상·금지 요청을 다시 보냄

1. **백업 검증 (사본을 다시 읽어 검증, 실패하면 멈춤, 실행 전 버전·바뀔 항목 표시, 운영 정책 그대로)**
   - 실제 운영 정책(운영 표 `notes`의 RLS)은 읽기만 합니다. 사본 `s4-rls-v1`은 운영 정책이 4단계 안전 기준과 같을 때 읽어 둔 것이고, 차이 보기·복원은 시험 정책(시험 표 `notes_drill`의 RLS)만 대상으로 합니다.
   - 복원은 실행할 때마다 사본을 다시 읽어 SHA-256을 다시 계산·대조합니다. 사본이 없거나 대조가 다르면 `stopped`로 멈추고 아무 정책도 바꾸지 않습니다.
   - 실행 전(`notes_policy_restore(…, false)`)에는 복원할 버전과 바뀔 항목만 보여 주고 바꾸지 않습니다.
   - 실행 뒤 시험 정책을 다시 읽어 사본과 같은지, 운영 정책 지문이 실행 전과 같은지 확인합니다. 하나라도 다르면 전체 취소합니다.
   - Supabase 실행 결과(21:21): 실행 전 차이 보기 `backupVerified: true`, 대상 `notes_drill`, 바뀔 항목 4개 → 미리보기 `previewed (changeCount 2)` → `restored (changeCount 2, operatingPolicyUnchanged: true)` → `policy_restore_test · pass` → 차이 `changeCount 0`.
   - 로컬 PostgreSQL 16(Supabase 역할·`auth.uid()` 흉내) 실행 결과: 복원 시험 `pass`(침공 상태 B→A 시험 메모 1건, 복원 뒤 0건, A 자기 시험 메모 1건), 미리보기 바뀔 항목 2개, 없는 사본·변조 사본 `stopped`(정책 그대로), 운영 표 `notes` 정책 지문 실행 전후 같음, 브라우저 역할 함수 실행 거부.
   - 판정기 보조 사본: `zone-v10r2`를 다시 읽어 지문·Git(`e46270d`)·안전 요청 18건으로 검증 통과. 변조 사본 → 중단, 없는 사본 → 중단. 시험 정책·감사 기록·운영 정책(`src/decider.mjs`) 그대로.
   - 판정기 응답: 검증 정책 버전(1)의 복구 `allow`, 바뀐 버전(2)의 복구 `deny(policy_unverified)`.
2. **한 건 복원 일치 (ID·소유자·내용 해시가 사본과 같을 때만 그 한 건, 다른 메모 그대로)**
   - 대상: 시험 계정 B의 메모 한 건. 사본 기록 `backup/notes-manifest.json`(라벨 `pre-incident-10`)의 항목 `80976c71-b57f-48f4-b3fe-85cfabaae21a`와 대조했습니다.

     | 값 | 사본 기록 | 복원 뒤 다시 읽은 값 |
     |---|---|---|
     | ID | `80976c71-b57f-48f4-b3fe-85cfabaae21a` | `80976c71-b57f-48f4-b3fe-85cfabaae21a` (같음) |
     | 소유자 지문 `sha256(owner_id)` | `1b0784406de5fedebbe8951cdc56914a024bc79f32c8bea05157d03a60965c63` | 같음 |
     | 내용 해시 `sha256(title + 줄바꿈 + body)` | `e39ce5818d1bce2bff55abbe161f7e14578836d68513e0f3ba0732679345872f` | 같음 |

   - 「같음」의 근거: 복원 경로(`verifyRestored`, `lib/backup-verify.mjs`)가 복원 뒤 그 행을 다시 읽어 세 값을 64자 전체로 사본 기록과 비교하고, 셋 다 같을 때만 `200 restored`를 돌려줍니다. 하나라도 다르면 쓰기 전으로 되돌리고 500으로 멈춥니다. 21:30 실행에서 삭제 뒤 복원과 변조 뒤 복원 모두 `200 restored`였고, 점검 출력에 표시된 앞 12자(`1b0784406de5`, `e39ce5818d1b`)도 사본과 같았습니다.
   - 삭제 뒤 복원: B 메모 삭제 200 → 미리보기(버전 `pre-incident-10`, 바뀔 항목 `note`) → 확인 없는 요청은 미리보기만(쓰기 없음) → 확인 뒤 복원 200 `restored` → 다시 읽어 위 세 값이 같음. 기록에 없는 ID는 404로 멈춤.
   - 변조 뒤 복원: 같은 메모의 제목·본문 변조 200 → 미리보기(바뀔 항목 `title,body`) → 확인 뒤 복원 200 `restored` → 다시 읽어 위 세 값이 같음. B의 다른 메모 1건은 그대로.
   - B가 A 메모를 복원하려 하면 404로 멈추고, A 메모는 그대로입니다.
3. **복원 뒤 재시험 (1~9단계 정상·금지 요청)**: 21:21 정책 복원과 21:30 한 건 복원이 끝난 뒤, 21:30 같은 묶음 실행에서 보낸 실제 요청과 판정기·탐지기 가상 요청의 결과입니다(제출 묶음 점검 `post_restore_retest` 등).
   - 정상: B 목록 200, B 복원 메모 200, A 목록 200, A 메모 200(내용 그대로).
   - 금지:
     - [1·2] `/data.json` 404(메모 0건)
     - [3] 비로그인 401, 위조 토큰 401
     - [3·5] 브라우저 키로 원본 직접 조회 401(행 없음), 첫 화면에 저장소 주소·키 없음
     - [4] B→A 메모 읽기·수정·삭제·복원 모두 404
     - [5] 쿼리 400, 본문 `owner_id` 400
     - [6] 미등록 기기 `deny`
     - [7] 새벽+처음 보는 네트워크+대량 읽기 `step_up`, 재로그인 뒤 `allow`
     - [8] 메모 전체 목록 `deny`, 학생의 공지 목록·수정 403, 비로그인 공지 401, 판정기의 공지·export·경로표 밖 `deny`
     - [9] 정상 기기 `observe`, 도플갱어 기기만 회수 제안
   - 미실행:
     - 엔진의 실제 재로그인 흐름 실측
     - 엔진의 실제 회수 집행
     - 둘 다 이 저장소에서 보낼 수 없어서 미실행입니다.

### 제작 1: 안전 정책 사본과 차이 보기 (`supabase/10-policy-backup.sql`)

- 정책 세 가지를 나눕니다.
  - **실제 운영 정책**: 운영 표 `public.notes`의 RLS(4단계 정책 4개 `notes_select_own`·`notes_insert_own`·`notes_update_own`·`notes_delete_own`, 모두 `authenticated` 역할에 `auth.uid() = owner_id`). 10단계 SQL은 이 정책을 **읽기만** 하고 바꾸지 않습니다.
  - **안전 정책 사본**: 침해 전에 운영 정책이 위 기준과 같은지 검증한 뒤 읽어 둔 사본(`notes_policy_backup`, 버전 `s4-rls-v1`, SHA-256 함께).
  - **시험 정책**: 운영 표와 따로 둔 시험 표 `public.notes_drill`의 RLS. 가상 시험 메모만 넣고 브라우저 역할 권한은 없습니다. 3차 침공 훈련은 이 시험 정책을 바꾸고 되돌립니다.
- 사본 표 `notes_policy_backup`에는 버전, 정책 JSON, SHA-256을 두고, 감사 표 `notes_policy_audit`에는 덧붙이기만 합니다. 두 표 모두 트리거로 고치기·지우기를 막고, 브라우저 역할(`anon`·`authenticated`) 권한은 없습니다.
- 함수(모두 브라우저 역할 실행 불가):
  - `notes_policy_capture('s4-rls-v1')`: 운영 정책이 4단계 안전 기준(RLS 켜짐, 정책 4개, 모두 `auth.uid()`·`owner_id` 비교)과 같을 때만 읽어서 침해 전 사본을 남깁니다. 다르면 멈춥니다. 운영 정책은 바꾸지 않습니다.
  - `notes_policy_backup_verify(버전)`: 사본을 다시 읽어 SHA-256을 다시 계산·대조합니다. 없거나 다르면 예외로 멈춥니다.
  - `notes_policy_diff(버전)`: 검증된 사본과 시험 정책(`notes_drill`)의 차이만 보여 줍니다(읽기 전용). 결과에 버전, 사본 출처(`notes`), 대상(`notes_drill`), 바뀔 항목 수와 항목별 지금 값·사본 값이 나옵니다. 사본이 없거나 검증이 실패하면 예외로 멈춥니다.

### 보조: 판정기 코드 사본 (`npm run policy:diff`)

- 판정기 코드도 같은 방식으로 사본(`policy/safe/decider.zone-v10r2.mjs`, 커밋 `e46270d`의 운영 판정기와 같음)을 두고, 시험 정책 `policy/test/decider.mjs`만 비교·복원합니다.
- 사본 검증은 SHA-256, Git 기록, 정상·금지 가상 요청 18건으로 합니다. Git 기록을 읽을 수 없으면 중단합니다.
- 실제 운영 판정기 `src/decider.mjs`는 이 도구의 대상이 아닙니다(지문만 읽음).

### 제작 2: 안전 정책으로 되돌리기 (`notes_policy_restore`)

- `select public.notes_policy_restore('s4-rls-v1', false);`: 복원할 버전과 바뀔 항목만 보여 주고 아무것도 바꾸지 않습니다(감사 기록에 `previewed`).
- `select public.notes_policy_restore('s4-rls-v1', true);`:
  1. 사본을 다시 읽어 검증합니다. 사본이 없거나 검증이 실패하면 아무것도 바꾸지 않고 감사 기록(`stopped`)만 남기고 멈춥니다.
  2. 운영 정책 지문을 먼저 읽어 둡니다.
  3. 시험 표 `notes_drill`의 정책만 사본대로 되돌립니다. 운영 표 `notes`, 다른 서비스 표(`notices`·`instructors`·`notes_backup` 등)의 정책, 사본·감사 기록은 건드리지 않습니다.
  4. 시험 정책을 다시 읽어 사본과 같은지 대조하고, 운영 정책 지문이 그대로인지 확인합니다. 하나라도 다르면 예외로 이 복원 전체를 취소합니다.
  5. 감사 표에 `restored`와 `operatingPolicyUnchanged: true`를 덧붙입니다.
- 복원 시험(`supabase/10-policy-restore-test.sql`, 한 묶음으로 실행되고 실패하면 전부 취소):
  1. 준비: 운영 표에서 A·B 소유자 ID만 읽어, 시험 표에 A·B의 가상 시험 메모를 넣고 시험 정책을 사본대로 맞춤
  2. 3차 침공 흉내(시험 정책만): 누구나 모든 메모 읽기 정책 추가, 본인 수정 정책 삭제
  3. 복원 전 확인: B로 A 시험 메모가 보임(침공 상태)
  4. 미리보기 → 실행
  5. 복원 뒤 확인: B로는 A 시험 메모 0건(거부), A로는 자기 시험 메모가 보임(유지)
  6. 시험용 읽기 권한을 다시 회수하고, 운영 정책 지문이 처음과 같은지 확인한 뒤 결과를 감사 표에 `pass`/`fail`로 기록
- 로컬 PostgreSQL 16(Supabase 역할·`auth.uid()` 흉내)에서 실행한 결과(제출 묶음 밖, 2026-10-13):
  - 시험 `pass` 두 번(다시 실행해도 같음): 침공 상태에서 B가 A 시험 메모 1건을 봤고, 복원 뒤 0건, A는 자기 시험 메모 1건. 운영 표 `notes` 정책 지문은 실행 전후 같음.
  - 미리보기는 정책을 바꾸지 않음. 없는 버전·변조된 사본은 `stopped`로 멈추고, 침공 정책이 그대로 남아 있음(아무것도 바꾸지 않음).
  - 사본·감사 표 고치기·지우기 거부, 브라우저 역할(`anon`·`authenticated`) 함수 실행 거부.
- 실제 Supabase에서 실행한 결과는 아래 「학생이 SQL Editor에서 실행한 결과」에 적었습니다.

#### 보조 도구 되돌리기 (`npm run policy:restore -- --confirm zone-v10r2`)

- `--confirm <버전>` 없이 실행하면 미리보기만 하고 아무것도 바꾸지 않습니다.
- 확인을 붙이면 시험 정책 한 파일만 사본으로 바꾸고, 지문과 안전 요청을 다시 검사합니다. 이 검사가 실패하면 원래 파일로 되돌리고 멈춥니다. `src/decider.mjs`, `src/detect.mjs`, `xdr/` 규칙은 바꾸지 않습니다.
- 결과는 `policy/audit.jsonl` 끝에 한 줄씩 덧붙이기만 합니다(시각, 버전, 전후 지문, 운영 정책 지문과 그대로인지, 달라진 요청, 결과). 2026-10-13에 시험 정책을 사본 버전으로 되돌린 기록 4줄이 있고, 모두 `restored`·운영 정책 그대로(`operatingPolicyUnchanged: true`)입니다.
- 되돌린 뒤 시험 정책은 메모 전체 목록 `deny`, 자기 메모 한 건 `allow`, 검증 정책 버전의 복구 `allow`, 바뀐 정책 버전의 복구 `deny`입니다.

### 제작 3: 메모 한 건 복원 (`POST /api/restore/notes/:id`, 서비스 `notes`)

- 요청: `POST /api/restore/notes/<메모 UUID>`, 본문 없음, 로그인 토큰 필요. 경로의 ID만 읽고, 주인은 로그인 토큰으로만 정합니다(심판 시험 계정은 `sub`와 신원 a·b를 묶은 주인 열쇠).
- 비공개 사본은 Supabase 표 `notes_backup`에 있습니다(메모마다 처음 사본 하나, 덧붙이기만 가능). 메모 본문은 저장소에 두지 않습니다.
  - 침해 전에 있던 메모: `supabase/10-backup.sql` ②로 사본을 떴고, 침해 전 검증 기록 `backup/notes-manifest.json`(라벨 `pre-incident-10`)에 시험 계정 B의 메모 두 건의 ID, 소유자 지문(`sha256(owner_id)`), 내용 해시(`sha256(title + 줄바꿈 + body)`)만 담았습니다. SQL Editor에서 사본을 다시 읽어 재계산이 일치(`recomputed_ok: true`)한 값만 넣었습니다.
  - 그 뒤에 만든 메모: `POST /api/notes`가 메모를 만들 때 처음 내용을 사본 표에 한 건 덧붙이고(라벨 `on-create`), 다시 읽어 내용 해시를 확인합니다. 고치거나 지울 때는 사본을 새로 만들지 않습니다.
- 복원 경로의 처리 순서(`api/restore/notes/[id].js`, 규칙은 `lib/backup-verify.mjs`):
  1. 로그인 토큰으로 요청자를 확인합니다(없으면 401). 본문은 비어 있어야 하고, 쿼리는 거부합니다(400).
  2. 사본을 다시 읽어 ID·소유자·내용 해시를 대조합니다.
     - 침해 전 메모는 검증 기록과 세 값을 모두 대조합니다. 사본 표에 함께 저장된 해시만 믿지 않습니다.
     - 그 뒤에 만든 메모는 사본의 제목·내용으로 해시를 다시 계산해 사본에 저장된 처음 해시와 대조합니다.
     - 사본 행 없음, 남의 메모 → 404로 멈춤 / ID·소유자·내용 해시가 다름 → 409로 멈춤. 멈추면 아무것도 쓰지 않습니다.
  3. 머리글 `X-Restore-Preview: 1`을 붙이면 복원할 버전과 바뀔 항목(`note`·`title`·`body`)만 보여 주고 쓰지 않습니다. 화면의 복원 버튼은 이 미리보기를 먼저 보여 주고 확인을 받은 뒤에 보냅니다. `X-Restore-Confirm`을 붙였는데 사본 버전과 다르면 409로 멈춥니다.
  4. 그 ID 한 건만 넣거나(지워졌을 때, 같은 ID·주인으로) 제목·내용을 고친 뒤, 다시 읽어 ID·소유자 지문·내용 해시가 사본과 같은지 64자 전체로 확인합니다. 같으면 `200 restored`(이미 같으면 `already_same`), 다르면 쓰기 전 상태로 되돌리고 500으로 멈춥니다. 다른 메모는 건드리지 않습니다.
  5. 모든 결과(미리보기, 복원, 멈춤)를 `restore_audit`에 덧붙입니다. 사본·감사 표 모두 고치기·지우기를 트리거로 막았고, 서버 키 권한은 읽기·덧붙이기뿐이며, 브라우저 키 권한은 없습니다.
- 가짜 DB 로컬 시험(2026-10-13, 17건 통과, 제출 묶음 밖에서 실행):
  - B가 새 메모를 만들면 처음 사본이 남음 → 변조 뒤 본문 없는 `POST` 복원 200 `restored`, 삭제 뒤 복원 200 `restored`(같은 ID·주인), ID·소유자 지문·내용 해시가 사본과 같음 → 다시 복원 `already_same`.
  - 침해 전 기록 메모: 삭제 뒤 복원 200, 사본의 내용과 해시를 함께 바꾸면 409.
  - 멈춤: A가 B 메모 복원 404, B가 A 메모 복원 404, 사본 없음 404, 사본 내용 변조 409, 틀린 확인 버전 409, 미리보기는 쓰기 없음.
  - 거부: 비로그인 401, 본문 `owner_id` 400. A 메모 그대로, 감사 기록 남음, 로그·감사에 본문·토큰 없음.
- 판정기(`src/decider.mjs`) `restore_verified_policy`: 엔진을 거치는 복구 요청(`POST /restore/notes/:id`, 같은 뜻의 `POST /notes/:id/restore`)은 자기 메모 구역 조건(로그인 주체, 등록 기기, 이상 사건이면 `step_up`)에 더해, 엔진이 알려 준 정책 버전 `policyRevision`이 침해 전에 검증한 안전 정책 버전(`1`, `policy/safe/manifest.json`)일 때만 허용합니다. 버전이 바뀌었거나 없으면 복원하지 않고 `deny · policy_unverified`로 멈춥니다. 다른 경로의 판정은 9단계와 같습니다.

### 제작 4: 복구 뒤 재시험

`npm run bundle`은 **복원 점검을 먼저** 실행하고, **그 뒤에** 1~9단계의 정상·금지 요청을 다시 보냅니다. 제출 묶음(`artifacts/submission.json`의 `attackAttempts`)에도 이 순서대로 적힙니다. 실제로 보낸 요청의 결과만 적고, 하지 않은 시험은 「미실행」으로 남기며 결과를 꾸미지 않습니다. 2026-10-13 21:00 실제 결과는 위 「판정 조건별 근거」와 `backup/restore-test-log.md`에 옮겨 적었습니다.

B·A 계정 요청은 학생이 GitHub Codespaces 비밀값(`ALEPH_B_EMAIL`·`ALEPH_B_PASSWORD`, `ALEPH_A_EMAIL`·`ALEPH_A_PASSWORD`)을 넣은 경우에만 보냅니다. 이메일·비밀번호·토큰은 결과·로그·묶음에 남기지 않고, 끝나면 로그아웃합니다.

| 순서 | 단계 | 정상 요청 / 금지 요청 | 제출 묶음 점검 | 실행 여부 |
|---|---|---|---|---|
| 0 | 10 | 시험 정책(`notes_drill` RLS) 복원 시험: 침공 흉내 → 미리보기 → 복원 → B로 A 시험 메모 0건·A로 자기 시험 메모 보임 → 운영 정책 그대로 → 감사 표 `pass` | SQL Editor `supabase/10-policy-restore-test.sql` | 학생이 SQL Editor에서 실행(결과는 아래), 제출 묶음 밖 |
| 1 | 10 | 금지: 비로그인·위조 토큰 복원 요청 | `restore_anonymous` | 항상 실행(실제 배포) |
| 2 | 10 | 판정기 코드 사본(보조) 다시 읽기 검증, 실행 전 복원 버전·변경 범위 표시, 변조·없는 사본은 중단 | `policy_snapshot_verified` | 항상 실행 |
| 3 | 10 | B 메모 **삭제** → 미리보기 → 확인 없는 요청은 쓰기 없음 → 확인 뒤 복원 → 다시 읽어 침해 전 기록과 ID·소유자 지문·내용 해시 대조, 기록에 없는 ID는 멈춤 | `restore_b_deleted_note` | B 비밀값이 있을 때 실행, 없으면 미실행 |
| 4 | 10 | B 메모 **변조** → 미리보기(바뀔 항목 제목·내용) → 확인 뒤 복원 → 다시 읽어 대조, B의 다른 메모 그대로 | `restore_b_tampered_note` | B 비밀값이 있을 때 실행, 없으면 미실행 |
| 5 | 3·5 | 금지: 비로그인·위조 토큰 메모 목록, 브라우저 키로 원본 직접 조회, 첫 화면의 키 노출 | `anonymous_api_read`, `forged_token_read`, `anon_original_api_read`, `browser_key_exposure` | 항상 실행(실제 배포) |
| 6 | 4 | 금지: B의 A 메모 읽기·수정·삭제·복원(404), A 메모는 그대로 | `cross_user_note_read` | A·B 비밀값이 있을 때 실행, 없으면 미실행 |
| 7 | 6·7 | 정상: 등록 기기 allow, 재로그인 뒤 allow / 금지: 미등록 기기 deny, 복합 이상 step_up | `registered_device_read`, `unregistered_device_read`, `anomalous_context_read` | 항상 실행(판정기 가상 요청) |
| 8 | 7 | 엔진의 실제 재로그인 흐름 | `real_step_up_block` | 미실행 |
| 9 | 8·10 | 정상: 자기 메모 한 건, 검증 정책 버전의 복구 / 금지: 바뀐 정책 버전의 복구, 전체 목록, 공지, 기능 경로, 경로표 밖, 비로그인 공지 | `zone_decider_rules`, `anonymous_notice_read` | 항상 실행 |
| 10 | 8 | 금지: 메뉴를 우회한 직접 API 요청(B의 A 메모, 학생의 공지 목록·수정) | `zone_api_cross_owner` | A·B 비밀값이 있을 때 실행, 없으면 미실행 |
| 11 | 9 | 정상 기기 유지 / 도플갱어 기기 회수 제안 | `detect_normal_device`, `detect_doppelganger_burst` | 항상 실행(가상 사건) |
| 12 | 9 | 엔진의 실제 회수 집행 | `live_revocation` | 미실행 |
| 13 | 1·2·3·4·5·8 | 정상: B·A 자기 목록·메모 읽기 / 금지: [1·2] 공개 `/data.json`의 메모, [3] 비로그인·위조 토큰 목록, [4] B의 A 메모 읽기·수정·삭제·복원, [5] 쿼리로 다른 주인·본문 `owner_id`, [8] 공지·없는 메모 | `post_restore_retest` | B 비밀값이 있을 때 실행(A 부분은 A 비밀값이 있을 때), 없으면 미실행 |

로컬에서 바로 다시 확인하는 명령: `npm run policy:diff`, `npm run decider:test`, `npm run fixture:7`, `npm run detect:test`.

### 학생이 SQL Editor에서 실행한 결과 (시험 정책 = `notes_drill` RLS)

- 2026-10-13 21:21(KST) `supabase/10-policy-backup.sql`: 사본 `s4-rls-v1` 이미 있음(`exists`, 17:16 운영 정책을 읽어 남긴 사본), 차이 보기 `backupVerified: true`, `backupFrom: notes`, `target: notes_drill`, `changeCount: 4`(정책 4개 `missing_now`).
- 2026-10-13 21:21(KST) `supabase/10-policy-restore-test.sql`: 감사 표에 `policy_restore · restored (changeCount 4, operatingPolicyUnchanged: true)`(시험 준비) → `policy_restore · previewed (changeCount 2)` → `policy_restore · restored (changeCount 2, operatingPolicyUnchanged: true)` → `policy_restore_test · pass`(대상 `notes_drill`). 이어서 차이 보기 `changeCount: 0`.
- `pass`는 시험 SQL에서 복원 상태가 `restored`이고, 복원 전 B가 A 시험 메모를 봤고, 복원 뒤 B로는 0건, A로는 자기 시험 메모 1건 이상, 운영 정책 지문이 처음과 같을 때만 기록됩니다.

## 10단계 저장점

- `step` 10. 기존 `allowedRoutes`에 `POST /api/restore/notes/:id`를 더하고, `restoreRoute`를 같은 값으로 넣었습니다. `identityProvider`, `originalApiUrl`은 그대로입니다.
- 판정기 `RULE_IDS`는 실제 구현한 8개입니다: 9단계의 7개 + `restore_verified_policy`. 판정기는 보조 사본 `zone-v10r2`와 같습니다.
- 실제로 실행한 복원 시험 결과는 `backup/restore-test-log.md`에 있습니다.
- `src/attack-check.mjs`의 10단계 점검은 위 표의 1~4번과 13번이며, 6·10번은 A·B 비밀값이 있으면 실제 요청 결과로 바뀝니다. 제출 점검 20개 한도 때문에 8단계 판정기 구역 가상 요청 여섯 건은 결과를 그대로 둔 채 한 줄(`zone_decider_rules`)로 합쳤습니다. 심판 판정이 아닙니다.
- 다시 실행하는 방법:
  1. SQL Editor에서 `supabase/10-backup.sql` ①~③ 실행 → ④로 검증 기록 값을 뽑아 `backup/notes-manifest.json`에 넣고 커밋 → `supabase/10-policy-backup.sql` 실행(사본 검증, 시험 정책과 차이 보기) → `supabase/10-policy-restore-test.sql` 실행(감사 표에 `pass`, 운영 정책 그대로)
  2. (선택) GitHub Codespaces 비밀값 `ALEPH_B_EMAIL`·`ALEPH_B_PASSWORD`, `ALEPH_A_EMAIL`·`ALEPH_A_PASSWORD`를 등록한 뒤 Codespace를 멈췄다가 다시 시작
  3. `npm ci` → `npm run policy:diff` → `bundle-notes.json` 작성 → `npm run bundle`
