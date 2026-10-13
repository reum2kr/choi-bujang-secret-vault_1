-- 8단계: 강사 공지 구역(notices)과 강사 권한 표(instructors)를 만듭니다. (학습 DB 전용)
-- 메모 표(notes)는 건드리지 않습니다. 실제 이메일은 공개 저장소에 남기지 않습니다.
-- SQL Editor에서 한 번 실행합니다.

begin;

create table if not exists public.notices (
  id         uuid primary key default gen_random_uuid(),
  title      text not null,
  body       text not null,
  updated_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 강사 권한은 이 표에 저장된 사용자 ID로만 판단합니다(요청의 role은 믿지 않음).
create table if not exists public.instructors (
  user_id    uuid primary key,
  created_at timestamptz not null default now()
);

-- 5단계와 같은 원칙: 브라우저 키로 직접 부를 수 없고 서버 함수(service_role)만 씁니다.
alter table public.notices enable row level security;
alter table public.instructors enable row level security;
revoke all on table public.notices, public.instructors from public, anon, authenticated;
grant select, insert, update, delete on table public.notices to service_role;
grant select on table public.instructors to service_role;

-- 공개해도 되는 가상 공지 한 건
insert into public.notices (title, body)
select '반 공지', '실습용 가상 공지입니다.'
where not exists (select 1 from public.notices);

commit;

-- (선택) 강사 계정을 하나 지정합니다. <INSTRUCTOR_EMAIL>을 강사용 테스트 계정 이메일로 바꿔 실행하세요.
-- insert into public.instructors (user_id)
-- select id from auth.users where lower(email) = lower('<INSTRUCTOR_EMAIL>')
-- on conflict do nothing;

-- 확인
select r.role,
  concat_ws(', ',
    case when has_table_privilege(r.role, 'public.notices', 'SELECT') then 'notices:SELECT' end,
    case when has_table_privilege(r.role, 'public.notices', 'UPDATE') then 'notices:UPDATE' end,
    case when has_table_privilege(r.role, 'public.instructors', 'SELECT') then 'instructors:SELECT' end) as privileges
from (values ('anon'), ('authenticated'), ('service_role')) as r(role);
