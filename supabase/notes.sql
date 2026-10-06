-- 2단계 제작 1: 공개 data.json의 가상 메모를 학습용 Supabase 테이블로 옮깁니다.
-- Supabase 대시보드 → SQL Editor에 이 파일 전체를 붙여 넣고 Run 합니다.
-- 테이블 구조와 권한만 담습니다. 실제 개인정보·키를 넣지 마세요.

create table if not exists public.notes (
  id         bigint generated always as identity primary key,
  owner_id   uuid,                         -- 3단계 로그인용 자리. auth.users 외래키는 일부러 걸지 않음
  title      text not null,
  content    text not null,
  created_at timestamptz not null default now()
);

-- RLS를 켜고 정책은 만들지 않습니다 → 공개 키로는 한 줄도 읽을 수 없습니다.
alter table public.notes enable row level security;

-- 브라우저용 역할에서 테이블 권한 자체를 회수합니다.
revoke all on table public.notes from anon, authenticated;

-- 서버 함수(secret key = service_role)만 읽을 수 있게 명시적으로 허용합니다.
grant select on table public.notes to service_role;

-- 가상 메모 네 건은 SQL Editor에서 한 번만 넣었습니다(2026-10-06).
-- 메모 문장이 공개 저장소에 다시 남지 않도록 넣는 값은 이 파일에 두지 않습니다.
-- 새 프로젝트에서 다시 만들 때는 Table Editor에서 직접 가상 메모를 넣으세요.

-- 확인용: 실행 결과 아래에 칸 목록과 RLS 상태가 나옵니다.
select column_name, data_type, is_nullable
from information_schema.columns
where table_schema = 'public' and table_name = 'notes'
order by ordinal_position;

select relname as table_name, relrowsecurity as rls_enabled
from pg_class
where oid = 'public.notes'::regclass;
