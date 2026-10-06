-- 2단계 제작 1: 공개 data.json의 가상 메모를 학습용 Supabase 테이블로 옮깁니다.
-- Supabase 대시보드 → SQL Editor에 이 파일 전체를 붙여 넣고 Run 합니다.
-- 여기 들어가는 메모는 모두 실습용 가상 자료입니다. 실제 개인정보·키를 넣지 마세요.

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

-- 가상 메모 네 건 (다시 실행해도 중복으로 쌓이지 않음)
insert into public.notes (title, content)
select v.title, v.content
from (values
  ('과제',           '실습용 가상 과제 기록'),
  ('포트폴리오',     '실습용 가상 포트폴리오 기록'),
  ('아침 리추얼',    '실습용 가상 리추얼 기록'),
  ('훈련 행정 자료', '실습용 가상 행정 기록')
) as v(title, content)
where not exists (select 1 from public.notes n where n.title = v.title);

-- 확인용: 실행 결과 아래에 칸 목록과 RLS 상태가 나옵니다.
select column_name, data_type, is_nullable
from information_schema.columns
where table_schema = 'public' and table_name = 'notes'
order by ordinal_position;

select relname as table_name, relrowsecurity as rls_enabled
from pg_class
where oid = 'public.notes'::regclass;
