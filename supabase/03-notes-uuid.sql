-- 3단계 제작 3: 메모 API 모양 {id(UUID), title, body}에 맞게 notes 테이블을 바꿉니다.
-- 기존 가상 메모 네 건은 그대로 두고 칸 이름과 id 형식만 바꿉니다.
-- Supabase 대시보드 → SQL Editor에 붙여 넣고 한 번만 Run 합니다.

-- 1) 본문 칸 이름: content → body
alter table public.notes rename column content to body;

-- 2) id를 숫자에서 UUID로 바꿉니다(기존 행에도 새 UUID가 붙습니다).
alter table public.notes add column new_id uuid not null default gen_random_uuid();
alter table public.notes drop constraint notes_pkey;
alter table public.notes drop column id;
alter table public.notes rename column new_id to id;
alter table public.notes add primary key (id);

-- 3) 권한: 브라우저용 역할은 계속 막고, 서버 함수(service_role)만 읽기·쓰기를 허용합니다.
--    RLS는 켜진 그대로이며 정책은 만들지 않습니다.
revoke all on table public.notes from anon, authenticated;
grant select, insert, update, delete on table public.notes to service_role;

-- 확인용
select column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public' and table_name = 'notes'
order by ordinal_position;
