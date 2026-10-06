-- 5단계 제작 2: 학습용 notes 테이블을 브라우저 키로 직접 부르는 길을 닫습니다.
-- PUBLIC·anon·authenticated의 직접 권한을 모두 거둡니다. 다른 테이블은 건드리지 않습니다.
-- 서버 함수가 쓰는 service_role 권한과 RLS(켜짐)는 그대로 둡니다.
-- SQL Editor에서 [1] 적용 전 확인 → [2] 적용 → [1]을 다시 실행해 적용 후 확인합니다.

-- [1] 권한 확인 (적용 전·후 같은 쿼리)
select r.role,
  concat_ws(', ',
    case when has_table_privilege(r.role, 'public.notes', 'SELECT') then 'SELECT' end,
    case when has_table_privilege(r.role, 'public.notes', 'INSERT') then 'INSERT' end,
    case when has_table_privilege(r.role, 'public.notes', 'UPDATE') then 'UPDATE' end,
    case when has_table_privilege(r.role, 'public.notes', 'DELETE') then 'DELETE' end,
    case when has_table_privilege(r.role, 'public.notes', 'TRUNCATE') then 'TRUNCATE' end,
    case when has_table_privilege(r.role, 'public.notes', 'REFERENCES') then 'REFERENCES' end,
    case when has_table_privilege(r.role, 'public.notes', 'TRIGGER') then 'TRIGGER' end) as privileges
from (values ('anon'), ('authenticated'), ('service_role')) as r(role);

-- [2] 적용 (한 묶음)
begin;
revoke all on table public.notes from public, anon, authenticated;
-- 서버 함수 전용 권한은 명시적으로 유지합니다.
grant select, insert, update, delete on table public.notes to service_role;
-- RLS는 켠 채로 둡니다. 4단계 정책은 남아 있어도 권한이 없으므로 직접 호출은 모두 거부됩니다.
alter table public.notes enable row level security;
commit;

-- 기대 결과 ([1]을 다시 실행)
--   anon          : (빈칸)
--   authenticated : (빈칸)
--   service_role  : SELECT, INSERT, UPDATE, DELETE (그 밖의 권한이 있어도 서버 함수용이라 괜찮음)
