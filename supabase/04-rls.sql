-- 4단계 제작 3: notes 테이블에 RLS와 최소 권한을 적용합니다. (학습 DB 전용)
-- 다른 테이블은 건드리지 않습니다. 서버 함수가 쓰는 service_role 권한도 그대로 둡니다.
-- SQL Editor에서 [1] 적용 전 확인 → [2] 적용 → [3] 적용 후 확인 순서로 하나씩 실행하세요.

-- ─────────────────────────────────────────────
-- [1] 적용 전 확인 (이 블록만 선택해 Run)
-- ─────────────────────────────────────────────
select g.grantee, string_agg(g.privilege_type, ', ' order by g.privilege_type) as granted
from information_schema.role_table_grants g
where g.table_schema = 'public' and g.table_name = 'notes'
  and g.grantee in ('anon', 'authenticated')
group by g.grantee
union all
select r.role || ' (has_table_privilege)',
  concat_ws(', ',
    case when has_table_privilege(r.role, 'public.notes', 'SELECT') then 'SELECT' end,
    case when has_table_privilege(r.role, 'public.notes', 'INSERT') then 'INSERT' end,
    case when has_table_privilege(r.role, 'public.notes', 'UPDATE') then 'UPDATE' end,
    case when has_table_privilege(r.role, 'public.notes', 'DELETE') then 'DELETE' end,
    case when has_table_privilege(r.role, 'public.notes', 'TRUNCATE') then 'TRUNCATE' end,
    case when has_table_privilege(r.role, 'public.notes', 'REFERENCES') then 'REFERENCES' end,
    case when has_table_privilege(r.role, 'public.notes', 'TRIGGER') then 'TRIGGER' end)
from (values ('anon'), ('authenticated')) as r(role)
order by 1;

-- ─────────────────────────────────────────────
-- [2] 적용 (이 블록만 선택해 Run)
-- ─────────────────────────────────────────────
begin;

-- 기존 권한부터 모두 회수합니다.
revoke all on table public.notes from public, anon, authenticated;

-- 로그인 사용자 역할에만 네 가지 권한을 줍니다. anon에는 아무 권한도 주지 않습니다.
grant select, insert, update, delete on table public.notes to authenticated;

-- RLS를 켜고, 본인 행만 허용하는 정책을 만듭니다.
alter table public.notes enable row level security;

drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

-- SELECT: 기존 행 USING
create policy notes_select_own on public.notes
  for select to authenticated
  using (auth.uid() = owner_id);

-- INSERT: 새 행 WITH CHECK
create policy notes_insert_own on public.notes
  for insert to authenticated
  with check (auth.uid() = owner_id);

-- UPDATE: 기존 행 USING + 새 행 WITH CHECK (소유자를 남에게 넘길 수 없음)
create policy notes_update_own on public.notes
  for update to authenticated
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

-- DELETE: 기존 행 USING
create policy notes_delete_own on public.notes
  for delete to authenticated
  using (auth.uid() = owner_id);

commit;

-- ─────────────────────────────────────────────
-- [3] 적용 후 확인 (이 블록만 선택해 Run)
--   기대: anon → 아무 권한 없음 / authenticated → DELETE, INSERT, SELECT, UPDATE만
-- ─────────────────────────────────────────────
select g.grantee, string_agg(g.privilege_type, ', ' order by g.privilege_type) as granted
from information_schema.role_table_grants g
where g.table_schema = 'public' and g.table_name = 'notes'
  and g.grantee in ('anon', 'authenticated')
group by g.grantee
union all
select r.role || ' (has_table_privilege)',
  coalesce(nullif(concat_ws(', ',
    case when has_table_privilege(r.role, 'public.notes', 'SELECT') then 'SELECT' end,
    case when has_table_privilege(r.role, 'public.notes', 'INSERT') then 'INSERT' end,
    case when has_table_privilege(r.role, 'public.notes', 'UPDATE') then 'UPDATE' end,
    case when has_table_privilege(r.role, 'public.notes', 'DELETE') then 'DELETE' end,
    case when has_table_privilege(r.role, 'public.notes', 'TRUNCATE') then 'TRUNCATE' end,
    case when has_table_privilege(r.role, 'public.notes', 'REFERENCES') then 'REFERENCES' end,
    case when has_table_privilege(r.role, 'public.notes', 'TRIGGER') then 'TRIGGER' end), ''), '(없음)')
from (values ('anon'), ('authenticated')) as r(role)
union all
select 'policy ' || p.policyname, p.cmd || ' → ' || array_to_string(p.roles, ',')
  || coalesce(' USING ' || p.qual, '') || coalesce(' CHECK ' || p.with_check, '')
from pg_policies p
where p.schemaname = 'public' and p.tablename = 'notes'
order by 1;
