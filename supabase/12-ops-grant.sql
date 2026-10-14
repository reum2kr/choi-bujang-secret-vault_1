-- 12단계 제작 1: 탈환 작전실(GET /api/ops)이 정책 복원 시험 기록을 읽을 수 있게, 서버 키(service_role)에 읽기 권한만 줍니다.
-- 고치기·지우기 권한은 주지 않습니다(이 표는 10단계 트리거로 덧붙이기만 가능). 브라우저용 역할(anon·authenticated)은 그대로 막힙니다.
grant select on table public.notes_policy_audit to service_role;

-- 확인: service_role 줄에 SELECT가 보이고, anon·authenticated 줄은 없어야 합니다.
select grantee, string_agg(privilege_type, ', ' order by privilege_type) as privileges
  from information_schema.role_table_grants
 where table_schema = 'public' and table_name = 'notes_policy_audit'
   and grantee in ('service_role', 'anon', 'authenticated')
 group by grantee;
