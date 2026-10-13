-- 10단계 제작 3: 비공개 가상 메모 사본(notes_backup)과 복원 감사 기록(restore_audit)
-- Supabase SQL Editor에서 한 번 실행합니다. 메모 본문은 이 데이터베이스 안에만 있고 저장소에는 남기지 않습니다.
-- 브라우저 키(anon·authenticated)는 두 표 모두 직접 읽거나 쓸 수 없습니다.
-- 서버 함수(service_role)는 사본을 읽기만, 감사 기록은 읽기·덧붙이기만 할 수 있습니다.

-- ① 표 만들기 ---------------------------------------------------------------
create table if not exists public.notes_backup (
  id              uuid primary key,
  owner_id        uuid not null,
  title           text not null,
  body            text not null,
  content_sha256  text not null,             -- sha256(title || 줄바꿈 || body), 소문자 16진수
  backup_label    text not null,
  backed_up_at    timestamptz not null default now()
);

create table if not exists public.restore_audit (
  audit_id   uuid primary key default gen_random_uuid(),
  at         timestamptz not null default now(),
  note_id    uuid,
  actor_id   uuid,                           -- 서버가 검증한 요청자(주인 열쇠). 이메일·토큰은 남기지 않음
  result     text not null,
  detail     text
);

alter table public.notes_backup enable row level security;
alter table public.restore_audit enable row level security;

revoke all on table public.notes_backup, public.restore_audit from public, anon, authenticated, service_role;
grant select on table public.notes_backup to service_role;
grant select, insert on table public.restore_audit to service_role;

-- 사본과 감사 기록은 고치거나 지울 수 없게 막습니다(SQL Editor의 관리자 계정도 포함).
create or replace function public.forbid_change() returns trigger language plpgsql as $$
begin
  raise exception '% 표는 덧붙이기만 할 수 있습니다 (%).', tg_table_name, tg_op;
end $$;

drop trigger if exists notes_backup_no_change on public.notes_backup;
create trigger notes_backup_no_change before update or delete on public.notes_backup
  for each row execute function public.forbid_change();
drop trigger if exists notes_backup_no_truncate on public.notes_backup;
create trigger notes_backup_no_truncate before truncate on public.notes_backup
  for each statement execute function public.forbid_change();

drop trigger if exists restore_audit_no_change on public.restore_audit;
create trigger restore_audit_no_change before update or delete on public.restore_audit
  for each row execute function public.forbid_change();
drop trigger if exists restore_audit_no_truncate on public.restore_audit;
create trigger restore_audit_no_truncate before truncate on public.restore_audit
  for each statement execute function public.forbid_change();

-- ② 침해 전 사본 뜨기 --------------------------------------------------------
-- 지금 notes에 있는 가상 메모를 사본에 넣습니다. 이미 사본에 있는 ID는 처음 값 그대로 둡니다.
insert into public.notes_backup (id, owner_id, title, body, content_sha256, backup_label)
select id, owner_id, title, body,
       encode(sha256(convert_to(title || E'\n' || body, 'UTF8')), 'hex'),
       'pre-incident-10'
from public.notes
where owner_id is not null
on conflict (id) do nothing;

-- ③ 확인 ---------------------------------------------------------------------
-- 사본을 다시 읽어 지문을 계산해 봅니다. mismatched가 0이어야 합니다.
select count(*) as backed_up,
       count(*) filter (where content_sha256 <> encode(sha256(convert_to(title || E'\n' || body, 'UTF8')), 'hex')) as mismatched
from public.notes_backup;

-- 권한 확인: anon·authenticated 줄은 없어야 하고, service_role은 notes_backup SELECT, restore_audit INSERT·SELECT만.
select grantee, table_name, string_agg(privilege_type, ', ' order by privilege_type) as privileges
from information_schema.role_table_grants
where table_schema = 'public' and table_name in ('notes_backup', 'restore_audit')
group by grantee, table_name order by table_name, grantee;
