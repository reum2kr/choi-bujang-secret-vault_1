-- 10단계: 메모를 새로 만들면 그 처음 내용을 비공개 사본 표(notes_backup)에 데이터베이스가 직접 한 건 남깁니다.
-- supabase/10-backup.sql을 실행한 뒤 Supabase SQL Editor에서 이 파일 전체를 한 번 실행합니다. 여러 번 실행해도 됩니다.
-- 서버 키(service_role)의 사본 권한은 읽기만 그대로 둡니다. 사본은 이 트리거만 덧붙이고, 고치기·지우기는 기존 트리거가 막습니다.
-- 메모를 고치거나 지울 때는 사본을 새로 만들지 않습니다(처음 사본이 기준). 같은 ID의 사본이 이미 있으면 그대로 둡니다.
-- 이 파일에는 키·메모 본문·이메일이 없습니다.

create or replace function public.notes_backup_on_insert() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.owner_id is null then
    return new;
  end if;
  insert into public.notes_backup (id, owner_id, title, body, content_sha256, backup_label)
  values (new.id, new.owner_id, new.title, new.body,
          encode(sha256(convert_to(new.title || E'\n' || new.body, 'UTF8')), 'hex'), 'on-create')
  on conflict (id) do nothing;
  return new;
end;
$$;
revoke all on function public.notes_backup_on_insert() from public, anon, authenticated;

drop trigger if exists notes_backup_on_insert on public.notes;
create trigger notes_backup_on_insert after insert on public.notes
  for each row execute function public.notes_backup_on_insert();

-- 확인: 트리거가 있고, 서버 키의 사본 권한은 SELECT만이어야 합니다.
select tgname as trigger_name from pg_trigger
 where tgrelid = 'public.notes'::regclass and tgname = 'notes_backup_on_insert';
select grantee, string_agg(privilege_type, ', ' order by privilege_type) as privileges
  from information_schema.role_table_grants
 where table_schema = 'public' and table_name = 'notes_backup' and grantee = 'service_role'
 group by grantee;
