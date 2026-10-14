-- 11단계 제작 2: 기기 승인 등록부(vault_devices)와 승인 함수
-- Supabase SQL Editor에서 이 파일 전체를 한 번 실행합니다. 여러 번 실행해도 됩니다. 이 파일에는 키·이메일이 없습니다.
--
-- · 기기 ID는 서버가 만든 무작위 값이며 브라우저에는 httpOnly 쿠키로만 있습니다(자바스크립트로 읽을 수 없음).
--   이 표에는 그 값의 SHA-256만 저장합니다. 기기 개인키는 만들지 않습니다.
-- · 서버 함수(service_role)는 「승인 대기」 요청을 덧붙이고 상태를 읽을 수만 있습니다. 승인으로 바꿀 권한이 없습니다.
-- · 승인은 SQL Editor에서 학생(관리자)이 approve_vault_device('요청 코드')를 실행할 때만 됩니다.
--   화면의 버튼, 앱 설치 여부, 요청 본문의 값으로는 승인되지 않습니다.

create table if not exists public.vault_devices (
  device_hash  text not null check (device_hash ~ '^[0-9a-f]{64}$'),
  owner_id     uuid not null,
  status       text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  requested_at timestamptz not null default now(),
  decided_at   timestamptz,
  primary key (device_hash, owner_id)
);
alter table public.vault_devices enable row level security;
revoke all on table public.vault_devices from public, anon, authenticated, service_role;
grant select, insert on table public.vault_devices to service_role;

-- 서버가 새 요청을 넣을 때는 항상 「승인 대기」로만 들어가게 합니다(승인 상태로 넣는 요청은 거부).
create or replace function public.vault_devices_insert_pending() returns trigger
language plpgsql set search_path = '' as $$
begin
  if new.status <> 'pending' or new.decided_at is not null then
    raise exception 'device_request_must_be_pending';
  end if;
  return new;
end;
$$;
drop trigger if exists vault_devices_insert_pending on public.vault_devices;
create trigger vault_devices_insert_pending before insert on public.vault_devices
  for each row execute function public.vault_devices_insert_pending();

-- 승인(관리자 전용): 화면에 보인 요청 코드(기기 지문 앞 12자리)로 승인 대기 기기 한 대를 승인합니다.
create or replace function public.approve_vault_device(p_code text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  n int;
begin
  if p_code !~ '^[0-9a-f]{12}$' then
    raise exception 'request_code_must_be_12_hex';
  end if;
  select count(*) into n from public.vault_devices where left(device_hash, 12) = p_code and status = 'pending';
  if n <> 1 then
    return jsonb_build_object('approved', false, 'reason', 'pending_request_not_found_or_ambiguous', 'matches', n);
  end if;
  update public.vault_devices set status = 'approved', decided_at = now()
   where left(device_hash, 12) = p_code and status = 'pending';
  return jsonb_build_object('approved', true, 'code', p_code);
end;
$$;

-- 승인 취소(관리자 전용): 잃어버린 기기 등은 revoked로 바꾸면 다시 자료가 닫힙니다.
create or replace function public.revoke_vault_device(p_code text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  update public.vault_devices set status = 'revoked', decided_at = now()
   where left(device_hash, 12) = p_code and status <> 'revoked';
  return jsonb_build_object('revoked', found, 'code', p_code);
end;
$$;
revoke all on function public.approve_vault_device(text) from public, anon, authenticated, service_role;
revoke all on function public.revoke_vault_device(text) from public, anon, authenticated, service_role;
revoke all on function public.vault_devices_insert_pending() from public, anon, authenticated, service_role;

-- 확인: 서버 키 권한은 INSERT, SELECT만이어야 하고(UPDATE 없음), 승인 대기 목록이 보입니다.
select grantee, string_agg(privilege_type, ', ' order by privilege_type) as privileges
  from information_schema.role_table_grants
 where table_schema = 'public' and table_name = 'vault_devices' and grantee = 'service_role'
 group by grantee;
select left(device_hash, 12) as request_code, status, requested_at, decided_at
  from public.vault_devices order by requested_at desc limit 10;
