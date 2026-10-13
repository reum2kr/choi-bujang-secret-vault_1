-- 10단계 제작 1·2: 안전 정책 사본 → 다시 읽어 검증 → 시험 정책과 차이 보기 → 시험 정책 되돌리기
-- supabase/10-backup.sql(forbid_change 함수가 들어 있음)을 실행한 뒤, Supabase SQL Editor에서 이 파일 전체를 실행합니다.
-- 여러 번 실행해도 안전합니다. 이 파일에는 키·메모 본문·이메일이 없습니다.
--
-- 세 가지 정책을 구분합니다.
--  · 실제 운영 정책 : 운영 표 public.notes의 RLS(4단계 정책 4개, auth.uid() = owner_id). 이 파일은 운영 정책을 읽기만 하고 바꾸지 않습니다.
--  · 안전 정책 사본 : 침해 전에 운영 정책이 4단계 기준과 같은지 검증한 뒤 읽어 둔 사본(notes_policy_backup, SHA-256 함께).
--  · 시험 정책      : 운영 표와 따로 둔 시험 표 public.notes_drill의 RLS. 3차 침공 훈련은 이 시험 정책을 바꾸고 되돌립니다.
--
--  · notes_policy_capture(버전)        : 운영 정책이 4단계 안전 기준과 같을 때만 읽어서 사본을 남깁니다(운영 정책은 바꾸지 않음).
--  · notes_policy_backup_verify(버전)  : 사본을 다시 읽어 SHA-256을 다시 계산·대조합니다. 없거나 다르면 예외(멈춤).
--  · notes_policy_diff(버전)           : 검증된 사본과 시험 정책(notes_drill)의 차이만 보여 줍니다(아무것도 바꾸지 않음).
--  · notes_policy_restore(버전, 확인)  : 확인 false면 복원할 버전과 바뀔 항목만 보여 주고, true면 사본을 다시 검증한 뒤
--      시험 표 notes_drill의 정책만 사본대로 되돌리고, 다시 읽어 사본과 같은지 대조합니다. 운영 정책 지문이 바뀌었거나
--      대조가 다르면 예외로 전체 취소. 사본이 없거나 검증이 실패하면 아무것도 바꾸지 않고 감사 기록만 남기고 멈춥니다.
--      운영 표 notes와 다른 표(notices·instructors·notes_backup 등)의 정책, 사본·감사 기록은 건드리지 않습니다.

-- 1) 정책 사본 표와 감사 기록 표(덧붙이기만 가능)
create table if not exists public.notes_policy_backup (
  version         text primary key check (version ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  snapshot        jsonb not null,
  snapshot_sha256 text not null check (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
  captured_at     timestamptz not null default now()
);
create table if not exists public.notes_policy_audit (
  id      bigint generated always as identity primary key,
  at      timestamptz not null default now(),
  action  text not null,
  version text,
  result  text not null,
  detail  jsonb
);
alter table public.notes_policy_backup enable row level security;
alter table public.notes_policy_audit enable row level security;
revoke all on table public.notes_policy_backup from public, anon, authenticated;
revoke all on table public.notes_policy_audit from public, anon, authenticated;
drop trigger if exists notes_policy_backup_no_change on public.notes_policy_backup;
create trigger notes_policy_backup_no_change before update or delete on public.notes_policy_backup
  for each row execute function public.forbid_change();
drop trigger if exists notes_policy_backup_no_truncate on public.notes_policy_backup;
create trigger notes_policy_backup_no_truncate before truncate on public.notes_policy_backup
  for each statement execute function public.forbid_change();
drop trigger if exists notes_policy_audit_no_change on public.notes_policy_audit;
create trigger notes_policy_audit_no_change before update or delete on public.notes_policy_audit
  for each row execute function public.forbid_change();
drop trigger if exists notes_policy_audit_no_truncate on public.notes_policy_audit;
create trigger notes_policy_audit_no_truncate before truncate on public.notes_policy_audit
  for each statement execute function public.forbid_change();

-- 2) 시험 표(시험 정책이 걸리는 곳). 운영 notes와 같은 칸이지만 가상 시험 메모만 넣습니다. 브라우저 역할 권한 없음.
create table if not exists public.notes_drill (
  id       uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title    text not null,
  body     text not null default ''
);
alter table public.notes_drill enable row level security;
revoke all on table public.notes_drill from public, anon, authenticated;

-- 3) 표의 지금 정책 읽기(표 이름 → RLS 켜짐 여부 + 정책 목록, 이름순)
create or replace function public.notes_policy_current(p_table text) returns jsonb
language sql stable security definer set search_path = '' as $$
  select jsonb_build_object(
    'table', p_table,
    'rls', (select c.relrowsecurity from pg_catalog.pg_class c
              join pg_catalog.pg_namespace n on n.oid = c.relnamespace
             where n.nspname = 'public' and c.relname = p_table),
    'policies', coalesce((
      select jsonb_agg(jsonb_build_object(
               'name', p.policyname, 'permissive', p.permissive,
               'roles', (select jsonb_agg(r::text order by r::text) from unnest(p.roles) as r),
               'cmd', p.cmd, 'qual', p.qual, 'with_check', p.with_check) order by p.policyname)
        from pg_catalog.pg_policies p
       where p.schemaname = 'public' and p.tablename = p_table), '[]'::jsonb));
$$;

create or replace function public.notes_policy_sha256(p_snapshot jsonb) returns text
language sql immutable set search_path = '' as $$
  select encode(sha256(convert_to(p_snapshot::text, 'UTF8')), 'hex');
$$;

-- 표 이름을 뺀 정책 내용(RLS 여부 + 정책 목록)의 지문. 사본과 시험 정책을 같은 기준으로 비교할 때 씁니다.
create or replace function public.notes_policy_rules_sha256(p_snapshot jsonb) returns text
language sql immutable set search_path = '' as $$
  select public.notes_policy_sha256(jsonb_build_object('rls', p_snapshot->'rls', 'policies', p_snapshot->'policies'));
$$;

-- 4) 침해 전 사본 남기기: 운영 정책이 4단계 안전 기준과 같을 때만 읽어서 저장(운영 정책은 바꾸지 않음)
create or replace function public.notes_policy_capture(p_version text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  snap jsonb;
  names text[];
  pol jsonb;
  rule text;
begin
  if exists (select 1 from public.notes_policy_backup where version = p_version) then
    return jsonb_build_object('status', 'exists', 'version', p_version);
  end if;
  snap := public.notes_policy_current('notes');
  if (snap->>'rls')::boolean is not true then
    raise exception 'policy_capture_refused: rls_off';
  end if;
  select array_agg(e->>'name' order by e->>'name') into names from jsonb_array_elements(snap->'policies') as e;
  if names is distinct from array['notes_delete_own', 'notes_insert_own', 'notes_select_own', 'notes_update_own'] then
    raise exception 'policy_capture_refused: unexpected_policies %', names;
  end if;
  for pol in select value from jsonb_array_elements(snap->'policies') loop
    rule := coalesce(pol->>'qual', '') || ' ' || coalesce(pol->>'with_check', '');
    if rule !~ 'auth\.uid\(\)' or rule !~ 'owner_id' or pol->'roles' <> '["authenticated"]'::jsonb
       or pol->>'permissive' <> 'PERMISSIVE' then
      raise exception 'policy_capture_refused: unsafe_rule %', pol->>'name';
    end if;
  end loop;
  insert into public.notes_policy_backup (version, snapshot, snapshot_sha256)
  values (p_version, snap, public.notes_policy_sha256(snap));
  insert into public.notes_policy_audit (action, version, result) values ('policy_capture', p_version, 'captured');
  return jsonb_build_object('status', 'captured', 'version', p_version, 'sha256', public.notes_policy_sha256(snap));
end;
$$;

-- 5) 사본 다시 읽어 검증: 없거나 해시가 다르면 예외(멈춤)
create or replace function public.notes_policy_backup_verify(p_version text) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare
  b public.notes_policy_backup%rowtype;
begin
  select * into b from public.notes_policy_backup where version = p_version;
  if not found then
    raise exception 'policy_backup_missing';
  end if;
  if public.notes_policy_sha256(b.snapshot) <> b.snapshot_sha256 then
    raise exception 'policy_backup_unverified';
  end if;
  return b.snapshot;
end;
$$;

-- 6) 차이만 보기(읽기 전용): 검증된 사본과 시험 정책(notes_drill)
create or replace function public.notes_policy_diff(p_version text) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare
  snap jsonb;
  cur jsonb;
  changes jsonb;
begin
  snap := public.notes_policy_backup_verify(p_version);
  cur := public.notes_policy_current('notes_drill');
  with b as (select e->>'name' as n, e from jsonb_array_elements(snap->'policies') as e),
       c as (select e->>'name' as n, e from jsonb_array_elements(cur->'policies') as e)
  select coalesce(jsonb_agg(jsonb_build_object(
           'item', coalesce(b.n, c.n),
           'change', case when b.n is null then 'added_after_backup'
                          when c.n is null then 'missing_now' else 'changed' end,
           'current', c.e, 'backup', b.e) order by coalesce(b.n, c.n)), '[]'::jsonb)
    into changes
    from b full join c on b.n = c.n
   where b.e is distinct from c.e;
  if (cur->>'rls') is distinct from (snap->>'rls') then
    changes := jsonb_build_array(jsonb_build_object('item', 'rls', 'change', 'changed',
                 'current', cur->'rls', 'backup', snap->'rls')) || changes;
  end if;
  return jsonb_build_object('version', p_version, 'backupFrom', snap->>'table', 'target', 'notes_drill',
                            'backupVerified', true, 'changeCount', jsonb_array_length(changes), 'changes', changes);
end;
$$;

-- 7) 시험 정책 되돌리기: 미리 보기(확인 false) / 실행(확인 true)
create or replace function public.notes_policy_restore(p_version text, p_confirm boolean default false) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  snap jsonb;
  d jsonb;
  ch jsonb;
  def jsonb;
  roles text;
  cur jsonb;
  operating_before text;
begin
  -- 사본 다시 읽어 검증. 없거나 실패하면 아무것도 바꾸지 않고 멈춤(감사 기록만)
  begin
    snap := public.notes_policy_backup_verify(p_version);
  exception when others then
    insert into public.notes_policy_audit (action, version, result, detail)
    values ('policy_restore', p_version, 'stopped', jsonb_build_object('reason', sqlerrm, 'target', 'notes_drill'));
    return jsonb_build_object('status', 'stopped', 'reason', sqlerrm);
  end;
  operating_before := public.notes_policy_sha256(public.notes_policy_current('notes'));

  d := public.notes_policy_diff(p_version);
  if not p_confirm then
    insert into public.notes_policy_audit (action, version, result, detail)
    values ('policy_restore', p_version, 'previewed',
            jsonb_build_object('target', 'notes_drill', 'changeCount', d->'changeCount'));
    return jsonb_build_object('status', 'preview', 'version', p_version, 'target', 'notes_drill', 'changes', d->'changes',
                              'next', 'select public.notes_policy_restore(''' || p_version || ''', true);');
  end if;

  -- 검증된 사본대로 시험 표 notes_drill의 정책만 되돌림(운영 표 notes는 건드리지 않음)
  for ch in select value from jsonb_array_elements(d->'changes') loop
    continue when ch->>'item' = 'rls';
    if jsonb_typeof(ch->'current') = 'object' then
      execute format('drop policy if exists %I on public.notes_drill', ch->>'item');
    end if;
    def := ch->'backup';
    if jsonb_typeof(def) = 'object' then
      select string_agg(case when r = 'public' then 'public' else quote_ident(r) end, ', ')
        into roles from jsonb_array_elements_text(def->'roles') as r;
      execute format('create policy %I on public.notes_drill as %s for %s to %s %s %s',
        def->>'name', def->>'permissive', def->>'cmd', roles,
        case when def->>'qual' is not null then 'using (' || (def->>'qual') || ')' else '' end,
        case when def->>'with_check' is not null then 'with check (' || (def->>'with_check') || ')' else '' end);
    end if;
  end loop;
  if (snap->>'rls')::boolean then
    execute 'alter table public.notes_drill enable row level security';
  end if;

  -- 다시 읽어 사본과 같은지 대조하고, 운영 정책이 그대로인지 확인. 하나라도 다르면 예외로 이 복원 전체 취소
  cur := public.notes_policy_current('notes_drill');
  if public.notes_policy_rules_sha256(cur) <> public.notes_policy_rules_sha256(snap) then
    raise exception 'policy_restore_verify_failed';
  end if;
  if public.notes_policy_sha256(public.notes_policy_current('notes')) <> operating_before then
    raise exception 'policy_restore_touched_operating_policy';
  end if;
  insert into public.notes_policy_audit (action, version, result, detail)
  values ('policy_restore', p_version, 'restored',
          jsonb_build_object('target', 'notes_drill', 'changeCount', d->'changeCount', 'operatingPolicyUnchanged', true));
  return jsonb_build_object('status', 'restored', 'version', p_version, 'target', 'notes_drill', 'changes', d->'changes',
                            'rulesSha256', public.notes_policy_rules_sha256(cur), 'operatingPolicyUnchanged', true);
end;
$$;

-- 서버 전용 역할만 실행(브라우저용 역할 실행 불가)
revoke all on function public.notes_policy_current(text) from public, anon, authenticated;
revoke all on function public.notes_policy_sha256(jsonb) from public, anon, authenticated;
revoke all on function public.notes_policy_rules_sha256(jsonb) from public, anon, authenticated;
revoke all on function public.notes_policy_capture(text) from public, anon, authenticated;
revoke all on function public.notes_policy_backup_verify(text) from public, anon, authenticated;
revoke all on function public.notes_policy_diff(text) from public, anon, authenticated;
revoke all on function public.notes_policy_restore(text, boolean) from public, anon, authenticated;

-- 8) 침해 전 사본 남기기(이미 있으면 그대로 둠) → 다시 읽어 검증 → 시험 정책과 차이 확인
--    처음 실행하면 시험 표에 정책이 없으므로 사본의 정책 4개가 「missing_now」로 보입니다(복원할 항목).
select public.notes_policy_capture('s4-rls-v1') as capture;
select public.notes_policy_diff('s4-rls-v1') as diff_now;
