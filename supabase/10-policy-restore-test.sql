-- 10단계: 정책 사본이 "실제로 복원되는지" 시험하고 결과를 기록합니다(깃랩 사고의 교훈).
-- supabase/10-policy-backup.sql을 실행한 뒤 Supabase SQL Editor에서 실행합니다. 여러 번 실행해도 됩니다.
-- 이 파일에는 키·메모 본문·이메일이 없습니다. 시험 계정 ID는 메모 표의 소유자 칸에서만 고릅니다.
--
-- 순서(하나의 묶음으로 실행되어, 중간에 실패하면 전부 취소되고 원래 상태 그대로 남습니다):
--  1) 3차 침공 흉내: "누구나 모든 메모 읽기" 정책을 몰래 추가하고, 본인 수정 정책 하나를 지웁니다.
--  2) 복원 전 확인: B 로그인으로 A 메모가 보이는지 셉니다(침공 상태라 보여야 함).
--  3) 미리 보기: notes_policy_restore(…, false) — 복원할 버전과 바뀔 항목만 보고 아무것도 바꾸지 않습니다.
--  4) 실행: notes_policy_restore(…, true) — 사본을 다시 읽어 검증한 뒤 정책만 되돌리고 다시 대조합니다.
--  5) 복원 뒤 확인: B 로그인으로 A 메모 0건(거부), A 로그인으로 자기 메모 1건 이상(정상 유지).
--  6) 시험용으로 잠깐 준 읽기 권한을 다시 회수하고(5단계 상태), 결과를 감사 기록(notes_policy_audit)에 남깁니다.

do $$
declare
  a uuid;
  b uuid;
  b_sees_a_before int;
  b_sees_a_after int;
  a_sees_own_after int;
  preview jsonb;
  restored jsonb;
  ok boolean;
begin
  select owner_id into a from public.notes where owner_id is not null
   group by owner_id order by count(*) desc, owner_id limit 1;
  select owner_id into b from public.notes where owner_id is not null and owner_id <> a
   group by owner_id order by count(*) desc, owner_id limit 1;
  if a is null or b is null then
    raise exception 'restore_test_needs_two_owners';
  end if;

  -- 1) 침공 흉내
  execute 'create policy notes_attack_read_all on public.notes for select to authenticated using (true)';
  execute 'drop policy if exists notes_update_own on public.notes';
  execute 'grant select on public.notes to authenticated';

  -- 2) 복원 전: B로 A 메모 세기
  perform set_config('request.jwt.claims', json_build_object('sub', b, 'role', 'authenticated')::text, true);
  execute 'set local role authenticated';
  select count(*) into b_sees_a_before from public.notes where owner_id = a;
  execute 'reset role';

  -- 3) 미리 보기, 4) 실행
  preview := public.notes_policy_restore('s4-rls-v1', false);
  restored := public.notes_policy_restore('s4-rls-v1', true);

  -- 5) 복원 뒤: B는 A 메모 0건, A는 자기 메모 보임
  perform set_config('request.jwt.claims', json_build_object('sub', b, 'role', 'authenticated')::text, true);
  execute 'set local role authenticated';
  select count(*) into b_sees_a_after from public.notes where owner_id = a;
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role', 'authenticated')::text, true);
  select count(*) into a_sees_own_after from public.notes where owner_id = a;
  execute 'reset role';

  -- 6) 시험용 권한 회수(5단계 상태로), 결과 기록
  execute 'revoke all on table public.notes from authenticated';
  ok := restored->>'status' = 'restored' and b_sees_a_after = 0 and a_sees_own_after > 0;
  insert into public.notes_policy_audit (action, version, result, detail)
  values ('policy_restore_test', 's4-rls-v1', case when ok then 'pass' else 'fail' end,
          jsonb_build_object('previewStatus', preview->>'status',
                             'previewChanges', jsonb_array_length(coalesce(preview->'changes', '[]'::jsonb)),
                             'restoreStatus', restored->>'status',
                             'bSeesANotesBefore', b_sees_a_before,
                             'bSeesANotesAfter', b_sees_a_after,
                             'aSeesOwnNotesAfter', a_sees_own_after));
  if not ok then
    raise exception 'restore_test_failed: %', restored->>'status';
  end if;
end;
$$;

-- 결과 확인: 최근 정책 감사 기록과 지금 정책 차이(changeCount 0이어야 정상)
select at, action, result, detail from public.notes_policy_audit order by id desc limit 4;
select public.notes_policy_diff('s4-rls-v1') as diff_now;
