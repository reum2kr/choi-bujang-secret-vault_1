-- 12단계 제작 1 확인: 탈환 작전실(/ops.html, GET /api/ops)의 수치와 서버 기록을 SQL Editor에서 직접 맞춰 봅니다.
-- 읽기만 합니다. 메모 제목·본문, 사용자 ID, 기기 지문은 꺼내지 않고(가림), 결과 이름별 개수와 마지막 시각만 셉니다.

-- ① 회수 상태: 기기 승인 등록부의 상태별 개수 (화면 「회수 상태」와 같아야 함)
select status, count(*) as devices from public.vault_devices group by status order by status;

-- ② 복구: 메모 복원 감사 기록의 결과별 개수와 마지막 시각 (화면 「복구 버전」의 감사 기록과 같아야 함)
select result, count(*) as rows, max(at) as last_at from public.restore_audit group by result order by result;

-- ③ 복구: 정책 복원 시험의 기록 수와 마지막 결과 (화면 「정책 복원 시험」과 같아야 함)
select count(*) as tests,
       (select result from public.notes_policy_audit where action = 'policy_restore_test' order by at desc, id desc limit 1) as last_result,
       max(at) as last_at
  from public.notes_policy_audit where action = 'policy_restore_test';
