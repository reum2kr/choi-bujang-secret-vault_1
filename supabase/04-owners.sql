-- 4단계 제작 1: 기존 가상 메모에 주인(owner_id)을 연결합니다. (학습용)
-- 실제 이메일은 공개 저장소에 남기지 않습니다.
-- SQL Editor에 붙여 넣은 뒤 아래 두 자리표시자만 실제 테스트 계정 이메일로 바꿔 실행하세요.
--   <A_EMAIL> : A 계정 이메일
--   <B_EMAIL> : B 계정 이메일
-- API와 권한 정책은 이 파일에서 바꾸지 않습니다.

do $$
declare
  a_id uuid;
  b_id uuid;
begin
  select id into a_id from auth.users where lower(email) = lower('<A_EMAIL>');
  select id into b_id from auth.users where lower(email) = lower('<B_EMAIL>');
  if a_id is null then raise exception 'A 계정을 auth.users에서 찾지 못했습니다.'; end if;
  if b_id is null then raise exception 'B 계정을 auth.users에서 찾지 못했습니다.'; end if;
  if a_id = b_id then raise exception 'A와 B가 같은 계정입니다.'; end if;

  -- A: 기존 가상 메모 세 개 (주인이 비어 있는 것만)
  update public.notes set owner_id = a_id
  where owner_id is null and title in ('과제', '포트폴리오', '아침 리추얼');

  -- B: 공개 가능한 시험 메모 한 건 (기존 가상 메모 중 남은 한 건을 B에게)
  update public.notes set owner_id = b_id
  where owner_id is null and title = '훈련 행정 자료';
end $$;

-- 확인용: 메모 제목별 주인. 이메일은 화면에서만 보고 어디에도 복사하지 마세요.
select n.title, n.owner_id, u.email as owner_email
from public.notes n
left join auth.users u on u.id = n.owner_id
order by owner_email nulls last, n.title;
