// 8단계: 자료실 자원을 구역으로 나눕니다. api/ 밖이라 그 자체로는 공개 주소가 아닙니다.
// 서버는 요청마다 아래 자원 ID로 무엇을 건드리는지 구별합니다.
//   메모 구역   notes   : 목록 "notes",   한 건 "note:<id>"
//   공지 구역   notices : 목록 "notices", 한 건 "notice:<id>"
// 쿼리로 기능을 고르지 않습니다. 경로의 마지막 칸은 자료 ID뿐이고, 같은 깊이에 export 같은 기능 경로를 두지 않습니다.

export const ZONES = Object.freeze({ notes: 'note', notices: 'notice' });

export function resourceId(zone, id) {
  const kind = ZONES[zone];
  if (!kind) throw new TypeError('unknown_zone');
  return id ? `${kind}:${String(id).toLowerCase()}` : zone;
}

// 응답 머리글에 자원 ID를 붙여 둡니다(본문 모양 {id,title,body}는 그대로).
export function markResource(response, zone, id) {
  response.setHeader('X-Resource-Id', resourceId(zone, id));
}

// 거부 사유를 짧게 남깁니다. 사용자 ID·토큰·자료 본문은 남기지 않습니다.
export function logDeny(zone, method, reason) {
  console.warn(`zone_deny zone=${zone} method=${method} reason=${reason}`);
}
