#!/bin/bash

# init_server 프로세스가 실행 중인지 확인하는 함수
is_init_server_running() {
  pgrep -f "init_server" > /dev/null 2>&1  # -f 옵션으로 전체 명령어 라인 검색
  return $? # pgrep의 반환값 (0: 찾음, 1: 못 찾음)을 반환
}

# init_server 프로세스가 없을 때까지 대기
while is_init_server_running; do
  sleep 1  # 1초 간격으로 확인
  echo "." # 상태를 표시하기 위해 점(.)을 출력 (선택 사항)
done
# 추가 작업 (선택 사항): 프로세스 종료 후 실행할 명령
# 예: 특정 파일 삭제, 다른 스크립트 실행 등
# 예시: rm /tmp/init_server_log.txt
kill -9 $(pgrep server)
kill -9 $(pgrep server.sh)
incus stop $(incus list | awk '{print $2}' | grep --invert-match NAME)
