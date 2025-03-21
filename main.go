package main

import (
    client "github.com/lxc/incus/client"
    httpRequest "github.com/yoonjin67/lvirt_applicationUnit/http_request"
    iUnit "github.com/yoonjin67/lvirt_applicationUnit/incusUnit"
    "log"
    "container/heap"
)

// 전역 변수 선언
var WorkQueue chan int

func main() {
    // PortHeap 초기화
    iUnit.PortHeap = &iUnit.IntHeap{}
    heap.Init(iUnit.PortHeap)

    var err error
    iUnit.IncusCli, err = client.ConnectIncusUnix("", nil)
    if err != nil {
        log.Fatalf("Failed to connect to LXD: %v", err)
    }

    // WorkQueue 초기화
    WorkQueue = make(chan int, 100)

    // HTTP 요청 초기화
    httpRequest.InitHttpRequest(iUnit.WorkQueue)

    // 컨테이너 작업자 풀 시작
}

