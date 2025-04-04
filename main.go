package main

import (
    client "github.com/lxc/incus/client"
    http_request "github.com/yoonjin67/linux_virt_unit/http_request"
    linux_virt "github.com/yoonjin67/linux_virt_unit"
    db "github.com/yoonjin67/linux_virt_unit/mongo_connect"
    incus_unit "github.com/yoonjin67/linux_virt_unit/incus_unit"
    "log"
    "container/heap"
)

// 전역 변수 선언
var WorkQueue chan int

func main() {
    // PortHeap 초기화
    incus_unit.PortHeap = &incus_unit.IntHeap{}
    incus_unit.WorkQueue = &incus_unit.ContainerQueue{
        Tasks: make(chan linux_virt.ContainerInfo, 100),
    }
    heap.Init(incus_unit.PortHeap)

    log.Println("Port heap allocation succeed.")

    var err error
    db.InitMongoDB()
    defer db.CloseMongoDB()
    incus_unit.IncusCli, err = client.ConnectIncusUnix("", nil)
    if err != nil {
        log.Fatalf("Failed to connect to Incus: %v", err)
    }

    // WorkQueue 초기화

    // HTTP 요청 초기화
    http_request.InitHttpRequest(incus_unit.WorkQueue)

    // 컨테이너 작업자 풀 시작
}

