package main

import (
    client "github.com/lxc/incus/client"
    http_request "github.com/yoonjin67/linux_virt_unit/http_request"
    db "github.com/yoonjin67/linux_virt_unit/mongo_connect"
    incus_unit "github.com/yoonjin67/linux_virt_unit/incus_unit"
    "log"
    "container/heap"
)

// 전역 변수 선언

func main() {
    // AvailablePorts 초기화
    incus_unit.InitWorkQueue()
    incus_unit.AvailablePorts = &incus_unit.PortHeap{}
    incus_unit.UnavailablePorts = &incus_unit.PortHeap{}
    heap.Init(incus_unit.AvailablePorts)
    heap.Init(incus_unit.UnavailablePorts)

    log.Println("Port heap allocation succeed.")

    var err error
    incus_unit.WorkQueue.Start(5) // 5개의 작업자 시작
    defer incus_unit.WorkQueue.Stop()
    db.InitMongoDB()
    defer db.CloseMongoDB()
    incus_unit.IncusCli, err = client.ConnectIncusUnix("", nil)
    if err != nil {
        log.Fatalf("Failed to connect to Incus: %v", err)
    }

    // WorkQueue 초기화

    // HTTP 요청 초기화
    http_request.InitHttpRequest()

    // 컨테이너 작업자 풀 시작
}

