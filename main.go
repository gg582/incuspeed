package main

import (
    client "github.com/lxc/incus/client"
    http_request "github.com/yoonjin67/linux_virt_unit/http_request"
    db "github.com/yoonjin67/linux_virt_unit/mongo_connect"
    incus_unit "github.com/yoonjin67/linux_virt_unit/incus_unit"
    "log"
)

// 전역 변수 선언

func main() {
    // AvailablePorts 초기화

    incus_unit.InitWorkQueue()
    var err error
    incus_unit.WorkQueue.Start(5) // five worker started 
    defer incus_unit.WorkQueue.Stop()
    db.InitMongoDB()
    defer db.CloseMongoDB()
    incus_unit.IncusCli, err = client.ConnectIncusUnix("", nil)
    if err != nil {
        log.Fatalf("Failed to connect to Incus: %v", err)
    }

    //Reset http request 
    http_request.InitHttpRequest()

}

