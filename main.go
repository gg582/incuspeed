package main

import (
        client "github.com/lxc/incus/client"
        http_request "github.com/yoonjin67/linux_virt_unit/http_request"
        db "github.com/yoonjin67/linux_virt_unit/mongo_connect"
        incus_unit "github.com/yoonjin67/linux_virt_unit/incus_unit"
        "log"

)

// @title Linux Virtualization API
// @version 1.0
// @description Linux Virtualization API with Incus.
// @host localhost:32000
// @BasePath /

func main() {
    incus_unit.InitWorkQueue()
    var err error
    incus_unit.WorkQueue.Start(24)
    defer incus_unit.WorkQueue.Stop()
    db.InitMongoDB()
    defer db.CloseMongoDB()
    incus_unit.IncusCli, err = client.ConnectIncusUnix("", nil)
    if err != nil {
            log.Fatalf("Failed to connect to Incus: %v", err)
    }

    http_request.InitHttpRequest()

}
