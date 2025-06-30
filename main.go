package main

import (
	"log"
	"os"
    "os/exec"
    "io"

	client "github.com/lxc/incus/client"
	http_request "github.com/gg582/linux_virt_unit/http_request"
	incus_unit "github.com/gg582/linux_virt_unit/incus_unit"
    . "github.com/gg582/linux_virt_unit"
	db "github.com/gg582/linux_virt_unit/mongo_connect"
)

// @title Linux Virtualization API
// @version 1.0
// @description Linux Virtualization API with Incus.
// @host localhost:32000
// @BasePath /

func main() {
    incus_unit.InitWorkQueue()
    var err error
    incus_unit.WorkQueue.Start(48)
    defer incus_unit.WorkQueue.Stop()
    db.InitMongoDB()
    defer db.CloseMongoDB()
    incus_unit.IncusCli, err = client.ConnectIncusUnix("", nil)
    if err != nil {
            log.Fatalf("Failed to connect to Incus: %v", err)
    }
    copyFile(LINUX_VIRT_PATH+"/backup.conf", NGINX_LOCATION)

	http_request.InitHttpRequest()

}

func copyFile(src string, dst string) {
    srcFile, err := os.Open(src)
    if err != nil {
        log.Printf("Failed to open backup source: %v", err)
        defer srcFile.Close()
    }

    dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
    if err != nil {
        log.Println("[FATAL]: Nginx config not found")
        log.Fatal(err)
        defer dstFile.Close()
    }

    _, err = io.Copy(dstFile, srcFile)
    if err != nil {
        log.Println("Failed to copy from backup.conf")
    }

    if exec.Command("nginx", "-s", "reload").Run() != nil {
        log.Println("failed to reload nginx")
    }
}
