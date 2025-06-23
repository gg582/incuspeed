package main

import (
    "fmt"
    "os/exec"
)

// runSSH is responsible for managing the SSH service based on the system configuration.
func runSSH() {
    // Check if systemctl is available
    _, err := exec.LookPath("systemctl")
    if err != nil {
        // If systemctl is not found, check for /etc/rc.d or /etc/init.d directories
        if _, err := exec.Command("test", "-d", "/etc/rc.d").Output(); err == nil {
            fmt.Println("Found /etc/rc.d directory.")
            // Grant execute permission to rc.sshd and restart the service
            exec.Command("chmod", "+x", "/etc/rc.d/rc.sshd").Run()
            exec.Command("/etc/rc.d/rc.sshd", "restart").Run()
        } else if _, err := exec.Command("test", "-d", "/etc/init.d").Output(); err == nil {
            fmt.Println("Found /etc/init.d directory.")
            // Grant execute permission to /etc/init.d/ssh and restart the service
            exec.Command("chmod", "+x", "/etc/init.d/ssh").Run()
            exec.Command("/etc/init.d/ssh", "restart").Run()
        } else {
            // Grant execute permission to any ssh-related script in /etc/*.d/ and restart them
            fmt.Println("Found neither /etc/rc.d nor /etc/init.d directories.")
            exec.Command("chmod", "+x", "/etc/*.d/*ssh*").Run()
            exec.Command("/etc/*.d/*ssh*", "restart").Run()
        }
    } else {
        // If systemctl is available, restart and enable the ssh and sshd services
        fmt.Println("systemctl found. Restarting and enabling services...")
        exec.Command("systemctl", "restart", "sshd").Run()
        exec.Command("systemctl", "restart", "ssh").Run()
        exec.Command("systemctl", "enable", "ssh").Run()
        exec.Command("systemctl", "enable", "sshd").Run()
    }
}

func main() {
    // Call runSSH function to manage the SSH service
    runSSH()
}

