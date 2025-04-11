# 🐧 Linux Virtualization RestAPI Server and Front-End App

> **A super-lightweight LXD/Incus container management GUI for Linux systems**  
> Current Distro: **🟣 Ubuntu 24.04**

---

## 🚀 Getting Started – Server Setup

### 📦 Installation Steps

1. **Clone this repository**
   ```bash
   git clone https://your-repo-url
   cd your-repo-name
   ```

2. **Run installation commands**
   ```bash
   make
   ./initial_setup.sh --reconfigure-incus
   systemctl start --now linuxVirtualization
   ```

   > ⚠️ **WARNING:**  
   > This process **overwrites your Nginx configuration**.  
   > Be sure to modify `nginx.conf` from this repo before running the setup script.

3. **After setup**
   - Default SSH & Xrdp ports will be assigned automatically.
   - Incus containers will be managed via a reverse-proxy (Nginx).

---

## 🖥 GUI Application Usage

### ✅ Quick Steps

1. **Navigate to the application directory**
   ```bash
   cd app
   ```

2. **Run the GUI application**
   ```bash
   python3 main.py
   ```

3. **Login with default credentials**
   - **Username:** *username from Front-end app*
   - **Password:** *password from Front-end app*  
     > ⚠️ Change this password immediately after your first login!

---

## 🧠 Back-End Information

- Written in **Go**, optimized for Linux server orchestration.
- All container operations (create, stop, start, etc.) are securely managed via the back-end.

### 🔧 Build the back-end binary

```bash
make
```

---

## 🧱 Virtual Machine Management

- Powered by **LXD/Incus containers**
- Integrated with Nginx reverse-proxy (experimental!)
- Containers are isolated, and each is assigned its own port.

> ⚠️ **Note:** Reverse proxy logic is still under active development. You may experience unstable behavior when using multiple container ports simultaneously.

---

## 📁 Directory Structure Overview

```text
.
├── main.go           # Go-based Incus management server
├── app/               # Kivy-based GUI app (Python)
├── nginx.conf         # Default Nginx configuration (can be replaced)
├── initial_setup.sh   # Shell script for system setup
├── Makefile           # Build instructions
└── README.md          # This file
```

---

## 📜 TODO
- Support for other distributions
- Incus integration for RestAPI /create path
## 📜 NOTE
- Default domain is hobbies.yoonjin2.kr.
- If you are installing this, please change URL prefix.
- You can find prefixes by this command.
```bash
grep yoonjin2 $(find . -type f)
```
 
---

## 🤝 Contributing

Pull requests are welcome! If you find any issues or have improvements, feel free to open a PR or issue.

---

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
