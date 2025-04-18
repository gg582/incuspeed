
# 🖥️ LVirt Basic GUI Client

A graphical interface for the [LVirt Project](https://github.com/your-username/linuxVirtualization) — a lightweight container management platform using LXD/Incus.

This client allows users to securely communicate with the LVirt server over HTTPS and manage containers with ease.

---

## 🚀 Features

- Built with **KivyMD**
- Secure HTTPS communication using client-side certificate
- AES-encrypted messages and bcrypt-secured login
- Supports container state management (start, pause, resume, restart)
- Modern Material UI design

---

## 📦 Installation & Usage

* Disclaimer: This application's buildozer.specs has automatically generated. *
* Change /home/yjlee to your directory *

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/lvirt-client.git
cd lvirt-client
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate Client Certificate

This app requires a valid client certificate for encrypted HTTPS communication with the LVirt server.

🔐 **Important:**  
Use the `utils/keygen.sh` script included in the main [LVirt repository](https://github.com/your-username/linuxVirtualization) to generate the certificate.


### 4. Run the GUI App

```bash
python main.py
```

---

## 🔧 Supported Server Functions

This client communicates with the following LVirt server endpoints:

| Method | Endpoint     | Description               |
|--------|--------------|---------------------------|
| POST   | `/start`     | Start a container         |
| POST   | `/pause`     | Pause a running container |
| POST   | `/resume`    | Resume a paused container |
| POST   | `/restart`   | Restart a container       |

Other endpoints (`/create`, `/delete`, `/request`, etc.) are available and documented through Swagger:

📚 **Swagger Documentation**  
Access it via your server:  
`https://<your-domain>:32000/swagger/index.html`

---

## 🔐 Authentication

- Uses bcrypt to verify credentials.
- AES encryption for client-server message security.
- Certificates are required for communication.

---

## 🗂 Directory Overview

```text
lvirt-client/
├── certs/
│   ├── client.crt
│   └── client.key
├── main.py
├── requirements.txt
└── README.md
```

---

## 📝 Notes

- Make sure the LVirt server is running and accessible at the correct domain/port.
- Adjust `server_domain` and `https_port` settings in your code or config as needed.
- You must **generate your certificate before launching the app**.

---

## 📄 License

MIT License © 2025 LVirt Project

---

## 🙌 Contributing

Feel free to submit issues, pull requests, or suggestions!

