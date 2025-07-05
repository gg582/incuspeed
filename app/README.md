
# 🖥️ IncuSpeed Basic GUI Client

A graphical interface for the [IncuSpeed Project](https://github.com/gg582/incuspeed) — a lightweight container management platform using LXD/Incus.

This client allows users to securely communicate with the IncuSpeed server over HTTPS and manage containers with ease.

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
git clone https://github.com/gg582/incuspeed
cd app
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate Client Certificate

This app requires a valid client certificate for encrypted HTTPS communication with the IncuSpeed server.

🔐 **Important:**  
Use the `utils/keygen.sh` script included in the main [IncuSpeed repository](https://github.com/gg582/incuspeed) to generate the certificate.


### 4. Run the GUI App

You can see kivy's buildozer docs.
---

## 🔧 Supported Server Functions

This client communicates with documented endpoints(`/create`, `/delete`, `/request`, etc.);they are documented through Swagger:

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
app/
├── certs/
│   ├── ca.crt
├── main.py
├── requirements.txt
└── README.md
```

---

## 📝 Notes

- Make sure the IncuSpeed server is running and accessible at the correct domain/port.
- Adjust `server_domain` and `https_port` settings in your code or config as needed.
- You must **generate your certificate before launching the app**.

---

## 📄 License

MIT License © 2025 IncuSpeed Project

---

## 🙌 Contributing

Feel free to submit issues, pull requests, or suggestions!

