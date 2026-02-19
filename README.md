# Huawei HiLink SMS Bridge

**Huawei E3372h → Telegram + Email (SMTP) on Debian**

## Overview

This project provides a **production-ready daemon** that:

* Connects to a **Huawei HiLink USB modem (E3372h and compatible)**
* Polls the modem **near real-time** for incoming SMS messages
* Decodes SMS correctly (including **Cyrillic / UCS-2**)
* Delivers messages to:

  * **Telegram chat**
  * **Email via SMTP (e.g. mail.ru)**
* Archives processed messages locally
* **Safely deletes SMS from the modem only after successful delivery**
* Runs as a hardened **systemd service**
* Works **without mobile data enabled on the SIM**
* Ensures the modem **never becomes the default network gateway**

---

## Design Constraints & Assumptions

### Modem

* Huawei **E3372h HiLink** (or similar HiLink firmware)
* Modem exposes web API at `http://192.168.8.1`
* SMS storage: **Local (modem)**, not SIM
* Mobile data **disabled** on SIM (SMS-only usage)

### Host system

* Debian (tested on Debian 11/12)
* NetworkManager enabled
* systemd available
* Server may be **remote-only (SSH)** → network misconfiguration must be avoided

### Key Huawei HiLink quirks handled

* Token expiration (`125002`)
* Session/token mismatch (`125003`)
* Token rotation via HTTP headers
* Additional token endpoint `/api/webserver/token`
* Reusable SMS `Index` values
* XML format sensitivity (`100005`)
* UCS-2 hex encoded SMS
* UTF-8 mojibake (`ÐÐ¾...`)

---

## Network Configuration (CRITICAL)

### Goal

The modem **must not**:

* Become the default gateway
* Provide DNS
* Break server connectivity after reboot

The modem interface is used **only** for local access to `192.168.8.1`.

---

### Identify the modem interface

```bash
ip link
```

Example:

```text
enx0c5b8f279a64
```

---

### Create a dedicated NetworkManager connection

```bash
nmcli con add type ethernet \
  ifname enx0c5b8f279a64 \
  con-name hilink-local \
  ipv4.method manual \
  ipv4.addresses 192.168.8.2/24 \
  ipv4.gateway "" \
  ipv4.dns "" \
  ipv6.method disabled
```

---

### Harden the connection (VERY IMPORTANT)

```bash
nmcli con modify hilink-local \
  connection.autoconnect yes \
  connection.autoconnect-priority -999 \
  ipv4.never-default yes \
  ipv4.ignore-auto-dns yes \
  ipv4.ignore-auto-routes yes
```

---

### Verify routing table

```bash
ip route
```

You **must** see:

* Default route via your real LAN interface
* `192.168.8.0/24` routed only via the modem interface
* **No default route via the modem**

---

## Service Architecture

```text
Huawei Modem (HiLink)
  ↓ HTTP API
Debian Server
  ↓ Python daemon (smsbridge)
Telegram API
Email SMTP (mail.ru)
```

---

## Installation

### 1. Create service user

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/smsbridge smsbridge
```

---

### 2. Create directories

```bash
sudo mkdir -p /opt/smsbridge /var/lib/smsbridge
sudo chown smsbridge:smsbridge /var/lib/smsbridge
```

---

### 3. Python virtual environment

```bash
sudo -u smsbridge python3 -m venv /opt/smsbridge/venv
sudo -u smsbridge /opt/smsbridge/venv/bin/pip install --upgrade pip
sudo -u smsbridge /opt/smsbridge/venv/bin/pip install requests
```

---

### 4. Install `smsbridge.py`

```bash
sudo cp smsbridge.py /opt/smsbridge/smsbridge.py
sudo chmod 755 /opt/smsbridge/smsbridge.py
```

(The final script includes **all Huawei token handling, decoding fixes, and cleanup logic**.)

---

## Configuration

### `/etc/smsbridge.env`

```env
# Modem
MODEM_URL=http://192.168.8.1

# Telegram
TELEGRAM_BOT_TOKEN=123456:ABCDEF
TELEGRAM_CHAT_ID=-1001234567890

# Email (optional)
EMAIL_TO=you@example.com
EMAIL_FROM=smsbridge@example.com

SMTP_HOST=smtp.mail.ru
SMTP_PORT=587
SMTP_USER=you@mail.ru
SMTP_PASS=app_password_here
SMTP_TLS=yes

# Polling
COUNT_POLL_SECONDS=1
POLL_INTERVAL_SECONDS=1

# Storage
STATE_DIR=/var/lib/smsbridge
```

Secure it:

```bash
sudo chown root:smsbridge /etc/smsbridge.env
sudo chmod 640 /etc/smsbridge.env
```

---

## systemd Service

### `/etc/systemd/system/smsbridge.service`

```ini
[Unit]
Description=Huawei HiLink SMS Bridge
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=smsbridge
Group=smsbridge
WorkingDirectory=/var/lib/smsbridge
EnvironmentFile=/etc/smsbridge.env
ExecStart=/opt/smsbridge/venv/bin/python /opt/smsbridge/smsbridge.py

Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/smsbridge
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
RestrictNamespaces=true
PrivateNetwork=false

[Install]
WantedBy=multi-user.target
```

---

### Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now smsbridge
```

---

## Monitoring

### Live logs

```bash
journalctl -u smsbridge -f -o cat
```

Expected behavior:

```text
Huawei session initialized
Modem LocalUnread=1
Telegram delivered
Email delivered
Archived locally
Processed SMS (delivered+archived+deleted)
Modem LocalUnread=0
```

---

## Failure Semantics (IMPORTANT)

The daemon guarantees:

* ❌ SMS is **NOT deleted** if:

  * Telegram delivery fails
  * Email delivery fails
  * Archive write fails
* ✅ SMS is deleted **only after all deliveries succeed**
* Token/session errors are retried safely
* Duplicate SMS is avoided via **content fingerprinting**

---

## Local Storage

```text
/var/lib/smsbridge/
├── processed_hashes.json   # Deduplication state
└── sms_archive.jsonl       # Full SMS archive (JSON lines)
```

---

## Security Notes

* Runs as **unprivileged user**
* No shell access
* No modem exposure beyond `192.168.8.0/24`
* systemd hardening enabled
* Secrets stored only in root-owned env file

---

## Tested With

* Debian 11 / 12
* Huawei E3372h HiLink
* SMS-only SIM
* Telegram Bot API
* SMTP mail.ru (STARTTLS)

---

## License

MIT (or adapt as needed)

---

## Final Notes

This project intentionally avoids:

* Serial/AT mode
* ModemManager
* PPP / data connections
* Default routing via USB modem

It is designed specifically for **reliable SMS ingestion on headless Linux servers**.

If you deploy this on a remote server, **always configure the network interface first**, or you risk locking yourself out.

---

