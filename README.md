# Huawei HiLink SMS Bridge

Huawei E3372h/HiLink SMS bridge for Debian/systemd.

The daemon reads incoming SMS from a Huawei HiLink modem, delivers them to a configured SMS recipient via Telegram and optional email, archives them locally, and deletes them from the modem only after successful delivery. Administrator alerts are separate from normal SMS delivery.

## Roles

### SMS recipient

The SMS recipient receives forwarded SMS messages.

Preferred config variables:

```env
SMS_TELEGRAM_BOT_TOKEN=
SMS_TELEGRAM_CHAT_ID=
SMS_EMAIL_TO=
SMS_EMAIL_FROM=
SMS_SMTP_HOST=
SMS_SMTP_PORT=587
SMS_SMTP_USER=
SMS_SMTP_PASS=
SMS_SMTP_TLS=yes
```

Legacy variables are still supported for compatibility:

```env
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
EMAIL_TO=
EMAIL_FROM=
SMTP_HOST=
SMTP_PORT=
SMTP_USER=
SMTP_PASS=
SMTP_TLS=
```

### Service administrator

The administrator receives only service health alerts, not copies of normal SMS messages.

Admin Telegram alerts use a separate bot:

```env
ADMIN_ALERT_ENABLED=yes
ADMIN_TELEGRAM_BOT_TOKEN=
ADMIN_TELEGRAM_CHAT_ID=
ADMIN_TELEGRAM_USERNAME_HINT=@example
```

Admin email alerts use the same SMTP account by default. Leave `ADMIN_SMTP_*` empty to fall back to `SMS_SMTP_*` / legacy `SMTP_*`:

```env
ADMIN_EMAIL_TO=
ADMIN_EMAIL_FROM=
ADMIN_EMAIL_SUBJECT_PREFIX=[SMSBridge ALERT]
ADMIN_SMTP_HOST=
ADMIN_SMTP_PORT=587
ADMIN_SMTP_USER=
ADMIN_SMTP_PASS=
ADMIN_SMTP_TLS=yes
```

Telegram Bot API sends to `chat_id`, not directly to a username. `ADMIN_TELEGRAM_USERNAME_HINT` is documentation only.

## Failure and alerting model

Runtime modem/API failures do not necessarily crash the daemon. The daemon tracks consecutive failures and sends administrator alerts when SMS polling cannot recover automatically.

Admin Telegram alert:

- short;
- no SMS content;
- no logs;
- points administrator to email for details.

Admin email alert:

- detailed;
- includes failure counters and recent sanitized technical logs;
- does not include SMS archive contents or secrets.

Relevant settings:

```env
ADMIN_ALERT_AFTER_CONSECUTIVE_RUNTIME_FAILURES=5
ADMIN_ALERT_REPEAT_SECONDS=3600
ADMIN_ALERT_LOG_LINES=120
ADMIN_ALERT_SEND_RECOVERY=yes
ADMIN_ALERT_STALE_HEARTBEAT_SECONDS=600
```

The daemon also writes a heartbeat to:

```text
/var/lib/smsbridge/health.json
```

`smsbridge_healthcheck.py` can be run by a systemd timer as a second layer of protection. It alerts when the heartbeat is stale.

Alert rate-limiting state is stored in:

```text
/var/lib/smsbridge/alert_state.json
```

## Huawei modem network configuration

The modem must not become the default gateway or DNS provider.

Example NetworkManager profile:

```bash
nmcli con add type ethernet \
  ifname enx0c5b8f279a64 \
  con-name hilink-local \
  ipv4.method manual \
  ipv4.addresses 192.168.8.2/24 \
  ipv4.gateway "" \
  ipv4.dns "" \
  ipv6.method disabled

nmcli con modify hilink-local \
  connection.autoconnect yes \
  connection.autoconnect-priority -999 \
  ipv4.never-default yes \
  ipv4.ignore-auto-dns yes \
  ipv4.ignore-auto-routes yes
```

Verify:

```bash
ip route get 192.168.8.1
curl -sS -m 5 http://192.168.8.1/html/index.html
```

## Installation

Create service user and directories:

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/smsbridge smsbridge
sudo mkdir -p /opt/smsbridge /var/lib/smsbridge /var/log/smsbridge
sudo chown smsbridge:smsbridge /var/lib/smsbridge /var/log/smsbridge
```

Create virtual environment:

```bash
sudo -u smsbridge python3 -m venv /opt/smsbridge/venv
sudo -u smsbridge /opt/smsbridge/venv/bin/pip install --upgrade pip
sudo -u smsbridge /opt/smsbridge/venv/bin/pip install requests
```

Install code:

```bash
sudo cp smsbridge*.py /opt/smsbridge/
sudo chmod 755 /opt/smsbridge/smsbridge*.py
```

Install private config:

```bash
sudo cp smsbridge.env.example /etc/smsbridge.env
sudo chown root:smsbridge /etc/smsbridge.env
sudo chmod 640 /etc/smsbridge.env
sudo editor /etc/smsbridge.env
```

Install systemd units:

```bash
sudo cp smsbridge.service /etc/systemd/system/smsbridge.service
sudo cp smsbridge-alert@.service /etc/systemd/system/smsbridge-alert@.service
sudo cp smsbridge-healthcheck.service /etc/systemd/system/smsbridge-healthcheck.service
sudo cp smsbridge-healthcheck.timer /etc/systemd/system/smsbridge-healthcheck.timer
sudo cp logrotate.smsbridge /etc/logrotate.d/smsbridge
sudo systemctl daemon-reload
sudo systemctl enable --now smsbridge.service
sudo systemctl enable --now smsbridge-healthcheck.timer
```

## Testing

Syntax check:

```bash
python3 -m py_compile smsbridge*.py
```

Send a test administrator alert:

```bash
sudo -u smsbridge /opt/smsbridge/venv/bin/python \
  /opt/smsbridge/smsbridge_alert.py --source test --message "test admin alert"
```

Expected:

- administrator receives a short Telegram message via the admin bot;
- administrator receives detailed email;
- normal SMS recipient receives nothing.

Runtime modem failure test:

1. Temporarily set `MODEM_URL=http://192.168.8.254`.
2. Restart `smsbridge.service`.
3. After `ADMIN_ALERT_AFTER_CONSECUTIVE_RUNTIME_FAILURES`, administrator alert should be sent.
4. Restore `MODEM_URL=http://192.168.8.1`.
5. Recovery alert should be sent after polling succeeds again.

Systemd failure test:

Use a controlled test environment or temporary bad `ExecStart`; after start-limit failure, `smsbridge-alert@.service` should notify the administrator.

## Safety rules

Do not commit:

- `/etc/smsbridge.env`;
- real Telegram bot tokens;
- real Telegram chat IDs;
- SMTP passwords;
- modem cookies/session/CSRF tokens;
- `sms_archive.jsonl`;
- `processed_hashes.json`;
- `alert_state.json`;
- `health.json`;
- logs containing operational data.

The repository contains `smsbridge.env.example` only.

## Failure semantics

SMS is not deleted from the modem if:

- Telegram delivery to the SMS recipient fails;
- configured email delivery to the SMS recipient fails;
- local archive write fails.

SMS is deleted only after all configured delivery/archive steps succeed.

Duplicate processing is prevented with a SHA256 fingerprint of `phone|date|content`, because Huawei `Index` values can be reused.
