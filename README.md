# smsbridge
script to work with Huawei HiLink (E3372h) to read and forward sms

Huawei HiLink SMS → Telegram / Email
Полная инструкция по настройке (Debian, systemd, Python)
1. Постановка задачи и условия
Цель

Настроить на Debian-сервере сервис, который:

работает с USB-модемом Huawei HiLink (например E3372h)

мобильные данные на SIM отключены

модем используется только для приёма SMS

SMS:

читаются почти в реальном времени

корректно декодируются (русский язык)

пересылаются:

в Telegram

по email (SMTP, mail.ru)

сохраняются локально

после успешной доставки удаляются с модема

Ограничения и особенности Huawei HiLink

Модем работает в HiLink-режиме (RNDIS / CDC Ethernet)

Встроенный IP модема: 192.168.8.1

SMS API доступен по HTTP (/api/sms/*)

Huawei использует:

cookies

CSRF-токены (TokInfo)

дополнительные токены (/api/webserver/token)

ротацию токенов через HTTP-заголовки

Ошибки:

125002 — token invalid

125003 — session/token error (не фатально, но требует reinit)

100005 — неверный XML (лечится полным schema запроса)

2. Сетевая настройка Debian (КРИТИЧНО)
Задача

Модем не должен:

становиться default gateway

добавлять DNS

ломать доступ к серверу после reboot

Он нужен только для доступа к 192.168.8.1

2.1 Определение интерфейса модема
ip link


Обычно выглядит так:

enx0c5b8f279a64

2.2 Создание NetworkManager-профиля
sudo nmcli con add type ethernet \
  ifname enx0c5b8f279a64 \
  con-name hilink-local \
  ipv4.method manual \
  ipv4.addresses 192.168.8.2/24 \
  ipv6.method disabled

2.3 Ключевые параметры (ОБЯЗАТЕЛЬНО)
sudo nmcli con modify hilink-local \
  ipv4.never-default yes \
  ipv4.ignore-auto-dns yes \
  ipv4.ignore-auto-routes yes \
  connection.autoconnect yes \
  connection.autoconnect-priority -999


⚠️ Это предотвращает потерю сети после reboot

2.4 Проверка
nmcli con show hilink-local
ip route


В маршрутах должно быть:

192.168.8.0/24 dev enx0c5b8f279a64


И default route должен оставаться на основном интерфейсе.

3. Подготовка системы
3.1 Пользователь сервиса
sudo useradd -r -s /bin/false -d /var/lib/smsbridge smsbridge

3.2 Каталоги
sudo mkdir -p /opt/smsbridge /var/lib/smsbridge
sudo chown smsbridge:smsbridge /var/lib/smsbridge

4. Python virtualenv
sudo -u smsbridge python3 -m venv /opt/smsbridge/venv
sudo -u smsbridge /opt/smsbridge/venv/bin/pip install --upgrade pip
sudo -u smsbridge /opt/smsbridge/venv/bin/pip install requests

5. Скрипт smsbridge

Финальная версия smsbridge.py:

поддерживает:

/api/webserver/SesTokInfo

/api/webserver/token

ротацию токена из заголовков

корректно обрабатывает 125002 / 125003

использует полный XML schema для sms-list

гарантирует доставку до удаления SMS

📌 Файл размещается здесь:

/opt/smsbridge/smsbridge.py

sudo chown root:root /opt/smsbridge/smsbridge.py
sudo chmod 755 /opt/smsbridge/smsbridge.py

6. Конфигурация окружения
/etc/smsbridge.env
# ModemMODEM_URL=http://192.168.8.1

# Telegram
TELEGRAM_BOT_TOKEN=123456:ABCDEF...
TELEGRAM_CHAT_ID=-1001234567890

# Email (mail.ru SMTP)
EMAIL_TO=you@example.com
EMAIL_FROM=you@mail.ru
SMTP_HOST=smtp.mail.ru
SMTP_PORT=587
SMTP_USER=you@mail.ru
SMTP_PASS=APP_PASSWORD
SMTP_TLS=yes

# Polling
COUNT_POLL_SECONDS=1
POLL_INTERVAL_SECONDS=1

# State
STATE_DIR=/var/lib/smsbridge
sudo chown root:smsbridge /etc/smsbridge.env
sudo chmod 640 /etc/smsbridge.env

7. systemd-сервис
/etc/systemd/system/smsbridge.service
[Unit]
Description=Huawei HiLink SMS -> Telegram bridge (near real-time)
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
PrivateNetwork=false

[Install]
WantedBy=multi-user.target

Активация
sudo systemctl daemon-reload
sudo systemctl enable --now smsbridge

8. Проверка и эксплуатация
Логи
journalctl -u smsbridge -f -o cat


Ожидаемое поведение:

Huawei session initialized
Modem LocalUnread=1
Telegram delivered
Email delivered
Archived locally
Processed SMS ... (deleted)
