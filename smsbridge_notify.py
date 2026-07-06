#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import smtplib
from email.message import EmailMessage
from typing import Optional

import requests

from smsbridge_config import SmtpConfig


def send_telegram_message(bot_token: str, chat_id: str, text: str, timeout: float = 5.0) -> None:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    response = requests.post(url, data={"chat_id": chat_id, "text": text}, timeout=timeout)
    response.raise_for_status()


def send_email_message(
    smtp: SmtpConfig,
    to_addr: str,
    subject: str,
    body: str,
    from_addr: Optional[str] = None,
    timeout: float = 15.0,
) -> None:
    if not smtp.enabled:
        raise RuntimeError("SMTP config is incomplete")

    msg = EmailMessage()
    msg["To"] = to_addr
    msg["From"] = from_addr or smtp.user
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(smtp.host, smtp.port, timeout=timeout) as server:
        if smtp.tls:
            server.starttls()
        server.login(smtp.user, smtp.password)
        server.send_message(msg)
