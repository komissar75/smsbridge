#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from dataclasses import dataclass
from typing import Optional


TRUE_VALUES = {"1", "true", "yes", "y", "on"}


def load_env_file(path: str = "/etc/smsbridge.env") -> None:
    """Load KEY=VALUE lines into os.environ without overriding existing values."""
    if not path or not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def env_str(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def env_str_any(names: list[str], default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = env_str(name)
        if value is not None:
            return value
    return default


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in TRUE_VALUES


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value not in (None, "") else default


def env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    return float(value) if value not in (None, "") else default


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    user: Optional[str]
    password: Optional[str]
    tls: bool

    @property
    def enabled(self) -> bool:
        return bool(self.host and self.port and self.user and self.password)


@dataclass(frozen=True)
class SmsDeliveryConfig:
    telegram_bot_token: str
    telegram_chat_id: str
    email_to: Optional[str]
    email_from: Optional[str]
    email_subject_prefix: str
    smtp: SmtpConfig


@dataclass(frozen=True)
class AdminAlertConfig:
    enabled: bool
    telegram_bot_token: Optional[str]
    telegram_chat_id: Optional[str]
    telegram_username_hint: Optional[str]
    email_to: Optional[str]
    email_from: Optional[str]
    email_subject_prefix: str
    smtp: SmtpConfig
    after_consecutive_runtime_failures: int
    repeat_seconds: int
    log_lines: int
    send_recovery: bool
    stale_heartbeat_seconds: int

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.enabled and self.telegram_bot_token and self.telegram_chat_id)

    @property
    def email_enabled(self) -> bool:
        return bool(self.enabled and self.email_to and self.smtp.enabled)


@dataclass(frozen=True)
class RuntimeConfig:
    modem_url: str
    count_poll_seconds: float
    poll_interval_seconds: float
    http_timeout_seconds: float
    max_fetch: int
    state_dir: str
    log_dir: str
    processed_file: str
    archive_file: str
    alert_state_file: str
    health_file: str
    log_file: str
    sms: SmsDeliveryConfig
    admin: AdminAlertConfig


def load_config(env_file: Optional[str] = "/etc/smsbridge.env") -> RuntimeConfig:
    if env_file:
        load_env_file(env_file)

    state_dir = env_str("STATE_DIR", "/var/lib/smsbridge")
    log_dir = env_str("LOG_DIR", "/var/log/smsbridge")

    sms_smtp = SmtpConfig(
        host=env_str_any(["SMS_SMTP_HOST", "SMTP_HOST"], "smtp.mail.ru") or "smtp.mail.ru",
        port=env_int("SMS_SMTP_PORT", env_int("SMTP_PORT", 587)),
        user=env_str_any(["SMS_SMTP_USER", "SMTP_USER"]),
        password=env_str_any(["SMS_SMTP_PASS", "SMTP_PASS"]),
        tls=env_bool("SMS_SMTP_TLS", env_bool("SMTP_TLS", True)),
    )

    sms = SmsDeliveryConfig(
        telegram_bot_token=env_str_any(["SMS_TELEGRAM_BOT_TOKEN", "TELEGRAM_BOT_TOKEN"], "") or "",
        telegram_chat_id=env_str_any(["SMS_TELEGRAM_CHAT_ID", "TELEGRAM_CHAT_ID"], "") or "",
        email_to=env_str_any(["SMS_EMAIL_TO", "EMAIL_TO"]),
        email_from=env_str_any(["SMS_EMAIL_FROM", "EMAIL_FROM"]),
        email_subject_prefix=env_str_any(["SMS_EMAIL_SUBJECT_PREFIX", "EMAIL_SUBJECT_PREFIX"], "[SMSBridge]") or "[SMSBridge]",
        smtp=sms_smtp,
    )

    admin_smtp = SmtpConfig(
        host=env_str("ADMIN_SMTP_HOST", sms_smtp.host) or sms_smtp.host,
        port=env_int("ADMIN_SMTP_PORT", sms_smtp.port),
        user=env_str("ADMIN_SMTP_USER", sms_smtp.user),
        password=env_str("ADMIN_SMTP_PASS", sms_smtp.password),
        tls=env_bool("ADMIN_SMTP_TLS", sms_smtp.tls),
    )

    admin = AdminAlertConfig(
        enabled=env_bool("ADMIN_ALERT_ENABLED", True),
        telegram_bot_token=env_str("ADMIN_TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=env_str("ADMIN_TELEGRAM_CHAT_ID"),
        telegram_username_hint=env_str("ADMIN_TELEGRAM_USERNAME_HINT"),
        email_to=env_str("ADMIN_EMAIL_TO"),
        email_from=env_str("ADMIN_EMAIL_FROM", sms.email_from),
        email_subject_prefix=env_str("ADMIN_EMAIL_SUBJECT_PREFIX", "[SMSBridge ALERT]") or "[SMSBridge ALERT]",
        smtp=admin_smtp,
        after_consecutive_runtime_failures=env_int("ADMIN_ALERT_AFTER_CONSECUTIVE_RUNTIME_FAILURES", 5),
        repeat_seconds=env_int("ADMIN_ALERT_REPEAT_SECONDS", 3600),
        log_lines=env_int("ADMIN_ALERT_LOG_LINES", 120),
        send_recovery=env_bool("ADMIN_ALERT_SEND_RECOVERY", True),
        stale_heartbeat_seconds=env_int("ADMIN_ALERT_STALE_HEARTBEAT_SECONDS", 600),
    )

    return RuntimeConfig(
        modem_url=(env_str("MODEM_URL", "http://192.168.8.1") or "http://192.168.8.1").rstrip("/"),
        count_poll_seconds=env_float("COUNT_POLL_SECONDS", 1.0),
        poll_interval_seconds=env_float("POLL_INTERVAL_SECONDS", 1.0),
        http_timeout_seconds=env_float("HTTP_TIMEOUT_SECONDS", 5.0),
        max_fetch=env_int("MAX_FETCH", 50),
        state_dir=state_dir or "/var/lib/smsbridge",
        log_dir=log_dir or "/var/log/smsbridge",
        processed_file=env_str("PROCESSED_FILE", os.path.join(state_dir or "/var/lib/smsbridge", "processed_hashes.json")) or "",
        archive_file=env_str("ARCHIVE_FILE", os.path.join(state_dir or "/var/lib/smsbridge", "sms_archive.jsonl")) or "",
        alert_state_file=env_str("ALERT_STATE_FILE", os.path.join(state_dir or "/var/lib/smsbridge", "alert_state.json")) or "",
        health_file=env_str("HEALTH_FILE", os.path.join(state_dir or "/var/lib/smsbridge", "health.json")) or "",
        log_file=env_str("LOG_FILE", os.path.join(log_dir or "/var/log/smsbridge", "smsbridge.log")) or "",
        sms=sms,
        admin=admin,
    )


def validate_for_daemon(config: RuntimeConfig) -> list[str]:
    errors: list[str] = []
    if not config.sms.telegram_bot_token or not config.sms.telegram_chat_id:
        errors.append("Missing SMS_TELEGRAM_BOT_TOKEN/SMS_TELEGRAM_CHAT_ID (or legacy TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID)")
    if config.sms.email_to and not config.sms.smtp.enabled:
        errors.append("SMS email recipient is set but SMTP credentials are incomplete")
    if config.admin.enabled:
        if not config.admin.telegram_enabled:
            errors.append("Admin Telegram alerting enabled but ADMIN_TELEGRAM_BOT_TOKEN/ADMIN_TELEGRAM_CHAT_ID are incomplete")
        if not config.admin.email_enabled:
            errors.append("Admin email alerting enabled but ADMIN_EMAIL_TO or SMTP credentials are incomplete")
    return errors
