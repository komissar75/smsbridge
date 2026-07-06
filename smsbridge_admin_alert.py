#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import socket
from datetime import datetime, timezone
from typing import Iterable, Optional

from smsbridge_config import RuntimeConfig
from smsbridge_notify import send_email_message, send_telegram_message
from smsbridge_sanitize import sanitize_lines, sanitize_text
from smsbridge_state import parse_iso, read_json, write_json_atomic


log = logging.getLogger("smsbridge.alert")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _host() -> str:
    return socket.gethostname()


def _read_tail(path: str, max_lines: int) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return lines[-max_lines:]
    except Exception as e:
        return [f"Failed to read log file {path}: {e}"]


class AdminAlerter:
    def __init__(self, config: RuntimeConfig):
        self.config = config

    def _state(self) -> dict:
        data = read_json(self.config.alert_state_file, {})
        return data if isinstance(data, dict) else {}

    def _save_state(self, state: dict) -> None:
        write_json_atomic(self.config.alert_state_file, state)

    def _can_send(self, key: str, force: bool = False) -> bool:
        if force:
            return True
        state = self._state()
        item = state.get(key, {})
        last = parse_iso(item.get("last_sent_at") if isinstance(item, dict) else None)
        if last is None:
            return True
        return (_now() - last).total_seconds() >= self.config.admin.repeat_seconds

    def _mark_sent(self, key: str) -> None:
        state = self._state()
        item = state.get(key, {})
        if not isinstance(item, dict):
            item = {}
        item["last_sent_at"] = _now().isoformat()
        state[key] = item
        self._save_state(state)

    def _send(self, key: str, telegram_text: str, email_subject: str, email_body: str, force: bool = False) -> bool:
        if not self.config.admin.enabled:
            log.warning("Admin alert suppressed because ADMIN_ALERT_ENABLED is false: %s", key)
            return False
        if not self._can_send(key, force=force):
            log.warning("Admin alert suppressed by rate limit: %s", key)
            return False

        sent_any = False
        telegram_text = sanitize_text(telegram_text)
        email_subject = sanitize_text(email_subject)
        email_body = sanitize_text(email_body)

        if self.config.admin.telegram_enabled:
            try:
                send_telegram_message(
                    self.config.admin.telegram_bot_token or "",
                    self.config.admin.telegram_chat_id or "",
                    telegram_text,
                    timeout=self.config.http_timeout_seconds,
                )
                sent_any = True
                log.info("Admin Telegram alert sent: %s", key)
            except Exception as e:
                log.error("Failed to send admin Telegram alert (%s): %s", key, e)
        else:
            log.warning("Admin Telegram alert not configured")

        if self.config.admin.email_enabled:
            try:
                send_email_message(
                    self.config.admin.smtp,
                    self.config.admin.email_to or "",
                    email_subject,
                    email_body,
                    from_addr=self.config.admin.email_from,
                )
                sent_any = True
                log.info("Admin email alert sent: %s", key)
            except Exception as e:
                log.error("Failed to send admin email alert (%s): %s", key, e)
        else:
            log.warning("Admin email alert not configured")

        if sent_any:
            self._mark_sent(key)
        return sent_any

    def _common_report(
        self,
        source: str,
        severity: str,
        problem: str,
        details: Optional[str] = None,
        recent_logs: Optional[Iterable[str]] = None,
    ) -> str:
        log_lines = list(recent_logs or [])
        if not log_lines:
            log_lines = _read_tail(self.config.log_file, self.config.admin.log_lines)
        log_lines = sanitize_lines(log_lines)

        body = [
            "SMSBridge admin alert",
            "",
            f"Host: {_host()}",
            "Service: smsbridge.service",
            f"Time: {_now().isoformat()}",
            f"Source: {source}",
            f"Severity: {severity}",
            "",
            "Problem:",
            sanitize_text(problem),
            "",
            "Configuration:",
            f"MODEM_URL: {self.config.modem_url}",
            f"State dir: {self.config.state_dir}",
            f"Log file: {self.config.log_file}",
            "",
        ]
        if details:
            body.extend(["Details:", sanitize_text(details), ""])
        body.extend(
            [
                "Recent sanitized service log:",
                *log_lines,
                "",
                "Suggested checks:",
                "systemctl status smsbridge.service --no-pager",
                "journalctl -u smsbridge.service -n 120 --no-pager",
                f"ip route get {self.config.modem_url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]}",
                "ping -c 3 -W 2 192.168.8.1",
                "curl -sS -m 5 http://192.168.8.1/html/index.html",
            ]
        )
        return "\n".join(body)

    def runtime_critical(
        self,
        consecutive_failures: int,
        last_error: str,
        recent_logs: Optional[Iterable[str]] = None,
        force: bool = False,
    ) -> bool:
        host = _host()
        short = (
            f"SMSBridge ALERT: {host}\n"
            f"Cannot read SMS from modem after {consecutive_failures} failures.\n"
            "Check email for details."
        )
        subject = f"{self.config.admin.email_subject_prefix} {host}: runtime SMS polling failure"
        body = self._common_report(
            source="runtime",
            severity="critical",
            problem="Cannot read SMS from Huawei modem.",
            details=f"Consecutive runtime failures: {consecutive_failures}\nLast error: {last_error}",
            recent_logs=recent_logs,
        )
        return self._send("runtime_modem_failure", short, subject, body, force=force)

    def recovery(self, recent_logs: Optional[Iterable[str]] = None, force: bool = False) -> bool:
        if not self.config.admin.send_recovery:
            return False
        host = _host()
        short = f"SMSBridge RECOVERY: {host}\nModem polling is healthy again."
        subject = f"{self.config.admin.email_subject_prefix} {host}: service recovered"
        body = self._common_report(
            source="runtime",
            severity="recovery",
            problem="Huawei modem polling recovered.",
            recent_logs=recent_logs,
        )
        return self._send("runtime_modem_recovery", short, subject, body, force=force)

    def systemd_failure(self, unit: str, message: Optional[str] = None, force: bool = False) -> bool:
        host = _host()
        short = (
            f"SMSBridge ALERT: {host}\n"
            f"{unit} failed after restarts.\n"
            "Check email for details."
        )
        subject = f"{self.config.admin.email_subject_prefix} {host}: {unit} failed"
        body = self._common_report(
            source="systemd",
            severity="critical",
            problem=f"{unit} failed to start or crashed repeatedly.",
            details=message,
        )
        return self._send("systemd_failure", short, subject, body, force=force)

    def healthcheck_failure(self, age_seconds: float, last_error: Optional[str], force: bool = False) -> bool:
        host = _host()
        short = (
            f"SMSBridge ALERT: {host}\n"
            f"No successful modem poll for {int(age_seconds)} seconds.\n"
            "Check email for details."
        )
        subject = f"{self.config.admin.email_subject_prefix} {host}: stale modem polling heartbeat"
        body = self._common_report(
            source="healthcheck",
            severity="critical",
            problem="smsbridge health heartbeat is stale.",
            details=f"Heartbeat age seconds: {age_seconds:.1f}\nLast error: {last_error or 'n/a'}",
        )
        return self._send("healthcheck_stale_heartbeat", short, subject, body, force=force)

    def test(self, message: str = "test admin alert", force: bool = True) -> bool:
        host = _host()
        short = f"SMSBridge TEST: {host}\n{message}"
        subject = f"{self.config.admin.email_subject_prefix} {host}: test alert"
        body = self._common_report(
            source="test",
            severity="test",
            problem=message,
            details="This is a manual admin alert delivery test.",
        )
        return self._send("test_alert", short, subject, body, force=force)
