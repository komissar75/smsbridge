#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Huawei HiLink SMS → Telegram + Email bridge.

The daemon keeps normal SMS delivery separate from administrator alerting:
- SMS delivery goes to the configured SMS recipient.
- Administrator alerts go to a separate admin Telegram bot/chat and admin email.
- Runtime modem/API failures are detected inside the daemon.
- Startup/crash failures can be reported by smsbridge_alert.py through systemd OnFailure.
"""

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urljoin
from xml.etree import ElementTree as ET

import requests

from smsbridge_admin_alert import AdminAlerter
from smsbridge_config import RuntimeConfig, load_config, validate_for_daemon
from smsbridge_logging import setup_logging
from smsbridge_notify import send_email_message, send_telegram_message
from smsbridge_state import now_iso, write_json_atomic


log = logging.getLogger("smsbridge")


EP_INDEX_HTML = "/html/index.html"
EP_SES_TOK = "/api/webserver/SesTokInfo"
EP_WEB_TOKEN = "/api/webserver/token"
EP_SMS_COUNT = "/api/sms/sms-count"
EP_SMS_LIST = "/api/sms/sms-list"
EP_SET_READ = "/api/sms/set-read"
EP_DELETE_SMS = "/api/sms/delete-sms"

HUAWEI_ERR_125002 = "125002"
HUAWEI_ERR_125003 = "125003"


@dataclass
class SmsMessage:
    index: int
    phone: str
    content: str
    date: str
    smstat: str


class HuaweiSessionError(Exception):
    """Token/session invalid -> reinit needed."""


def ensure_state_dir(config: RuntimeConfig) -> None:
    os.makedirs(config.state_dir, exist_ok=True)


def load_processed_hashes(config: RuntimeConfig) -> set[str]:
    ensure_state_dir(config)
    try:
        if not os.path.exists(config.processed_file):
            return set()
        with open(config.processed_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("hashes"), list):
            return set(str(x) for x in data["hashes"])
        if isinstance(data, list):
            return set(str(x) for x in data)
        return set()
    except Exception as e:
        log.warning("Failed to load processed state (%s): %s; starting empty", config.processed_file, e)
        return set()


def save_processed_hashes(config: RuntimeConfig, hashes: set[str]) -> None:
    payload = {"hashes": sorted(hashes)}
    write_json_atomic(config.processed_file, payload)


def append_archive(config: RuntimeConfig, msg: SmsMessage, fp: str) -> None:
    ensure_state_dir(config)
    rec = {
        "archived_at": datetime.now(timezone.utc).isoformat(),
        "fingerprint": fp,
        "index": msg.index,
        "phone": msg.phone,
        "date": msg.date,
        "content": msg.content,
        "smstat": msg.smstat,
    }
    with open(config.archive_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def write_health(config: RuntimeConfig, **updates: object) -> None:
    payload = {
        "updated_at": now_iso(),
        **updates,
    }
    write_json_atomic(config.health_file, payload)


def fix_mojibake_utf8(text: str) -> str:
    if not text:
        return ""
    if "Ð" in text or "Ñ" in text:
        try:
            return text.encode("latin1").decode("utf-8")
        except Exception:
            return text
    return text


def decode_sms_content(text: str) -> str:
    if not text:
        return ""
    text = fix_mojibake_utf8(text)
    s = text.strip()
    if len(s) >= 8 and (len(s) % 4 == 0) and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            return bytes.fromhex(s).decode("utf-16-be")
        except Exception:
            return text
    return text


def sms_fingerprint(msg: SmsMessage) -> str:
    raw = f"{msg.phone}|{msg.date}|{msg.content}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_xml_bytes(data: bytes) -> ET.Element:
    return ET.fromstring(data)


def extract_error_code(root: ET.Element) -> Optional[str]:
    if root.tag.lower() == "error":
        code = root.findtext("code")
        return code.strip() if code else None
    err = root.find(".//error")
    if err is not None:
        code = err.findtext("code")
        return code.strip() if code else None
    return None


class HuaweiClient:
    def __init__(self, base_url: str, timeout: float, max_fetch: int):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_fetch = max_fetch
        self.sess = requests.Session()
        self.token: Optional[str] = None
        self.token_alt: Optional[str] = None

    def _url(self, path: str) -> str:
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def _capture_token_from_headers(self, response: requests.Response) -> None:
        for key in (
            "__RequestVerificationToken",
            "__requestverificationtoken",
            "__RequestVerificationTokenone",
            "__RequestVerificationTokenOne",
            "__RequestVerificationTokentwo",
            "__RequestVerificationTokenTwo",
        ):
            value = response.headers.get(key)
            if value and value.strip():
                parts = [p for p in value.strip().split("#") if p]
                if parts:
                    self.token = parts[0]
                    if len(parts) > 1:
                        self.token_alt = parts[1]
                return

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/xml"}
        if self.token:
            headers["__RequestVerificationToken"] = self.token
        return headers

    def _raise_if_session_error(self, code: Optional[str], where: str) -> None:
        if code in (HUAWEI_ERR_125002, HUAWEI_ERR_125003):
            raise HuaweiSessionError(f"{where} session/token error {code}")

    def init_session(self) -> None:
        r1 = self.sess.get(self._url(EP_INDEX_HTML), timeout=self.timeout)
        r1.raise_for_status()
        self._capture_token_from_headers(r1)

        r2 = self.sess.get(self._url(EP_SES_TOK), timeout=self.timeout)
        r2.raise_for_status()
        self._capture_token_from_headers(r2)

        root = parse_xml_bytes(r2.content)
        code = extract_error_code(root)
        if code:
            raise RuntimeError(f"SesTokInfo returned error code {code}")

        token = root.findtext(".//TokInfo")
        if token and token.strip():
            self.token = token.strip()

        r3 = self.sess.get(self._url(EP_WEB_TOKEN), timeout=self.timeout)
        r3.raise_for_status()
        self._capture_token_from_headers(r3)

        root3 = parse_xml_bytes(r3.content)
        code3 = extract_error_code(root3)
        if code3:
            log.info("webserver/token returned code=%s (ignored)", code3)
        else:
            token3 = root3.findtext(".//token") or root3.findtext(".//Token")
            if token3 and token3.strip():
                self.token = token3.strip()

        if not self.token:
            raise RuntimeError("Failed to obtain verification token from modem")
        log.info("Huawei session initialized")

    def sms_count_unread(self) -> int:
        response = self.sess.get(self._url(EP_SMS_COUNT), headers=self._headers(), timeout=self.timeout)
        response.raise_for_status()
        self._capture_token_from_headers(response)

        root = parse_xml_bytes(response.content)
        code = extract_error_code(root)
        self._raise_if_session_error(code, "sms-count")
        if code:
            raise RuntimeError(f"sms-count returned error code {code}")
        unread = root.findtext(".//LocalUnread")
        if unread is None:
            raise RuntimeError("sms-count missing LocalUnread")
        return int(unread.strip())

    def sms_list_unread(self) -> List[SmsMessage]:
        body = f"""<?xml version="1.0" encoding="UTF-8"?>
<request>
  <PageIndex>1</PageIndex>
  <ReadCount>{self.max_fetch}</ReadCount>
  <BoxType>1</BoxType>
  <SortType>0</SortType>
  <Ascending>0</Ascending>
  <UnreadPreferred>1</UnreadPreferred>
</request>"""
        response = self.sess.post(
            self._url(EP_SMS_LIST),
            headers=self._headers(),
            data=body.encode("utf-8"),
            timeout=self.timeout,
        )
        response.raise_for_status()
        self._capture_token_from_headers(response)

        root = parse_xml_bytes(response.content)
        code = extract_error_code(root)
        self._raise_if_session_error(code, "sms-list")
        if code:
            raise RuntimeError(f"sms-list returned error code {code}")

        messages = root.find(".//Messages")
        if messages is None:
            return []

        out: List[SmsMessage] = []
        for node in messages.findall(".//Message"):
            smstat = (node.findtext("Smstat") or "").strip()
            if smstat != "0":
                continue
            try:
                index = int((node.findtext("Index") or "").strip())
            except Exception:
                continue
            out.append(
                SmsMessage(
                    index=index,
                    phone=(node.findtext("Phone") or "").strip(),
                    content=decode_sms_content((node.findtext("Content") or "").strip()),
                    date=(node.findtext("Date") or "").strip(),
                    smstat="0",
                )
            )
        return out

    def set_read(self, index: int) -> None:
        body = f"""<?xml version="1.0" encoding="UTF-8"?><request><Index>{index}</Index></request>"""
        response = self.sess.post(
            self._url(EP_SET_READ),
            headers=self._headers(),
            data=body.encode("utf-8"),
            timeout=self.timeout,
        )
        response.raise_for_status()
        self._capture_token_from_headers(response)
        root = parse_xml_bytes(response.content)
        code = extract_error_code(root)
        self._raise_if_session_error(code, "set-read")
        if code:
            log.info("set-read returned code=%s for index=%d (ignored)", code, index)

    def delete_sms(self, index: int) -> None:
        body = f"""<?xml version="1.0" encoding="UTF-8"?><request><Index>{index}</Index></request>"""
        response = self.sess.post(
            self._url(EP_DELETE_SMS),
            headers=self._headers(),
            data=body.encode("utf-8"),
            timeout=self.timeout,
        )
        response.raise_for_status()
        self._capture_token_from_headers(response)
        root = parse_xml_bytes(response.content)
        code = extract_error_code(root)
        self._raise_if_session_error(code, "delete-sms")
        if code:
            log.info("delete-sms returned code=%s for index=%d (ignored)", code, index)


class RuntimeHealth:
    def __init__(self, config: RuntimeConfig, alerter: AdminAlerter, recent_log_lines):
        self.config = config
        self.alerter = alerter
        self.recent_log_lines = recent_log_lines
        self.consecutive_failures = 0
        self.was_critical = False
        self.last_error: Optional[str] = None
        self.last_successful_modem_poll: Optional[str] = None

    def success(self) -> None:
        self.last_successful_modem_poll = now_iso()
        write_health(
            self.config,
            last_successful_modem_poll=self.last_successful_modem_poll,
            consecutive_failures=0,
            last_error=None,
        )
        if self.was_critical:
            self.alerter.recovery(recent_logs=list(self.recent_log_lines))
        self.consecutive_failures = 0
        self.was_critical = False
        self.last_error = None

    def failure(self, error: Exception) -> None:
        self.consecutive_failures += 1
        self.last_error = str(error)
        write_health(
            self.config,
            last_successful_modem_poll=self.last_successful_modem_poll,
            consecutive_failures=self.consecutive_failures,
            last_error=self.last_error,
        )
        if self.consecutive_failures >= self.config.admin.after_consecutive_runtime_failures:
            self.was_critical = True
            self.alerter.runtime_critical(
                self.consecutive_failures,
                self.last_error,
                recent_logs=list(self.recent_log_lines),
            )


def send_sms_telegram(config: RuntimeConfig, msg: SmsMessage) -> None:
    text = (
        "📩 SMS\n"
        f"From: {msg.phone}\n"
        f"Date: {msg.date}\n"
        f"Text: {msg.content}\n"
        f"Index: {msg.index}"
    )
    send_telegram_message(
        config.sms.telegram_bot_token,
        config.sms.telegram_chat_id,
        text,
        timeout=config.http_timeout_seconds,
    )


def send_sms_email(config: RuntimeConfig, msg: SmsMessage) -> None:
    if not config.sms.email_to:
        return
    subject = f"{config.sms.email_subject_prefix} SMS from {msg.phone} @ {msg.date}"
    body = f"From: {msg.phone}\nDate: {msg.date}\n\n{msg.content}\n\nIndex: {msg.index}\n"
    send_email_message(config.sms.smtp, config.sms.email_to, subject, body, from_addr=config.sms.email_from)


def cleanup_modem_message(modem: HuaweiClient, msg: SmsMessage) -> bool:
    for attempt in (1, 2):
        try:
            modem.set_read(msg.index)
            modem.delete_sms(msg.index)
            return True
        except HuaweiSessionError as e:
            log.warning("%s; reinitializing session (cleanup attempt %d)", e, attempt)
            modem.init_session()
    return False


def main() -> int:
    config = load_config("/etc/smsbridge.env")
    recent_handler = setup_logging(
        config.log_file,
        level_name=os.environ.get("LOG_LEVEL", "INFO"),
        recent_lines=config.admin.log_lines,
    )

    errors = validate_for_daemon(config)
    if errors:
        for error in errors:
            log.error("Configuration error: %s", error)
        AdminAlerter(config).systemd_failure("smsbridge.service", message="\n".join(errors), force=True)
        return 2

    log.info("smsbridge starting (MODEM_URL=%s)", config.modem_url)

    processed = load_processed_hashes(config)
    log.info("Loaded %d processed fingerprints", len(processed))

    alerter = AdminAlerter(config)
    health = RuntimeHealth(config, alerter, recent_handler.lines)
    modem = HuaweiClient(config.modem_url, config.http_timeout_seconds, config.max_fetch)

    while True:
        try:
            modem.init_session()
            health.success()
            break
        except Exception as e:
            log.error("Failed to init modem session: %s; retrying in 5s", e)
            health.failure(e)
            time.sleep(5)

    last_unread = -1

    while True:
        try:
            try:
                unread = modem.sms_count_unread()
            except HuaweiSessionError as e:
                log.warning("%s; reinitializing session", e)
                modem.init_session()
                unread = modem.sms_count_unread()

            health.success()

            if unread != last_unread:
                log.info("Modem LocalUnread=%d", unread)
                last_unread = unread

            if unread <= 0:
                time.sleep(config.count_poll_seconds)
                continue

            try:
                messages = modem.sms_list_unread()
            except HuaweiSessionError as e:
                log.warning("%s; reinitializing session", e)
                modem.init_session()
                messages = modem.sms_list_unread()

            health.success()

            if not messages:
                time.sleep(config.count_poll_seconds)
                continue

            for msg in messages:
                fp = sms_fingerprint(msg)

                if fp in processed:
                    cleanup_modem_message(modem, msg)
                    continue

                try:
                    send_sms_telegram(config, msg)
                    log.info("Telegram delivered (fp=%s...)", fp[:8])

                    send_sms_email(config, msg)
                    if config.sms.email_to:
                        log.info("Email delivered to SMS recipient (fp=%s...)", fp[:8])

                    append_archive(config, msg, fp)
                    log.info("Archived locally (fp=%s...)", fp[:8])
                except Exception as e:
                    log.error("Delivery failed; SMS will NOT be deleted. fp=%s... err=%s", fp[:8], e)
                    continue

                if not cleanup_modem_message(modem, msg):
                    log.error("Cleanup failed after retries; message delivered but NOT deleted. fp=%s...", fp[:8])
                    continue

                processed.add(fp)
                save_processed_hashes(config, processed)
                log.info("Processed SMS fp=%s... index=%d (delivered+archived+deleted)", fp[:8], msg.index)

            time.sleep(config.poll_interval_seconds)

        except requests.RequestException as e:
            log.error("Network error while polling modem: %s; sleeping 5s", e)
            health.failure(e)
            time.sleep(5)
        except Exception as e:
            log.exception("Unexpected loop error: %s; sleeping 5s", e)
            health.failure(e)
            time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
