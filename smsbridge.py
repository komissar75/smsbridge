#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
smsbridge.py — Huawei HiLink SMS → Telegram + Email (SMTP) bridge (Debian/systemd)

Key points for Huawei HiLink quirks (E3372h and similar):
- Some firmware requires tokens from BOTH:
    * /api/webserver/SesTokInfo  (TokInfo + SesInfo)
    * /api/webserver/token       (one or more verification tokens)
  especially for mutating endpoints like set-read / delete-sms.
- Token can also rotate and be returned in HTTP response headers:
    __RequestVerificationToken (or variants). We must capture and update it.

Robustness:
- Handles 125002/125003 as "session/token invalid" → full reinit and retry.
- sms-list request uses full schema (prevents 100005 format error).

Behavior:
- Poll /api/sms/sms-count; when LocalUnread>0 fetch unread messages
- Decode Cyrillic (mojibake + UCS-2 hex)
- Send Telegram + Email (optional)
- Archive locally
- Then set-read + delete-sms
- Dedup by fingerprint (sha256(phone|date|content)) since Index is reusable
"""

import hashlib
import json
import logging
import os
import smtplib
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Dict, List, Optional
from urllib.parse import urljoin
from xml.etree import ElementTree as ET

import requests

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("smsbridge")

# -----------------------------
# Config (env)
# -----------------------------
MODEM_URL = os.environ.get("MODEM_URL", "http://192.168.8.1").rstrip("/")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

EMAIL_TO = os.environ.get("EMAIL_TO")  # optional
EMAIL_FROM = os.environ.get("EMAIL_FROM")
EMAIL_SUBJECT_PREFIX = os.environ.get("EMAIL_SUBJECT_PREFIX", "[SMSBridge]")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.mail.ru")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_TLS = os.environ.get("SMTP_TLS", "yes").lower() in ("1", "true", "yes", "y")

COUNT_POLL_SECONDS = float(os.environ.get("COUNT_POLL_SECONDS", "1"))
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "1"))
HTTP_TIMEOUT_SECONDS = float(os.environ.get("HTTP_TIMEOUT_SECONDS", "5"))
MAX_FETCH = int(os.environ.get("MAX_FETCH", "50"))

STATE_DIR = os.environ.get("STATE_DIR", "/var/lib/smsbridge")
PROCESSED_FILE = os.environ.get("PROCESSED_FILE", os.path.join(STATE_DIR, "processed_hashes.json"))
ARCHIVE_FILE = os.environ.get("ARCHIVE_FILE", os.path.join(STATE_DIR, "sms_archive.jsonl"))

if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    log.error("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
    sys.exit(2)

if EMAIL_TO and not (SMTP_USER and SMTP_PASS):
    log.error("EMAIL_TO is set but SMTP_USER/SMTP_PASS missing")
    sys.exit(2)

# -----------------------------
# Huawei endpoints / codes
# -----------------------------
EP_INDEX_HTML = "/html/index.html"
EP_SES_TOK = "/api/webserver/SesTokInfo"
EP_WEB_TOKEN = "/api/webserver/token"

EP_SMS_COUNT = "/api/sms/sms-count"
EP_SMS_LIST = "/api/sms/sms-list"
EP_SET_READ = "/api/sms/set-read"
EP_DELETE_SMS = "/api/sms/delete-sms"

HUAWEI_ERR_125002 = "125002"  # token invalid
HUAWEI_ERR_125003 = "125003"  # session/token error


@dataclass
class SmsMessage:
    index: int
    phone: str
    content: str
    date: str
    smstat: str  # "0" unread


# -----------------------------
# State / archive
# -----------------------------
def ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def load_processed_hashes() -> set:
    ensure_state_dir()
    try:
        if not os.path.exists(PROCESSED_FILE):
            return set()
        with open(PROCESSED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("hashes"), list):
            return set(str(x) for x in data["hashes"])
        if isinstance(data, list):
            return set(str(x) for x in data)
        return set()
    except Exception as e:
        log.warning("Failed to load processed state (%s): %s; starting empty", PROCESSED_FILE, e)
        return set()


def save_processed_hashes(hashes: set) -> None:
    ensure_state_dir()
    tmp = PROCESSED_FILE + ".tmp"
    payload = {"hashes": sorted(hashes)}
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, PROCESSED_FILE)


def append_archive(msg: SmsMessage, fp: str) -> None:
    ensure_state_dir()
    rec = {
        "archived_at": datetime.now(timezone.utc).isoformat(),
        "fingerprint": fp,
        "index": msg.index,
        "phone": msg.phone,
        "date": msg.date,
        "content": msg.content,
        "smstat": msg.smstat,
    }
    with open(ARCHIVE_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


# -----------------------------
# Content decoding
# -----------------------------
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

    # UCS-2 hex (UTF-16BE)
    if len(s) >= 8 and (len(s) % 4 == 0) and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            return bytes.fromhex(s).decode("utf-16-be")
        except Exception:
            return text

    return text


def sms_fingerprint(msg: SmsMessage) -> str:
    raw = f"{msg.phone}|{msg.date}|{msg.content}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# -----------------------------
# XML helpers
# -----------------------------
def parse_xml_bytes(data: bytes) -> ET.Element:
    return ET.fromstring(data)


def extract_error_code(root: ET.Element) -> Optional[str]:
    if root.tag.lower() == "error":
        c = root.findtext("code")
        return c.strip() if c else None
    err = root.find(".//error")
    if err is not None:
        c = err.findtext("code")
        return c.strip() if c else None
    return None


class HuaweiSessionError(Exception):
    """Token/session invalid -> reinit needed."""


# -----------------------------
# Huawei client
# -----------------------------
class HuaweiClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.sess = requests.Session()

        # The "current" verification token we send (some firmwares rotate it)
        self.token: Optional[str] = None

        # Some firmwares also use additional tokens; we keep them if present
        self.token_alt: Optional[str] = None

    def _url(self, path: str) -> str:
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def _capture_token_from_headers(self, r: requests.Response) -> None:
        """
        Huawei may rotate token and return it in headers.
        Observed header names:
          - __RequestVerificationToken
          - __RequestVerificationTokenone / two (rare)
          - __requestverificationtoken (lowercase)
        We'll store main token and keep an alternate if provided.
        """
        for key in (
            "__RequestVerificationToken",
            "__requestverificationtoken",
            "__RequestVerificationTokenone",
            "__RequestVerificationTokenOne",
            "__RequestVerificationTokentwo",
            "__RequestVerificationTokenTwo",
        ):
            val = r.headers.get(key)
            if val and val.strip():
                # If token string contains multiple tokens separated by '#', keep first as main
                parts = [p for p in val.strip().split("#") if p]
                if parts:
                    self.token = parts[0]
                    if len(parts) > 1:
                        self.token_alt = parts[1]
                return

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/xml"}
        if self.token:
            h["__RequestVerificationToken"] = self.token
        return h

    def _raise_if_session_error(self, code: Optional[str], where: str) -> None:
        if code in (HUAWEI_ERR_125002, HUAWEI_ERR_125003):
            raise HuaweiSessionError(f"{where} session/token error {code}")

    def init_session(self) -> None:
        # 1) cookies
        r1 = self.sess.get(self._url(EP_INDEX_HTML), timeout=HTTP_TIMEOUT_SECONDS)
        r1.raise_for_status()
        self._capture_token_from_headers(r1)

        # 2) TokInfo token
        r2 = self.sess.get(self._url(EP_SES_TOK), timeout=HTTP_TIMEOUT_SECONDS)
        r2.raise_for_status()
        self._capture_token_from_headers(r2)

        root = parse_xml_bytes(r2.content)
        code = extract_error_code(root)
        if code:
            raise RuntimeError(f"SesTokInfo returned error code {code}")

        tok = root.findtext(".//TokInfo")
        if tok and tok.strip():
            self.token = tok.strip()

        # 3) Additional webserver token(s) (needed on some firmware for set-read/delete)
        r3 = self.sess.get(self._url(EP_WEB_TOKEN), timeout=HTTP_TIMEOUT_SECONDS)
        r3.raise_for_status()
        self._capture_token_from_headers(r3)

        root3 = parse_xml_bytes(r3.content)
        code3 = extract_error_code(root3)
        if code3:
            # don't fail hard; some firmwares may not support it
            log.info("webserver/token returned code=%s (ignored)", code3)
        else:
            t = root3.findtext(".//token") or root3.findtext(".//Token")
            if t and t.strip():
                self.token = t.strip()

        if not self.token:
            raise RuntimeError("Failed to obtain verification token from modem")

        log.info("Huawei session initialized")

    def sms_count_unread(self) -> int:
        r = self.sess.get(self._url(EP_SMS_COUNT), headers=self._headers(), timeout=HTTP_TIMEOUT_SECONDS)
        r.raise_for_status()
        self._capture_token_from_headers(r)

        root = parse_xml_bytes(r.content)
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
  <ReadCount>{MAX_FETCH}</ReadCount>
  <BoxType>1</BoxType>
  <SortType>0</SortType>
  <Ascending>0</Ascending>
  <UnreadPreferred>1</UnreadPreferred>
</request>"""

        r = self.sess.post(
            self._url(EP_SMS_LIST),
            headers=self._headers(),
            data=body.encode("utf-8"),
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        self._capture_token_from_headers(r)

        root = parse_xml_bytes(r.content)
        code = extract_error_code(root)
        self._raise_if_session_error(code, "sms-list")
        if code:
            raise RuntimeError(f"sms-list returned error code {code}")

        msgs_node = root.find(".//Messages")
        if msgs_node is None:
            return []

        out: List[SmsMessage] = []
        for m in msgs_node.findall(".//Message"):
            smstat = (m.findtext("Smstat") or "").strip()
            if smstat != "0":
                continue
            idx_txt = (m.findtext("Index") or "").strip()
            try:
                idx = int(idx_txt)
            except Exception:
                continue
            phone = (m.findtext("Phone") or "").strip()
            content_raw = (m.findtext("Content") or "").strip()
            date = (m.findtext("Date") or "").strip()

            out.append(
                SmsMessage(
                    index=idx,
                    phone=phone,
                    content=decode_sms_content(content_raw),
                    date=date,
                    smstat="0",
                )
            )
        return out

    def set_read(self, index: int) -> None:
        body = f"""<?xml version="1.0" encoding="UTF-8"?><request><Index>{index}</Index></request>"""
        r = self.sess.post(
            self._url(EP_SET_READ),
            headers=self._headers(),
            data=body.encode("utf-8"),
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        self._capture_token_from_headers(r)

        root = parse_xml_bytes(r.content)
        code = extract_error_code(root)
        self._raise_if_session_error(code, "set-read")
        if code:
            # Not fatal: some firmwares return codes when already-read
            log.info("set-read returned code=%s for index=%d (ignored)", code, index)

    def delete_sms(self, index: int) -> None:
        body = f"""<?xml version="1.0" encoding="UTF-8"?><request><Index>{index}</Index></request>"""
        r = self.sess.post(
            self._url(EP_DELETE_SMS),
            headers=self._headers(),
            data=body.encode("utf-8"),
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        self._capture_token_from_headers(r)

        root = parse_xml_bytes(r.content)
        code = extract_error_code(root)
        self._raise_if_session_error(code, "delete-sms")
        if code:
            # Not fatal: may already be deleted
            log.info("delete-sms returned code=%s for index=%d (ignored)", code, index)


# -----------------------------
# Delivery: Telegram + Email
# -----------------------------
def send_telegram(msg: SmsMessage) -> None:
    text = (
        "📩 SMS\n"
        f"From: {msg.phone}\n"
        f"Date: {msg.date}\n"
        f"Text: {msg.content}\n"
        f"Index: {msg.index}"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    r = requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=HTTP_TIMEOUT_SECONDS)
    r.raise_for_status()


def send_email_smtp(msg: SmsMessage) -> None:
    if not EMAIL_TO:
        return

    subject = f"{EMAIL_SUBJECT_PREFIX} SMS from {msg.phone} @ {msg.date}"
    body = f"From: {msg.phone}\nDate: {msg.date}\n\n{msg.content}\n\nIndex: {msg.index}\n"

    em = EmailMessage()
    em["To"] = EMAIL_TO
    em["From"] = EMAIL_FROM or SMTP_USER
    em["Subject"] = subject
    em.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
        if SMTP_TLS:
            s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(em)


# -----------------------------
# Main
# -----------------------------
def main() -> int:
    log.info("smsbridge starting (MODEM_URL=%s)", MODEM_URL)

    processed = load_processed_hashes()
    log.info("Loaded %d processed fingerprints", len(processed))

    modem = HuaweiClient(MODEM_URL)

    # Init modem session with retries
    while True:
        try:
            modem.init_session()
            break
        except Exception as e:
            log.error("Failed to init modem session: %s; retrying in 5s", e)
            time.sleep(5)

    last_unread = -1

    while True:
        try:
            # Count trigger
            try:
                unread = modem.sms_count_unread()
            except HuaweiSessionError as e:
                log.warning("%s; reinitializing session", e)
                modem.init_session()
                unread = modem.sms_count_unread()

            if unread != last_unread:
                log.info("Modem LocalUnread=%d", unread)
                last_unread = unread

            if unread <= 0:
                time.sleep(COUNT_POLL_SECONDS)
                continue

            # Fetch unread list
            try:
                msgs = modem.sms_list_unread()
            except HuaweiSessionError as e:
                log.warning("%s; reinitializing session", e)
                modem.init_session()
                msgs = modem.sms_list_unread()

            if not msgs:
                time.sleep(COUNT_POLL_SECONDS)
                continue

            for msg in msgs:
                fp = sms_fingerprint(msg)

                # If already processed, attempt cleanup but don't fail the loop
                if fp in processed:
                    for attempt in (1, 2):
                        try:
                            modem.set_read(msg.index)
                            modem.delete_sms(msg.index)
                            break
                        except HuaweiSessionError as e:
                            log.warning("%s; reinitializing session (cleanup attempt %d)", e, attempt)
                            modem.init_session()
                    continue

                # Delivery guarantee: do not delete if delivery fails
                try:
                    send_telegram(msg)
                    log.info("Telegram delivered (fp=%s...)", fp[:8])

                    send_email_smtp(msg)
                    if EMAIL_TO:
                        log.info("Email delivered to %s (fp=%s...)", EMAIL_TO, fp[:8])

                    append_archive(msg, fp)
                    log.info("Archived locally (fp=%s...)", fp[:8])
                except Exception as e:
                    log.error("Delivery failed; SMS will NOT be deleted. fp=%s... err=%s", fp[:8], e)
                    continue

                # Cleanup modem with retry on session/token errors
                cleaned = False
                for attempt in (1, 2):
                    try:
                        modem.set_read(msg.index)
                        modem.delete_sms(msg.index)
                        cleaned = True
                        break
                    except HuaweiSessionError as e:
                        log.warning("%s; reinitializing session (cleanup attempt %d)", e, attempt)
                        modem.init_session()

                if not cleaned:
                    log.error("Cleanup failed after retries; message delivered but NOT deleted. fp=%s...", fp[:8])
                    # Do NOT mark as processed so it can be retried/cleaned later (or handled manually)
                    continue

                processed.add(fp)
                save_processed_hashes(processed)
                log.info("Processed SMS fp=%s... index=%d (delivered+archived+deleted)", fp[:8], msg.index)

            time.sleep(POLL_INTERVAL_SECONDS)

        except requests.RequestException as e:
            log.error("Network error: %s; sleeping 5s", e)
            time.sleep(5)
        except Exception as e:
            log.exception("Unexpected loop error: %s; sleeping 5s", e)
            time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
