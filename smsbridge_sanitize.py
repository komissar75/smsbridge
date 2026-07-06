#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Iterable


SECRET_PATTERNS = [
    (re.compile(r"(\b(?:SMS_)?TELEGRAM_BOT_TOKEN\s*=\s*)(\S+)", re.I), r"\1<REDACTED>"),
    (re.compile(r"(\bADMIN_TELEGRAM_BOT_TOKEN\s*=\s*)(\S+)", re.I), r"\1<REDACTED>"),
    (re.compile(r"(bot)(\d{5,}:[A-Za-z0-9_-]{20,})"), r"\1<REDACTED>"),
    (re.compile(r"(\b(?:SMS_)?SMTP_PASS\s*=\s*)(\S+)", re.I), r"\1<REDACTED>"),
    (re.compile(r"(\bADMIN_SMTP_PASS\s*=\s*)(\S+)", re.I), r"\1<REDACTED>"),
    (re.compile(r"(\b(?:password|passwd|pass|token|secret|cookie|session|csrf)\b\s*[:=]\s*)(\S+)", re.I), r"\1<REDACTED>"),
    (re.compile(r"(__RequestVerificationToken(?:one|two)?\s*[:=]\s*)(\S+)", re.I), r"\1<REDACTED>"),
    (re.compile(r"(Authorization:\s*)(\S+.*)", re.I), r"\1<REDACTED>"),
]


PHONE_RE = re.compile(r"(?<!\d)(\+?\d[\d \-().]{7,}\d)(?!\d)")


def mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 8:
        return value
    suffix = digits[-3:]
    prefix = "+" if value.strip().startswith("+") else ""
    return f"{prefix}{digits[:3]}******{suffix}"


def sanitize_text(text: str, mask_phones: bool = True) -> str:
    out = text
    for pattern, replacement in SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    if mask_phones:
        out = PHONE_RE.sub(lambda m: mask_phone(m.group(1)), out)
    return out


def sanitize_lines(lines: Iterable[str], mask_phones: bool = True) -> list[str]:
    return [sanitize_text(line.rstrip("\n"), mask_phones=mask_phones) for line in lines]
