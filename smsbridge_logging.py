#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
from collections import deque
from logging.handlers import RotatingFileHandler
from typing import Deque


class RecentLogBufferHandler(logging.Handler):
    def __init__(self, max_lines: int):
        super().__init__()
        self.lines: Deque[str] = deque(maxlen=max_lines)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.append(self.format(record))
        except Exception:
            self.handleError(record)


def setup_logging(log_file: str, level_name: str = "INFO", recent_lines: int = 120) -> RecentLogBufferHandler:
    level = getattr(logging, level_name.upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    root.addHandler(stream)

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)

    recent = RecentLogBufferHandler(recent_lines)
    recent.setFormatter(fmt)
    root.addHandler(recent)
    return recent
