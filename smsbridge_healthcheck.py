#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timezone

from smsbridge_admin_alert import AdminAlerter
from smsbridge_config import load_config
from smsbridge_logging import setup_logging
from smsbridge_state import parse_iso, read_json


def main() -> int:
    config = load_config("/etc/smsbridge.env")
    setup_logging(config.log_file, recent_lines=config.admin.log_lines)

    health = read_json(config.health_file, {})
    last_success = parse_iso(health.get("last_successful_modem_poll") if isinstance(health, dict) else None)
    last_error = health.get("last_error") if isinstance(health, dict) else None

    if last_success is None:
        AdminAlerter(config).healthcheck_failure(float(config.admin.stale_heartbeat_seconds), "No successful modem poll recorded")
        return 1

    age = (datetime.now(timezone.utc) - last_success).total_seconds()
    if age > config.admin.stale_heartbeat_seconds:
        AdminAlerter(config).healthcheck_failure(age, last_error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
