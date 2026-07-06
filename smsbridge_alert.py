#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging

from smsbridge_admin_alert import AdminAlerter
from smsbridge_config import load_config
from smsbridge_logging import setup_logging


def main() -> int:
    parser = argparse.ArgumentParser(description="Send smsbridge administrator alerts")
    parser.add_argument("--source", choices=["test", "systemd", "runtime", "healthcheck"], default="test")
    parser.add_argument("--unit", default="smsbridge.service")
    parser.add_argument("--message", default="test admin alert")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--env-file", default="/etc/smsbridge.env")
    args = parser.parse_args()

    config = load_config(args.env_file)
    setup_logging(config.log_file, recent_lines=config.admin.log_lines)
    log = logging.getLogger("smsbridge.alert_cli")
    alerter = AdminAlerter(config)

    try:
        if args.source == "test":
            ok = alerter.test(args.message, force=True)
        elif args.source == "systemd":
            ok = alerter.systemd_failure(args.unit, message=args.message, force=args.force)
        elif args.source == "runtime":
            ok = alerter.runtime_critical(0, args.message, force=args.force)
        else:
            ok = alerter.healthcheck_failure(0, args.message, force=args.force)
        return 0 if ok else 1
    except Exception as e:
        log.exception("Alert CLI failed: %s", e)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
