"""PyWxDump remote collector stub.

This module is hosted externally so DustMirror can download and execute it
without bundling the decryption logic inside the free app.

It must expose:
- collect_date(target_date=None, **kwargs) -> dict

Implementations should read local WeChat encrypted DB using the original
wechat-insight collector_base utilities and insert messages into the
DustMirror SQLite warehouse.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Any

logger = logging.getLogger("pywxdump.collector")


def collect_date(target_date: date | None = None, **kwargs: Any) -> dict:
    """Minimal stub to validate remote-load flow.

    Real implementation should:
    1) Load keys (all_keys.json)
    2) Open encrypted DBs (sqlcipher3)
    3) Read messages for target_date
    4) Insert into local SQLite warehouse (chat_sessions/messages)
    """
    if target_date is None:
        target_date = date.today() - timedelta(days=1)

    logger.info("Remote collector invoked for %s (stub)", target_date.isoformat())

    # TODO: replace with real implementation from wechat-insight collector
    return {
        "status": "ok",
        "date": target_date.isoformat(),
        "messages_new": 0,
        "messages_total": 0,
        "tables_scanned": 0,
        "errors": [],
        "note": "stub collector; replace with real decrypt/ingest logic",
    }
