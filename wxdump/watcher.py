"""PyWxDump remote watcher stub.

This module is hosted externally so DustMirror can download and execute it
without bundling the watchdog logic inside the free app.

It must expose:
- start_watchdog(watch_dir=None, **kwargs) -> Any

Real implementation should watch WeChat WAL files and trigger incremental imports.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("pywxdump.watcher")


def start_watchdog(watch_dir: str | None = None, **kwargs: Any) -> bool:
    """Minimal stub to validate remote-load flow.

    Real implementation should use watchdog or polling to trigger import.
    """
    logger.info("Remote watcher start requested (stub), watch_dir=%s", watch_dir)
    # TODO: replace with real watchdog implementation
    return True
