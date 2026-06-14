"""PyWxDump remote watcher — real watchdog implementation.

Monitors WeChat WAL files and triggers incremental imports.

Entry point: start_watchdog(watch_dir=None, **kwargs) -> bool

Environment variables (set by DustMirror executor):
  DUSTMIRROR_DB_PATH  — path to dustmirror.db
  WECHAT_DB_DIR       — WeChat data directory
"""
from __future__ import annotations

import logging
import os
import random
import threading
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("pywxdump.watcher")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    class FileSystemEventHandler:  # type: ignore
        pass
    logger.warning("watchdog未安装，实时监控不可用")

# ── Global state ──
_last_sync_ts = 0
_lock = threading.Lock()
_is_running = False
_observer = None
_polling_thread = None
_stop_event = None
_cooldown = 30
_poll_interval = 30 * 60
_poll_jitter_min = 1
_poll_jitter_max = 60


def get_last_sync_ts():
    return _last_sync_ts


def set_last_sync_ts(ts):
    global _last_sync_ts
    _last_sync_ts = ts


def is_running():
    return _is_running


def _run_collect():
    """Import collector and run collect_date for today."""
    try:
        try:
            from wxdump.collector import collect_date
        except ImportError:
            from collector import collect_date
        result = collect_date(target_date=date.today() - timedelta(days=1))
        logger.info("增量采集结果: %s", result)
    except Exception as e:
        logger.error("增量采集失败: %s", e)


class WeChatDBHandler(FileSystemEventHandler):
    """Monitor WeChat WAL file changes."""

    def __init__(self):
        super().__init__()
        self._last_mtime = 0
        self._collect_lock = threading.Lock()
        self._collecting = False

    def on_modified(self, event):
        if event.is_directory:
            return
        fname = os.path.basename(event.src_path)
        if "message_0.db-wal" not in fname:
            return
        now = time.time()
        if now - self._last_mtime < _cooldown:
            return
        self._last_mtime = now
        if not self._collecting:
            self._collecting = True
            t = threading.Thread(target=self._safe_collect, daemon=True)
            t.start()

    def _safe_collect(self):
        try:
            logger.info("WAL变化检测，触发增量采集")
            set_last_sync_ts(time.time())
            _run_collect()
        except Exception as e:
            logger.error("增量采集回调失败: %s", e)
        finally:
            self._collecting = False


def _poll_watch_loop(watch_path: Path, stop_event: threading.Event | None = None):
    """Polling fallback when watchdog is not available."""
    target = watch_path / "message_0.db-wal"
    last_mtime = 0
    last_trigger = 0
    while stop_event is not None and not stop_event.is_set():
        try:
            if target.exists():
                mtime = target.stat().st_mtime
                now = time.time()
                if last_mtime and mtime != last_mtime and now - last_trigger >= _cooldown:
                    last_trigger = now
                    set_last_sync_ts(now)
                    logger.info("WAL轮询检测到变化，触发增量采集")
                    _run_collect()
                last_mtime = mtime
        except Exception as e:
            logger.error("轮询监控异常: %s", e)
        jitter = random.uniform(_poll_jitter_min, _poll_jitter_max)
        time.sleep(_poll_interval + jitter)


def start_watchdog(watch_dir: str | Path | None = None, **kwargs: Any) -> bool:
    """Start file monitoring."""
    global _observer, _is_running, _polling_thread, _stop_event

    if _is_running:
        logger.info("监控已在运行")
        return True

    if watch_dir is None:
        watch_dir = os.environ.get("WECHAT_DB_DIR", "")
        if watch_dir:
            watch_dir = str(Path(watch_dir) / "message")

    if not watch_dir:
        logger.warning("监控目录未指定")
        return False

    watch_path = Path(watch_dir)
    if not watch_path.exists():
        logger.warning(f"监控目录不存在: {watch_dir}")
        return False

    if HAS_WATCHDOG:
        logger.info(f"使用 watchdog 模式监控: {watch_path}")
        handler = WeChatDBHandler()
        _observer = Observer()
        _observer.schedule(handler, str(watch_path), recursive=False)
        _observer.daemon = True
        _observer.start()
        _is_running = True
        return True
    else:
        logger.info(f"使用轮询模式监控: {watch_path}")
        _stop_event = threading.Event()
        _polling_thread = threading.Thread(
            target=_poll_watch_loop,
            args=(watch_path, _stop_event),
            daemon=True,
        )
        _polling_thread.start()
        _is_running = True
        return True


def stop_watchdog():
    """Stop file monitoring."""
    global _observer, _is_running, _polling_thread, _stop_event
    if _observer:
        _observer.stop()
        _observer.join(timeout=3)
        _observer = None
    if _stop_event:
        _stop_event.set()
        _stop_event = None
    if _polling_thread:
        _polling_thread.join(timeout=3)
        _polling_thread = None
    _is_running = False
    logger.info("文件监控已停止")
