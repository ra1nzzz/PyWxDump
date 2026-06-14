"""PyWxDump remote collector — real implementation.

Reads WeChat encrypted DBs using collector_base utilities,
inserts messages into DustMirror SQLite warehouse.

Entry point: collect_date(target_date=None, **kwargs) -> dict

Environment variables (set by DustMirror executor):
  DUSTMIRROR_DB_PATH  — path to dustmirror.db
  WECHAT_DB_DIR       — WeChat data directory
  WECHAT_KEYS_FILE    — path to all_keys.json
  WI_MY_WXID          — user wxid (optional, auto-detected)
  WI_MY_ALIASES       — comma-separated aliases
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

try:
    from wxdump.collector_base import (
        load_keys, open_encrypted_db, safe_str, is_binary_content,
        build_table_wxid_map, discover_my_wxid, get_contacts,
        enrich_chat_contacts, resolve_chat_name, get_cached_my_sender_id,
        parse_message_sender, build_alias_set, is_at_me,
        learn_aliases_from_msgs, parse_system_msg, parse_appmsg_subtype,
        format_msg_display, extract_media_metadata,
    )
except ImportError:
    from collector_base import (
        load_keys, open_encrypted_db, safe_str, is_binary_content,
        build_table_wxid_map, discover_my_wxid, get_contacts,
        enrich_chat_contacts, resolve_chat_name, get_cached_my_sender_id,
        parse_message_sender, build_alias_set, is_at_me,
        learn_aliases_from_msgs, parse_system_msg, parse_appmsg_subtype,
        format_msg_display, extract_media_metadata,
    )

logger = logging.getLogger("pywxdump.collector")


def _db_path() -> Path:
    p = os.environ.get("DUSTMIRROR_DB_PATH", "")
    if not p:
        raise RuntimeError("DUSTMIRROR_DB_PATH not set")
    return Path(p)


def _wechat_db_dir() -> Path:
    p = os.environ.get("WECHAT_DB_DIR", "")
    if not p:
        raise RuntimeError("WECHAT_DB_DIR not set")
    return Path(p)


def _get_write_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()), timeout=5.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def _get_my_sender_id(msg_conn, group_tables: list) -> str:
    return os.environ.get("WI_MY_WXID", "")


def collect_date(target_date: date | None = None, **kwargs: Any) -> dict:
    """Main collection entry point."""
    if target_date is None:
        target_date = date.today() - timedelta(days=1)

    start_time = time.time()
    stats: dict[str, Any] = {
        "date": target_date.isoformat(),
        "messages_new": 0,
        "messages_total": 0,
        "tables_scanned": 0,
        "contacts_upserted": 0,
        "sessions_upserted": 0,
        "errors": [],
    }

    logger.info(f"开始采集 {target_date.isoformat()} 的消息")

    # Load keys
    try:
        keys = load_keys()
    except Exception as e:
        stats["errors"].append(f"加载密钥失败: {e}")
        return stats

    # Build table mapping
    table_map = build_table_wxid_map(keys)
    if not table_map:
        stats["errors"].append("无法建立表名映射")
        return stats

    # Open contact DB
    db_dir = _wechat_db_dir()
    contact_db_path = db_dir / "contact" / "contact.db"
    contact_key = keys.get("contact/contact.db")
    if not contact_key or not contact_db_path.exists():
        stats["errors"].append("contact数据库不可用")
        return stats
    try:
        contact_conn = open_encrypted_db(str(contact_db_path), contact_key)
    except Exception as e:
        stats["errors"].append(f"contact数据库打开失败: {e}")
        return stats

    contacts = enrich_chat_contacts(keys, get_contacts(contact_conn))
    logger.info(f"联系人: {len(contacts)}")

    # Detect user wxid
    my_wxid = os.environ.get("WI_MY_WXID", "") or discover_my_wxid(keys)
    if my_wxid:
        os.environ["WI_MY_WXID"] = my_wxid
    logger.info(f"用户wxid: {my_wxid}")

    aliases = build_alias_set(my_wxid, contacts, os.environ.get("WI_MY_ALIASES", "").split(","))

    # Open message DB
    msg_db_path = db_dir / "message" / "message_0.db"
    msg_key = keys.get("message/message_0.db")
    if not msg_key or not msg_db_path.exists():
        stats["errors"].append("message数据库不可用")
        contact_conn.close()
        return stats
    try:
        msg_conn = open_encrypted_db(str(msg_db_path), msg_key)
    except Exception as e:
        stats["errors"].append(f"message数据库打开失败: {e}")
        contact_conn.close()
        return stats

    # Get actual Msg_ tables
    actual_tables = set(
        r[0] for r in msg_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
        ).fetchall()
    )

    group_tables = [t for t, wxid in table_map.items() if t in actual_tables and wxid.endswith("@chatroom")]
    my_sender_id = _get_my_sender_id(msg_conn, group_tables)

    # Date range
    start_ts = int(datetime.combine(target_date, datetime.min.time()).timestamp())
    end_ts = int(datetime.combine(target_date + timedelta(days=1), datetime.min.time()).timestamp())

    conn = _get_write_conn()
    aliases = learn_aliases_from_msgs("", my_wxid, aliases)

    try:
        for table_name, wxid in table_map.items():
            if table_name not in actual_tables:
                continue
            stats["tables_scanned"] += 1

            try:
                rows = msg_conn.execute(
                    f"SELECT local_id, local_type, create_time, message_content, real_sender_id "
                    f"FROM [{table_name}] WHERE create_time >= ? AND create_time < ? ORDER BY create_time",
                    (start_ts, end_ts),
                ).fetchall()
            except Exception as e:
                stats["errors"].append(f"读取 {table_name} 失败: {e}")
                continue

            is_group = wxid.endswith("@chatroom")
            chat_name = resolve_chat_name(wxid, contacts)

            # Upsert session
            last_msg_time = 0
            for row in rows:
                if row[2] and row[2] > last_msg_time:
                    last_msg_time = row[2]

            local_type = 2 if is_group else (3 if wxid.startswith("gh_") else 1)
            conn.execute(
                """INSERT INTO chat_sessions(wxid, username, nick_name, local_type, last_msg_time, updated_at)
                   VALUES(?,?,?,?,?,datetime('now'))
                   ON CONFLICT(wxid) DO UPDATE SET
                     nick_name=excluded.nick_name, last_msg_time=MAX(excluded.last_msg_time, chat_sessions.last_msg_time),
                     updated_at=datetime('now')""",
                (wxid, wxid, chat_name, local_type, last_msg_time),
            )
            stats["sessions_upserted"] += 1

            # Upsert contact
            cinfo = contacts.get(wxid, {})
            conn.execute(
                """INSERT INTO contacts(wxid, nick_name, remark, local_type, last_seen)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(wxid) DO UPDATE SET
                     nick_name=excluded.nick_name, remark=excluded.remark,
                     last_seen=MAX(excluded.last_seen, contacts.last_seen)""",
                (wxid, cinfo.get("nick_name", chat_name), cinfo.get("remark", ""),
                 local_type, last_msg_time),
            )
            stats["contacts_upserted"] += 1

            for row in rows:
                local_id, local_type_raw, create_time, raw_content, real_sender_id = row

                raw_content = safe_str(raw_content) if raw_content else ""

                # Parse sender
                sender_wxid = ""
                sender_name = ""
                msg_content = raw_content

                if is_group and raw_content:
                    sender_wxid, msg_content = parse_message_sender(raw_content, my_wxid)
                    if sender_wxid and sender_wxid in contacts:
                        sender_name = contacts[sender_wxid].get("remark") or contacts[sender_wxid].get("nick_name", "")
                    elif sender_wxid:
                        sender_name = sender_wxid
                elif my_wxid and not is_group:
                    # For 1-on-1, we don't know who sent from DB alone
                    pass

                if not sender_wxid and real_sender_id:
                    sender_wxid = safe_str(real_sender_id)

                # Detect message type from local_type
                msg_type = 1  # default text
                msg_subtype = 0
                extra: dict[str, Any] = {}

                # Parse content
                has_binary = False
                if msg_content:
                    has_binary = is_binary_content(msg_content)
                    if has_binary:
                        media_meta = extract_media_metadata(1, msg_content)
                        extra.update(media_meta)
                        msg_content = ""

                # System messages
                if local_type_raw in (10000, 10001, 10002):
                    msg_type = local_type_raw
                    sys_info = parse_system_msg(raw_content)
                    extra.update(sys_info)
                    if sys_info.get("description"):
                        msg_content = sys_info["description"]
                    elif raw_content:
                        msg_content = raw_content

                # Detect type from content patterns
                if msg_content:
                    if msg_content.startswith("<?xml") or msg_content.startswith("<msg>"):
                        if "<appmsg" in msg_content:
                            msg_type = 49
                            sub, title, desc = parse_appmsg_subtype(msg_content)
                            msg_subtype = sub
                            if title:
                                extra["appmsg_title"] = title
                        elif "<voip" in msg_content:
                            msg_type = 50
                        elif "<emoji" in msg_content:
                            msg_type = 47
                        else:
                            msg_type = 49
                    elif msg_content.startswith("{") and '"msg_type"' in msg_content:
                        try:
                            obj = json.loads(msg_content)
                            msg_type = obj.get("msg_type", 1)
                        except json.JSONDecodeError:
                            pass

                # is_at_me
                at_me = 1 if is_at_me(msg_content or raw_content, aliases) else 0
                # is_from_me
                from_me = 1 if (sender_wxid in aliases) else 0

                # Final display content
                display_content = msg_content
                if msg_type != 1 and not display_content:
                    display_content = format_msg_display(msg_type, msg_subtype, "", extra)
                elif has_binary and not display_content:
                    display_content = format_msg_display(msg_type, msg_subtype, "", extra)

                extra_json = json.dumps(extra, ensure_ascii=False) if extra else ""

                try:
                    conn.execute(
                        """INSERT INTO messages(chat_wxid, msg_id, sender_wxid, sender_name,
                           msg_type, msg_subtype, content, extra, msg_time, is_at_me, is_from_me, source_db)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                           ON CONFLICT(chat_wxid, msg_id) DO UPDATE SET
                             content=excluded.content, extra=excluded.extra""",
                        (wxid, local_id, sender_wxid, sender_name,
                         msg_type, msg_subtype, display_content, extra_json,
                         create_time or 0, at_me, from_me, table_name),
                    )
                    stats["messages_new"] += 1
                except Exception as e:
                    stats["errors"].append(f"插入消息失败 {table_name}/{local_id}: {e}")

        stats["messages_total"] = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        conn.commit()

        # Update daily_stats
        try:
            day_str = target_date.isoformat()
            row = conn.execute(
                "SELECT COUNT(*) as cnt, SUM(is_at_me) as at_cnt, SUM(is_from_me) as from_cnt "
                "FROM messages WHERE msg_time >= ? AND msg_time < ?",
                (start_ts, end_ts),
            ).fetchone()
            conn.execute(
                """INSERT INTO daily_stats(stat_date, chat_wxid, msg_count, at_me_count, from_me_count)
                   VALUES(?, '', ?, ?, ?)
                   ON CONFLICT(stat_date, chat_wxid) DO UPDATE SET
                     msg_count=excluded.msg_count, at_me_count=excluded.at_me_count, from_me_count=excluded.from_me_count""",
                (day_str, row[0] or 0, row[1] or 0, row[2] or 0),
            )
            conn.commit()
        except Exception as e:
            logger.warning(f"daily_stats 更新失败: {e}")

        # Update contact msg_count
        try:
            conn.execute("""
                UPDATE contacts SET msg_count = (
                    SELECT COUNT(*) FROM messages WHERE messages.sender_wxid = contacts.wxid
                )
            """)
            conn.commit()
        except Exception:
            pass

    except Exception as e:
        stats["errors"].append(f"采集异常: {e}")
        logger.exception("采集异常")
    finally:
        conn.close()
        msg_conn.close()
        contact_conn.close()

    elapsed = time.time() - start_time
    logger.info(f"采集完成: {stats['messages_new']} 新消息, {stats['tables_scanned']} 表, 耗时 {elapsed:.1f}s")
    return stats
