"""PyWxDump collector_base — shared decryption/parsing utilities.

Extracted from wechat-insight server/services/collector_base.py.
All paths read from environment variables set by DustMirror executor.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

logger = logging.getLogger("pywxdump.collector_base")

# ── Paths from env ──
def _wechat_db_dir() -> Path:
    return Path(os.environ.get("WECHAT_DB_DIR", ""))

def _wechat_keys_file() -> Path:
    return Path(os.environ.get("WECHAT_KEYS_FILE", ""))

# ── Constants ──
ZERO_WIDTH_CHARS = '\u2005\u200b\u200c\u200d\u2060'

MSG_TYPE_LABELS = {
    1: "文本", 3: "图片", 34: "语音", 43: "视频",
    47: "表情", 49: "文件", 42: "名片", 48: "位置",
    10000: "系统", 10001: "系统", 10002: "系统",
}

APPMSG_SUBTYPES = {
    1: "链接", 3: "音乐", 4: "视频", 5: "红包",
    6: "文件", 7: "红包转账", 8: "小程序", 9: "红包",
    19: "合并转发", 33: "小程序", 36: "小程序", 37: "小程序",
    43: "视频号", 50: "语音/通话", 51: "红包", 52: "引用",
    53: "图片", 57: "引用", 63: "视频号直播", 64: "红包",
    87: "群公告", 2000: "转账",
}


# ── Keys & DB ──

def load_keys() -> dict:
    keys_file = _wechat_keys_file()
    if not keys_file.exists():
        raise FileNotFoundError(f"密钥文件不存在: {keys_file}")
    with open(keys_file, "r", encoding="utf-8") as f:
        raw = json.load(f)
    keys = {}
    for db_name, info in raw.items():
        if isinstance(info, dict) and "enc_key" in info:
            keys[db_name] = info
    logger.info(f"加载 {len(keys)} 个数据库密钥")
    return keys


def open_encrypted_db(db_path: str, key_info: dict):
    import sqlcipher3
    conn = sqlcipher3.connect(db_path)
    hex_key = key_info["enc_key"]
    salt = key_info.get("salt", "")
    conn.execute(f"PRAGMA key = \"x'{hex_key}'\"")
    if salt:
        conn.execute(f"PRAGMA cipher_salt = \"x'{salt}'\"")
    conn.execute("PRAGMA cipher_compatibility = 4")
    conn.execute("PRAGMA cipher_page_size = 4096")
    try:
        conn.execute("SELECT count(*) FROM sqlite_master")
    except Exception:
        conn.close()
        raise ValueError(f"密钥无效或数据库损坏: {db_path}")
    return conn


# ── String utils ──

def safe_str(data) -> str:
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            try:
                return data.decode("gbk", errors="replace")
            except Exception:
                return ""
    if data is None:
        return ""
    return str(data)


def is_binary_content(text: str, threshold: float = 0.15) -> bool:
    if not text or len(text) < 4:
        return False
    NL_TAB = chr(10) + chr(9)
    ctrl = sum(1 for c in text if ord(c) < 32 and c not in NL_TAB)
    fffd = text.count("\ufffd")
    return (ctrl / len(text) > threshold) or (fffd > 0 and fffd / len(text) > 0.02)


# ── Table mapping ──

def build_table_wxid_map(keys: dict) -> dict:
    db_dir = _wechat_db_dir()
    session_db = db_dir / "session" / "session.db"
    key_info = keys.get("session/session.db")
    if not key_info or not session_db.exists():
        logger.warning("session.db 不可用，无法建立表名映射")
        return {}
    conn = open_encrypted_db(str(session_db), key_info)
    wxids = [r[0] for r in conn.execute("SELECT user_name FROM Name2Id").fetchall()]
    conn.close()
    mapping = {}
    for wxid in wxids:
        md5 = hashlib.md5(wxid.encode("utf-8")).hexdigest()
        mapping[f"Msg_{md5}"] = wxid
    logger.info(f"建立 {len(mapping)} 个表名→wxid映射")
    return mapping


def discover_my_wxid(keys: dict) -> str:
    db_dir = _wechat_db_dir()
    general_db = db_dir / "general" / "general.db"
    key_info = keys.get("general/general.db")
    if not key_info or not general_db.exists():
        return ""
    try:
        conn = open_encrypted_db(str(general_db), key_info)
        row = conn.execute("SELECT value FROM general WHERE key='userName'").fetchone()
        conn.close()
        return row[0] if row else ""
    except Exception:
        return ""


# ── Contacts ──

def get_contacts(contact_conn) -> dict:
    contacts = {}
    try:
        rows = contact_conn.execute(
            "SELECT userName, nickName, remark, type FROM Contact"
        ).fetchall()
        for row in rows:
            wxid = row[0]
            contacts[wxid] = {
                "wxid": wxid,
                "nick_name": safe_str(row[1]),
                "remark": safe_str(row[2]),
                "type": row[3] if len(row) > 3 else 0,
            }
    except Exception as e:
        logger.warning(f"读取联系人失败: {e}")
    return contacts


def enrich_chat_contacts(keys: dict, contacts: dict) -> dict:
    return contacts


def resolve_chat_name(wxid: str, contacts: dict) -> str:
    c = contacts.get(wxid, {})
    return c.get("remark") or c.get("nick_name") or wxid


# ── Sender resolution ──

def get_cached_my_sender_id(msg_conn, group_tables: list) -> str:
    return os.environ.get("WI_MY_WXID", "")


def parse_message_sender(content: str, my_wxid: str) -> tuple:
    if not content:
        return "", content
    # Group msg: "wxid_xxx:\nactual content"
    m = re.match(r"^(wxid_[a-zA-Z0-9_]+|@[a-zA-Z0-9]+):\n", content)
    if m:
        sender = m.group(1)
        rest = content[m.end():]
        return sender, rest
    return "", content


def build_alias_set(my_wxid: str, contacts: dict, my_aliases: list) -> set:
    aliases = set()
    if my_wxid:
        aliases.add(my_wxid)
    for a in (my_aliases or []):
        a = a.strip()
        if a:
            aliases.add(a)
    return aliases


def is_at_me(content: str, aliases: set) -> bool:
    if not content or not aliases:
        return False
    for a in aliases:
        if f"@{a}" in content or f"@{a}\u2005" in content:
            return True
    return False


def learn_aliases_from_msgs(content: str, my_wxid: str, aliases: set) -> set:
    return aliases


# ── Message parsing ──

def parse_system_msg(content: str) -> dict:
    if not content or "<sysmsg" not in content:
        return {"sys_type": "unknown"}
    try:
        xml_start = content.find("<sysmsg")
        xml_end = content.find("</sysmsg>")
        if xml_start < 0 or xml_end < 0:
            return {"sys_type": "unknown"}
        xml_str = content[xml_start:xml_end + len("</sysmsg>")]
        root = ET.fromstring(xml_str)
        sys_type = root.get("type", "unknown")
        result = {"sys_type": sys_type}
        if sys_type == "revokemsg":
            revoked = root.find(".//revokemsg")
            if revoked is not None:
                replacemsg = revoked.findtext("replacemsg", "")
                result["description"] = safe_str(replacemsg)
        elif sys_type in ("notification", "simple_appmsg_notification"):
            lines = []
            for elem in root.iter():
                text = (elem.text or "").strip()
                if text and len(text) > 2:
                    lines.append(text)
            result["description"] = " ".join(lines[:3]) if lines else ""
        return result
    except Exception as e:
        logger.debug(f"系统消息解析失败: {e}")
        return {"sys_type": "unknown"}


def parse_appmsg_subtype(content: str) -> tuple:
    subtype = 0
    title = ""
    desc = ""
    if not content:
        return subtype, title, desc
    try:
        xml_start = content.find("<appmsg")
        xml_end = content.find("</appmsg>")
        if xml_start >= 0 and xml_end >= 0:
            xml_str = content[xml_start:xml_end + len("</appmsg>")]
            root = ET.fromstring(xml_str)
            type_el = root.find(".//type")
            if type_el is not None and type_el.text:
                subtype = int(type_el.text)
            title_el = root.find(".//title")
            if title_el is not None and title_el.text:
                title = safe_str(title_el.text)
            des_el = root.find(".//des")
            if des_el is not None and des_el.text:
                desc = safe_str(des_el.text)
    except Exception:
        pass
    return subtype, title, desc


def format_msg_display(msg_type: int, msg_subtype: int, content: str, extra: dict) -> str:
    if msg_type == 1:
        return content or ""
    if msg_type == 3:
        return "[图片]"
    if msg_type == 34:
        return "[语音]"
    if msg_type == 43:
        return "[视频]"
    if msg_type == 47:
        return "[表情]"
    if msg_type == 49:
        sub_label = APPMSG_SUBTYPES.get(msg_subtype, "文件")
        title = extra.get("appmsg_title", "")
        if title:
            return f"[{sub_label}] {title}"
        return f"[{sub_label}]"
    if msg_type == 42:
        return "[名片]"
    if msg_type == 48:
        return "[位置]"
    if msg_type in (10000, 10001, 10002):
        desc = extra.get("description", "")
        if desc:
            return desc
        return content or "[系统消息]"
    return f"[未知类型{msg_type}]"


def extract_media_metadata(msg_type: int, raw_content: str) -> dict:
    if not raw_content or msg_type == 1:
        return {}
    try:
        data = raw_content.encode("latin-1", errors="replace") if isinstance(raw_content, str) else raw_content
        extra = {}
        for pattern in [b'wxid_', b'\\Users\\', b'/storage/', b'.jpg', b'.png', b'.mp4', b'.silk', b'.amr', b'.gif']:
            idx = data.find(pattern)
            if idx >= 0:
                chunk = data[max(0,idx-20):idx+200]
                try:
                    decoded = chunk.decode("utf-16-le", errors="ignore")
                    clean = re.sub(r'[\x00-\x09\x0b\x0c\x0e-\x1f]', '', decoded)
                    if len(clean) > 5:
                        extra["file_hint"] = clean[:200]
                        break
                except Exception:
                    pass
        if msg_type == 3:
            extra.setdefault("note", "二进制图片数据")
        elif msg_type == 34:
            extra.setdefault("note", "二进制语音数据")
        elif msg_type == 43:
            extra.setdefault("note", "二进制视频数据")
        elif msg_type == 47:
            extra.setdefault("note", "二进制表情数据")
        elif msg_type == 42:
            extra.setdefault("note", "二进制名片数据")
        elif msg_type == 48:
            extra.setdefault("note", "二进制位置数据")
        return extra
    except Exception:
        return {}
