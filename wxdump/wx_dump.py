#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wx_dump.py - WeChat database encryption key extractor.

This script extracts the encryption key from a running WeChat process
and creates a keys.json file that DustMirror can use to decrypt the
WeChat database.

Usage: python wx_dump.py [--output PATH]

Requirements: Windows, WeChat running and logged in.
"""

import json
import os
import subprocess
import sys
import glob
from pathlib import Path


def ensure_pywxdump():
    """Install pywxdump if not already available."""
    try:
        import pywxdump
        return True
    except ImportError:
        pass

    print("[*] Installing pywxdump from PyPI...", flush=True)
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pywxdump",
             "--quiet", "--disable-pip-version-check"],
            timeout=120,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[!] Failed to install pywxdump: {e}", file=sys.stderr)
        return False


def extract_keys():
    """Extract WeChat encryption keys using pywxdump API."""
    from pywxdump.wx_core.wx_info import get_wx_info
    from pywxdump.wx_core.get_bias_addr import get_bias_addr

    # Load version offsets
    wx_offs = {}
    try:
        import pywxdump as _pkg
        offs_path = os.path.join(os.path.dirname(_pkg.__file__), "WX_OFFS.json")
        if os.path.isfile(offs_path):
            with open(offs_path, "r", encoding="utf-8") as f:
                wx_offs = json.load(f)
    except Exception:
        pass

    print("[*] Scanning for WeChat process...", flush=True)
    wx_info_list = get_wx_info(wx_offs, False, None)
    if not wx_info_list:
        print("[!] No WeChat process found. Please log in to WeChat first.", file=sys.stderr)
        return None

    info = wx_info_list[0] if isinstance(wx_info_list, list) else wx_info_list
    key = info.get("key", "")
    wx_dir = info.get("wx_dir", "")
    wxid = info.get("wxid", "")
    account = info.get("account", "")
    name = info.get("nickname", "")

    print(f"[+] Found WeChat: {name or account or wxid}")
    print(f"[+] Key: {'YES (' + key[:8] + '...)' if key else 'NOT FOUND'}")
    print(f"[+] Data dir: {wx_dir}")

    if not key:
        print("[!] Could not extract encryption key from memory.", file=sys.stderr)
        return None

    # Build keys dict for all database files
    keys = {}
    if wx_dir and os.path.isdir(wx_dir):
        # Find all .db files in the WeChat data directory
        db_files = []
        for root, dirs, files in os.walk(wx_dir):
            # Skip msg directory (contains the actual encrypted dbs)
            for f in files:
                if f.endswith(".db"):
                    db_files.append(os.path.join(root, f))

        for db_path in db_files:
            # Create relative path key like "session/session.db"
            rel = os.path.relpath(db_path, wx_dir).replace("\\", "/")
            keys[rel] = {"enc_key": key, "salt": ""}

        print(f"[+] Found {len(keys)} database files")
    else:
        # Fallback: just save the key for common db paths
        for db_name in ["session/session.db", "general/general.db",
                        "contact/contact.db", "message/message.db"]:
            keys[db_name] = {"enc_key": key, "salt": ""}

    return keys


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract WeChat DB encryption keys")
    parser.add_argument("-o", "--output", default=None,
                        help="Output path for keys.json (default: stdout)")
    args = parser.parse_args()

    if not sys.platform == "win32":
        print("[!] This script only works on Windows.", file=sys.stderr)
        sys.exit(1)

    if not ensure_pywxdump():
        sys.exit(1)

    keys = extract_keys()
    if not keys:
        sys.exit(1)

    output = json.dumps(keys, ensure_ascii=False, indent=2)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"[+] Keys saved to: {out_path}")
    else:
        print(output)

    print("[+] Done! Keys extracted successfully.")


if __name__ == "__main__":
    main()
