#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path

_VERSION_FILE = Path(__file__).with_name("version.json")


def _read_version() -> str:
    try:
        data = json.loads(_VERSION_FILE.read_text(encoding="utf-8"))
        return str(data.get("version", "0.0.000"))
    except Exception:
        return "0.0.000"


def _format_gui_version(full_version: str) -> str:
    parts = full_version.split(".")
    if len(parts) != 3:
        return full_version
    return f"{parts[0]}.{parts[1]}"


FULL_VERSION = _read_version()
GUI_VERSION = _format_gui_version(FULL_VERSION)
