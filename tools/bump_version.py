#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path

VERSION_FILE = Path(__file__).resolve().parents[1] / "version.json"


def parse(version: str):
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid version format: {version}. Expected x.x.xxx")
    major, minor, patch = parts
    if not (major.isdigit() and minor.isdigit() and patch.isdigit()):
        raise ValueError(f"Version must be numeric: {version}")
    return int(major), int(minor), int(patch)


def main():
    data = json.loads(VERSION_FILE.read_text(encoding="utf-8"))
    current = str(data.get("version", "0.0.000"))
    major, minor, patch = parse(current)

    patch += 1
    data["version"] = f"{major}.{minor}.{patch:03d}"
    VERSION_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Version bumped: {current} -> {data['version']}")


if __name__ == "__main__":
    main()