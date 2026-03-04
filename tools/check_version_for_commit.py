#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "version.json"
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d{3})$")


def fail(message: str):
    print(f"[version-check] {message}")
    sys.exit(1)


def parse_version(version: str):
    match = VERSION_RE.match(version.strip())
    if not match:
        fail(f"Invalid version '{version}'. Expected format x.x.xxx (e.g. 3.0.015)")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def get_working_version():
    if not VERSION_FILE.exists():
        fail("version.json not found")
    data = json.loads(VERSION_FILE.read_text(encoding="utf-8"))
    return str(data.get("version", "")).strip()


def get_head_version():
    result = subprocess.run(
        ["git", "show", "HEAD:version.json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        return None

    try:
        head_data = json.loads(result.stdout)
        return str(head_data.get("version", "")).strip()
    except json.JSONDecodeError:
        fail("Unable to parse version.json from HEAD")


def main():
    working_version = get_working_version()
    w_major, w_minor, w_patch = parse_version(working_version)

    head_version = get_head_version()
    if head_version is None:
        print("[version-check] Initial commit detected, skip comparison with HEAD")
        sys.exit(0)

    h_major, h_minor, h_patch = parse_version(head_version)

    if (w_major, w_minor) != (h_major, h_minor):
        fail(
            "Major/Minor changed. Per policy, first two digits can only change with explicit approval. "
            f"HEAD={head_version}, WORKTREE={working_version}"
        )

    if w_patch <= h_patch:
        fail(
            "Patch (last 3 digits) must increase on every commit. "
            f"HEAD={head_version}, WORKTREE={working_version}"
        )

    print(f"[version-check] OK: {head_version} -> {working_version}")


if __name__ == "__main__":
    main()