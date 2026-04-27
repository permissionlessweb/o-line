#!/usr/bin/env python3
"""
headscale-scrape-creds.py

Parse stdout from a headscale-on-Akash deployment (as streamed by
`oline manage logs <dseq>`) and extract the preauth key + admin API key
that the container's entrypoint prints on first boot.

The entrypoint emits a fixed sequence of banner lines:

    [headscale]: === Creating preauth key (reusable, 10yr expiry) ===
    [headscale]: 2026-04-20T18:30:12Z TRC expiration has been set ...
    [headscale]: re
    [headscale]: === Existing users ===
    ...
    [headscale]: === API key for remote management ===
    [headscale]: erqer.reqwr

The parser is a minimal two-state machine: a banner switches it into
"expect <kind>" mode; the next line that (after ANSI-stripping and
dropping the `[headscale]:` prefix) matches the expected shape is the
credential. Subsequent banners reset the state, so a corrupted stream
can't silently alias one cred for another.

Exit codes:
  0 — both creds captured
  1 — stream ended with at least one cred missing
  2 — malformed input
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Optional, TextIO

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\[(?:\d{1,3};)*\d{1,3}m")
HEAD_PREFIX_RE = re.compile(r"^\s*\[headscale\]:\s*")

BANNER_PREAUTH = "=== Creating preauth key"
BANNER_API_KEY = "=== API key for remote management ==="

# Preauth keys are 48 lowercase hex characters.
PREAUTH_RE = re.compile(r"^[0-9a-f]{48}$")
# Admin API keys are `<prefix>.<body>` where both sides are base64-ish.
API_KEY_RE = re.compile(r"^[A-Za-z0-9]{4,16}\.[A-Za-z0-9+/=]{30,64}$")


def clean(line: str) -> str:
    """Strip ANSI colour codes and the `[headscale]:` container prefix."""
    s = ANSI_RE.sub("", line).rstrip("\r\n")
    s = HEAD_PREFIX_RE.sub("", s)
    return s.strip()


def scrape(stream: TextIO) -> tuple[Optional[str], Optional[str]]:
    """Walk the log stream, return (preauth_key, admin_api_key)."""
    state: Optional[str] = None  # "preauth" | "api" | None
    preauth: Optional[str] = None
    api_key: Optional[str] = None

    for raw in stream:
        line = clean(raw)
        if not line:
            continue

        if BANNER_PREAUTH in line:
            state = "preauth"
            continue
        if BANNER_API_KEY in line:
            state = "api"
            continue
        if line.startswith("==="):
            # Any other banner cancels the pending capture.
            state = None
            continue

        if state == "preauth" and PREAUTH_RE.match(line):
            preauth = line
            state = None
        elif state == "api" and API_KEY_RE.match(line):
            api_key = line
            state = None

        if preauth and api_key:
            break

    return preauth, api_key


def emit(
    preauth: Optional[str],
    api_key: Optional[str],
    fmt: str,
    headscale_url: Optional[str],
) -> None:
    if fmt == "json":
        payload = {"preauth_key": preauth, "admin_api_key": api_key}
        if headscale_url:
            payload["headscale_url"] = headscale_url
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif fmt == "env":
        if headscale_url:
            sys.stdout.write(f"HEADSCALE_URL={headscale_url}\n")
        if preauth:
            sys.stdout.write(f"HEADSCALE_KEY={preauth}\n")
        if api_key:
            sys.stdout.write(f"HEADSCALE_API_KEY={api_key}\n")
    else:  # plain
        if preauth:
            sys.stdout.write(f"preauth: {preauth}\n")
        if api_key:
            sys.stdout.write(f"api_key: {api_key}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--format",
        choices=("plain", "json", "env"),
        default="plain",
        help="Output format (default: plain)",
    )
    ap.add_argument(
        "--input",
        type=argparse.FileType("r"),
        default=sys.stdin,
        help="Input log file (default: stdin)",
    )
    ap.add_argument(
        "--headscale-url",
        default=os.environ.get("HEADSCALE_URL"),
        help="Headscale control plane URL, included in env/json output",
    )
    args = ap.parse_args()

    try:
        preauth, api_key = scrape(args.input)
    except (KeyboardInterrupt, BrokenPipeError):
        return 2

    emit(preauth, api_key, args.format, args.headscale_url)

    missing = [
        name for name, val in (("preauth", preauth), ("api_key", api_key)) if not val
    ]
    if missing:
        print(f"WARN: missing credential(s): {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
