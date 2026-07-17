#!/usr/bin/env python3
"""Validate and serialize declarative Infiproxy module manifests."""

from __future__ import annotations

import argparse
import re
import stat
import sys
from pathlib import Path

FIELDS = (
    "id",
    "name",
    "kind",
    "role",
    "repo",
    "upstream",
    "ref",
    "driver",
    "root",
    "binary",
    "service",
    "config",
    "asset_amd64",
    "asset_arm64",
)
ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
REF_RE = re.compile(r"[A-Za-z0-9_./-]{1,120}\Z")
FILE_RE = re.compile(r"[A-Za-z0-9._+-]{1,80}\Z")
SERVICE_RE = re.compile(r"[A-Za-z0-9_.@-]{1,120}\.service\Z")
ASSET_RE = re.compile(r"[A-Za-z0-9._+{}-]{1,180}\Z")
PATH_RE = re.compile(r"/etc/[A-Za-z0-9/._+-]{1,240}\Z")


class ManifestError(ValueError):
    """Raised when a manifest violates the declarative contract."""


def parse(path: Path, *, root_owned: bool = False, registration: bool = False) -> dict[str, str]:
    """Read and validate one manifest without evaluating its contents."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024:
        raise ManifestError("manifest must be a regular file no larger than 16 KiB")
    if root_owned and (info.st_uid != 0 or info.st_mode & 0o022):
        raise ManifestError("installed manifest must be root-owned and not group/world-writable")

    values: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ManifestError(f"line {number}: expected key=value")
        key, value = (part.strip() for part in line.split("=", 1))
        if key not in FIELDS:
            raise ManifestError(f"line {number}: unknown key {key}")
        if key in values:
            raise ManifestError(f"line {number}: duplicate key {key}")
        if any(ord(char) < 32 or ord(char) > 126 or char in "|=" for char in value):
            raise ManifestError(f"line {number}: unsafe value")
        values[key] = value

    missing = set(FIELDS) - values.keys()
    if missing:
        raise ManifestError(f"missing fields: {', '.join(sorted(missing))}")
    if not ID_RE.fullmatch(values["id"]) or path.stem != values["id"]:
        raise ManifestError("id must be safe and match the file name")
    if not all(0 < len(values[field]) <= limit for field, limit in (("name", 80), ("kind", 48), ("role", 160))):
        raise ManifestError("name, kind or role length is invalid")
    if not REPO_RE.fullmatch(values["repo"]):
        raise ManifestError("invalid GitHub owner/repo")
    if values["upstream"] not in {"release", "commit"}:
        raise ManifestError("unsupported upstream")
    if values["upstream"] == "commit" and (
        not REF_RE.fullmatch(values["ref"])
        or values["ref"].startswith("/")
        or ".." in values["ref"]
    ):
        raise ManifestError("invalid commit ref")
    if values["driver"] not in {"release", "headscale", "mtproto-source"}:
        raise ManifestError("unsupported driver")
    if values["root"] not in {"cores", "modules"}:
        raise ManifestError("unsupported runtime root")
    if not FILE_RE.fullmatch(values["binary"]):
        raise ManifestError("invalid binary name")
    if not SERVICE_RE.fullmatch(values["service"]):
        raise ManifestError("invalid service name")
    if not PATH_RE.fullmatch(values["config"]) or ".." in values["config"]:
        raise ManifestError("invalid config path")
    if values["upstream"] == "release" and not all(
        ASSET_RE.fullmatch(values[field]) for field in ("asset_amd64", "asset_arm64")
    ):
        raise ManifestError("invalid release asset template")
    if values["driver"] == "release" and not (
        values["root"] == "cores"
        and values["service"] == f"infiproxy-{values['id']}.service"
        and values["config"].startswith(f"/etc/infiproxy-cores/{values['id']}/")
    ):
        raise ManifestError("generic modules must use their own core service and config tree")
    if values["driver"] == "headscale" and not (
        values["id"] == "headscale"
        and values["root"] == "modules"
        and values["service"] == "headscale.service"
        and values["config"] == "/etc/headscale/config.yaml"
    ):
        raise ManifestError("invalid Headscale module contract")
    if values["driver"] == "mtproto-source" and not (
        values["id"] == "mtproto"
        and values["root"] == "cores"
        and values["service"] == "infiproxy-mtproto.service"
        and values["config"].startswith("/etc/infiproxy-cores/mtproto/")
    ):
        raise ManifestError("invalid MTProto module contract")
    if registration and not (
        values["upstream"] == "release"
        and values["driver"] == "release"
        and values["root"] == "cores"
    ):
        raise ManifestError("registration only supports generic release modules under cores")
    return values


def main() -> int:
    """Run the small CLI consumed by the root module updater."""
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("read", "validate", "list"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--root-owned", action="store_true")
    parser.add_argument("--registration", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "list":
            module_ids = []
            for path in sorted(args.path.glob("*.module")):
                values = parse(path, root_owned=args.root_owned)
                module_ids.append(values["id"])
            print("\n".join(module_ids))
        else:
            values = parse(
                args.path,
                root_owned=args.root_owned,
                registration=args.registration,
            )
            if args.command == "read":
                print("|".join(values[field] for field in FIELDS))
    except (OSError, UnicodeError, ManifestError) as error:
        print(f"manifest error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
