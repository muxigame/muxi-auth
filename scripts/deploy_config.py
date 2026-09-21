"""Prepare production CZL configuration without exposing credentials in logs.

The server .env is persistent. GitHub Secrets, when provided as a complete pair,
may replace the stored credentials; absent Secrets never erase working values.
Compose resolves the final configuration before any running service is replaced.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Mapping


KEYS = ("MUXI_CZL_CLIENT_ID", "MUXI_CZL_CLIENT_SECRET")
ALIASES = ("Client_ID", "Client_Secret")


def atomic_write(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=".czl-config-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def merge_credentials(text: str, updates: Mapping[str, str]) -> str:
    lines = []
    for line in text.splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else ""
        if key not in updates:
            lines.append(line)
    for key, value in updates.items():
        if not value.strip() or any(char in value for char in "\r\n\0"):
            raise ValueError("CZL credentials must be nonempty, single-line values")
        # JSON quoting handles backslashes and quotes; $$ prevents Compose
        # from interpolating a literal dollar sign inside a secret.
        lines.append(key + "=" + json.dumps(value, ensure_ascii=False).replace("$", "$$"))
    return "\n".join(lines) + "\n"


def prepare(project: Path, compose: Path, environ: Mapping[str, str]) -> None:
    env_file = project / ".env"
    original = env_file.read_bytes()
    updates = {key: environ.get(key, "") for key in KEYS}
    has_values = [bool(value) for value in updates.values()]
    if any(has_values) and not all(has_values):
        raise ValueError("Supply both CZL deployment Secrets or neither; no configuration changed")
    changed = False
    if all(has_values):
        replacement = merge_credentials(original.decode("utf-8-sig"), updates).encode("utf-8")
        if replacement != original:
            backups = project / "incoming" / "config-backups"
            backups.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(backups, 0o700)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            atomic_write(backups / (".env." + stamp), original)
            atomic_write(env_file, replacement)
            changed = True
    try:
        result = subprocess.run(
            ["docker", "compose", "--project-directory", str(project),
             "--env-file", str(env_file), "-f", str(compose), "config", "--format", "json"],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if result.returncode:
            # Never print Compose's output: it contains resolved secrets.
            raise ValueError("Production Compose configuration could not be resolved")
        service = json.loads(result.stdout)["services"]["muxi-auth"]
        resolved = service.get("environment") or {}
        for key, alias in zip(KEYS, ALIASES):
            value = str(resolved.get(key) or resolved.get(alias) or "")
            if not value.strip():
                raise ValueError("CZL production credentials are missing; deployment stopped before restart")
            if all(has_values) and value != updates[key]:
                raise ValueError("CZL credentials changed during Compose resolution; deployment stopped")
        if resolved.get("MUXI_ISSUER", "").rstrip("/") != "https://account.muxigame.com":
            raise ValueError("Production MUXI_ISSUER does not match the registered CZL callback origin")
    except Exception:
        if changed:
            atomic_write(env_file, original)
        raise
    os.chmod(env_file, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=Path, required=True)
    parser.add_argument("--compose", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.project_dir.resolve(), args.compose.resolve(), os.environ)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit("CZL configuration preflight failed; check the credential pair and production issuer. Values were not logged.")
    print("CZL production configuration ready (both credentials present; callback origin verified).")


if __name__ == "__main__":
    main()
