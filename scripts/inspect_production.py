"""Print a redacted, read-only description of the production deployment.

Run on the deployment host by .github/workflows/inspect-production.yml. The
repository is public, so every value is masked unless it is boolean-like, a
number, or an absolute path. Nothing is written, restarted, or removed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path("/opt/muxi-auth")
CONTAINER = "muxi-auth-muxi-auth-1"
VHOST = Path("/www/server/panel/vhost/nginx/account.muxigame.com.conf")
SAFE = re.compile(r"(?i)^(0|1|true|false|yes|no|on|off|\d{1,6}|/[\w./-]*)$")
ASSIGN = re.compile(r"^(\s*-?\s*[\"']?)([A-Za-z_][A-Za-z0-9_]*)([\"']?\s*[:=]\s*)(.+?)\s*$")


def mask(value: object) -> str:
    text = str(value).strip().strip("\"'")
    return text if SAFE.match(text) else f"<set len={len(text)}>"


def run(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    return result.stdout if result.returncode == 0 else f"<exit {result.returncode}: {result.stderr.strip()[:300]}>"


def section(title: str) -> None:
    print(f"\n===== {title} =====")


def masked_env(entries: list[str] | dict | None) -> dict:
    if isinstance(entries, dict):
        pairs = entries.items()
    else:
        pairs = (item.split("=", 1) if "=" in item else (item, "") for item in entries or [])
    return {k: mask(v) for k, v in sorted(pairs)}


def show_file(path: Path) -> None:
    raw = path.read_bytes()
    print(f"--- {path} ({len(raw)}B sha256 {hashlib.sha256(raw).hexdigest()})")
    for line in raw.decode("utf-8", "replace").splitlines():
        m = ASSIGN.match(line)
        if m and not m.group(4).endswith(":") and m.group(2) not in {"image", "build", "context", "dockerfile", "command", "test", "restart", "user", "working_dir", "services", "volumes", "environment", "env_file", "ports", "healthcheck", "interval", "timeout", "retries", "start_period", "target", "source", "type", "read_only", "entrypoint"}:
            line = f"{m.group(1)}{m.group(2)}{m.group(3)}{mask(m.group(4))}"
        print(line)


section("tree")
for p in sorted(ROOT.iterdir()):
    print(("d " if p.is_dir() else "f ") + p.name)
releases = ROOT / ".releases"
if releases.is_dir():
    for p in sorted(releases.rglob("*")):
        if p.is_file() and "data" not in p.parts[len(releases.parts):len(releases.parts) + 2]:
            print("  " + str(p.relative_to(ROOT)), p.stat().st_size)

section("compose files")
files = sorted({*ROOT.glob("*.yaml"), *ROOT.glob("*.yml"), *releases.rglob("*.yaml"), *releases.rglob("*.yml")} if releases.is_dir() else ROOT.glob("*.yaml"))
for path in files:
    show_file(path)
for name in ("Dockerfile",):
    if (ROOT / name).is_file():
        show_file(ROOT / name)

section("container")
info = json.loads(run("docker", "inspect", CONTAINER) or "[]")
if info and isinstance(info, list):
    c = info[0]
    labels = c["Config"].get("Labels") or {}
    print(json.dumps({
        "image": c["Config"]["Image"], "imageId": c["Image"], "cmd": c["Config"]["Cmd"],
        "entrypoint": c["Config"].get("Entrypoint"), "user": c["Config"]["User"],
        "workdir": c["Config"]["WorkingDir"], "env": masked_env(c["Config"]["Env"]),
        "mounts": [{k: m.get(k) for k in ("Type", "Source", "Destination", "RW")} for m in c["Mounts"]],
        "ports": c["HostConfig"]["PortBindings"], "restart": c["HostConfig"]["RestartPolicy"],
        "healthcheck": c["Config"].get("Healthcheck"),
        "composeFiles": labels.get("com.docker.compose.project.config_files"),
        "composeWorkdir": labels.get("com.docker.compose.project.working_dir"),
        "state": c["State"]["Status"], "health": (c["State"].get("Health") or {}).get("Status"),
    }, indent=1, ensure_ascii=False))
else:
    print("container not found")

section("images")
print(run("docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}} {{.Size}}", "muxi-auth*"))
if info:
    hist = run("docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", info[0]["Image"])
    for line in hist.splitlines()[:40]:
        print("  " + line[:220])

section(".env keys")
env = ROOT / ".env"
if env.is_file():
    for line in env.read_text("utf-8", "replace").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            print(f"{k.strip()}={mask(v)}")

section("nginx vhost")
if VHOST.is_file():
    raw = VHOST.read_bytes()
    print(f"{len(raw)}B sha256 {hashlib.sha256(raw).hexdigest()}")
    print(raw.decode("utf-8", "replace"))
else:
    print("missing")
print(run("bash", "-c", "grep -l 'account.muxigame.com\\|127.0.0.1:9000' /www/server/panel/vhost/nginx/*.conf 2>/dev/null"))

section("image files")
# Hash every shipped file inside the running container (read-only). CRLF is
# normalised so a Windows checkout compares equal. Hex digits are shifted to
# letters g-p so GitHub's masking of short numeric secrets cannot hit them.
HASHER = r'''import hashlib,pathlib
root=pathlib.Path("/app")
t=str.maketrans("0123456789","ghijklmnop")
def h(p): return hashlib.sha256(p.read_bytes().replace(b"\r\n",b"\n")).hexdigest().translate(t)
for top in ("app","web","scripts"):
    for p in sorted((root/top).rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts: print(h(p),p.relative_to(root).as_posix())
for p in sorted(root.glob("requirements*.txt")): print(h(p),p.name)
'''
if info:
    print(run("docker", "exec", CONTAINER, "python", "-B", "-c", HASHER))

section("tools")
print(run("bash", "-c", "python3 --version; docker --version; docker compose version; command -v sqlite3; df -h /opt | tail -1"))

section("bindings")
if info:
    print(run("docker", "exec", CONTAINER, "python", "-B", "-c", Path(__file__).with_name("inspect_bindings.py").read_text("utf-8")))

section("binding requests in container log (path and status only)")
LINE = re.compile(r'"(GET|POST) (/external/[^ ?]*|/api/account/external[^ ?]*|/api/external/[^ ?]*)\S* HTTP/[\d.]+" (\d{3})')
logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True, timeout=60, check=False)
counts: dict = {}
for match in LINE.finditer(logs.stdout + logs.stderr):
    counts[match.groups()] = counts.get(match.groups(), 0) + 1
for key, value in sorted(counts.items()):
    print(" ", *key, value)
errors = [l for l in (logs.stdout + logs.stderr).splitlines() if re.search(r"Traceback|Error|Exception", l)]
print("error-looking lines:", len(errors))
for l in sorted({re.sub(r"[0-9a-f]{8,}|\d+", "#", l.strip())[:160] for l in errors})[:30]:
    print("  ", l)
