#!/usr/bin/env bash
# The only way muxi-auth reaches production: run by .github/workflows/deploy.yml
# for a v* tag. Do not run it by hand and do not patch the server around it; if
# a release cannot go out through CI, fix this script or the workflow.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: deploy.sh <release-archive> <release-tag>" >&2
  exit 2
fi

archive="$1"
release="$2"
project_dir="/opt/muxi-auth"
incoming="$project_dir/incoming"
stage="$project_dir/.stage"
container="muxi-auth-muxi-auth-1"
compose=(docker compose -f compose.prod.yaml)

if [[ ! "$release" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "release tag must look like v1.2.3: $release" >&2
  exit 2
fi
if [[ ! -f "$archive" ]]; then
  echo "release archive not found: $archive" >&2
  exit 2
fi
if [[ ! -f "$project_dir/.env" ]]; then
  echo "$project_dir/.env is missing" >&2
  exit 2
fi

mkdir -p "$incoming"
exec 9>"$incoming/.deploy.lock"
flock -n 9 || { echo "another deployment is running" >&2; exit 1; }

rm -rf "$stage"
mkdir -p "$stage"
# `data` is a bind mount. The image runs as uid/gid 10001, so a root-owned
# host directory would make SQLite fail with "unable to open database file".
install -d -m 0750 -o 10001 -g 10001 "$project_dir/data"
tar -xzf "$archive" -C "$stage"

# Validate the runtime configuration before touching the running release.
python3 "$stage/scripts/deploy_config.py" \
  --project-dir "$project_dir" --compose "$stage/compose.prod.yaml"

# Consistent SQLite backup taken through the running container (it knows the
# configured database path). Code rollbacks keep the live database; restoring a
# backup is a separate disaster-recovery decision.
previous_image=""
if docker inspect "$container" >/dev/null 2>&1; then
  previous_image="$(docker inspect -f '{{.Image}}' "$container")"
  docker tag "$previous_image" muxi-auth:previous
  docker exec -e RELEASE="$release" "$container" python -B -c '
import os, pathlib, sqlite3
target = pathlib.Path("/app/data/.release-backups") / os.environ["RELEASE"]
target.mkdir(parents=True, exist_ok=True)
source = sqlite3.connect(os.environ["MUXI_DATABASE_PATH"])
backup = sqlite3.connect(target / "before.db")
source.backup(backup)
status = backup.execute("pragma quick_check").fetchone()[0]
backup.close(); source.close()
if status != "ok":
    raise SystemExit("backup quick_check failed: " + status)
print("database backed up to", target / "before.db")
'
  # Keep the ten most recent backups.
  docker exec "$container" sh -c 'cd /app/data/.release-backups && ls -1t | tail -n +11 | xargs -r rm -rf'
fi

# The repository is the whole deployment: keep only secrets, data and the
# deploy inbox; everything else comes from the release archive.
find "$project_dir" -mindepth 1 -maxdepth 1 \
  ! -name '.env' ! -name 'data' ! -name 'incoming' ! -name '.stage' \
  -exec rm -rf {} +
cp -a "$stage"/. "$project_dir"/
rm -rf "$stage"

cd "$project_dir"
export MUXI_RELEASE="$release"
"${compose[@]}" build muxi-auth
"${compose[@]}" up -d --no-build --remove-orphans muxi-auth

healthy() {
  for _ in $(seq 1 45); do
    if curl --fail --silent http://127.0.0.1:9000/healthz >/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

if ! healthy; then
  echo "release $release is unhealthy" >&2
  "${compose[@]}" ps || true
  "${compose[@]}" logs --tail=160 || true
  if [[ -n "$previous_image" ]]; then
    echo "rolling back to the previous image" >&2
    MUXI_RELEASE=previous "${compose[@]}" up -d --no-build muxi-auth
    healthy && echo "rolled back; previous image is serving" >&2
  fi
  exit 1
fi

vhost="/www/server/panel/vhost/nginx/account.muxigame.com.conf"
mkdir -p /var/www/letsencrypt

# HTTP-only config first so ACME can complete on a fresh machine.
if [[ ! -f /etc/letsencrypt/live/account.muxigame.com/fullchain.pem ]]; then
  cat > "$vhost" <<'NGINX_HTTP'
server {
    listen 80;
    listen [::]:80;
    server_name account.muxigame.com;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type text/plain;
        try_files $uri =404;
    }

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto http;
    }
}
NGINX_HTTP
  nginx -t
  nginx -s reload
  certbot certonly --webroot -w /var/www/letsencrypt \
    -d account.muxigame.com --non-interactive --agree-tos --register-unsafely-without-email
fi

desired="$(mktemp)"
cat > "$desired" <<'NGINX_HTTPS'
server {
    listen 80;
    listen [::]:80;
    server_name account.muxigame.com;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type text/plain;
        try_files $uri =404;
    }

    location / {
        return 301 https://account.muxigame.com$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name account.muxigame.com;

    ssl_certificate /etc/letsencrypt/live/account.muxigame.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/account.muxigame.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MUXIGAME_SSL:10m;
    ssl_session_tickets off;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
NGINX_HTTPS

# Rewrite and reload Nginx only when the site config actually changes.
if ! cmp -s "$desired" "$vhost"; then
  cp "$vhost" "$incoming/nginx.conf.before" 2>/dev/null || true
  cp "$desired" "$vhost"
  if ! nginx -t; then
    [[ -f "$incoming/nginx.conf.before" ]] && cp "$incoming/nginx.conf.before" "$vhost"
    rm -f "$desired"
    exit 1
  fi
  nginx -s reload
fi
rm -f "$desired"

curl --fail --silent https://account.muxigame.com/healthz >/dev/null
python3 "$project_dir/scripts/check_external_auth.py"

# Keep the running release and the one before it; drop older CI-built tags.
for tag in $(docker image ls muxi-auth --format '{{.Tag}}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V); do
  [[ "$tag" == "$release" ]] && continue
  docker image rm "muxi-auth:$tag" >/dev/null 2>&1 || true
done
docker image prune -f >/dev/null 2>&1 || true
echo "muxi-auth $release is live and healthy"
