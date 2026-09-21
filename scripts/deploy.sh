#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: deploy.sh <release-archive>" >&2
  exit 2
fi

archive="$1"
project_dir="/opt/muxi-auth"
incoming="$project_dir/incoming"
stage="$project_dir/.stage"

if [[ ! -f "$archive" ]]; then
  echo "release archive not found: $archive" >&2
  exit 2
fi
if [[ ! -f "$project_dir/.env" ]]; then
  echo "$project_dir/.env is missing" >&2
  exit 2
fi

rm -rf "$stage"
mkdir -p "$stage" "$project_dir/data" "$incoming"
tar -xzf "$archive" -C "$stage"

# Keep only persistent runtime state in the project root.
find "$project_dir" -mindepth 1 -maxdepth 1 \
  ! -name '.env' ! -name 'data' ! -name 'incoming' ! -name '.stage' \
  -exec rm -rf {} +
cp -a "$stage"/. "$project_dir"/
rm -rf "$stage"

cd "$project_dir"
docker compose -f compose.prod.yaml build muxi-auth

# One-time migration from the account database that used to live inside Better MC.
legacy="$incoming/battermc-legacy.db"
migration_marker="$project_dir/data/.legacy-battermc-imported"
if [[ ! -f "$migration_marker" ]]; then
  if docker inspect better-mc-remake-server >/dev/null 2>&1; then
    docker cp better-mc-remake-server:/app/server/data/battermc.db "$legacy" 2>/dev/null || true
  fi
  if [[ -f "$legacy" ]]; then
    docker compose -f compose.prod.yaml run --rm \
      -v "$legacy:/legacy/battermc.db:ro" \
      muxi-auth python scripts/import_battermc.py /legacy/battermc.db
    touch "$migration_marker"
  fi
fi

docker compose -f compose.prod.yaml up -d --remove-orphans

for _ in $(seq 1 45); do
  if curl --fail --silent http://127.0.0.1:9000/healthz >/dev/null; then
    break
  fi
  if [[ "$_" == "45" ]]; then
    docker compose -f compose.prod.yaml ps
    docker compose -f compose.prod.yaml logs --tail=160
    exit 1
  fi
  sleep 2
done

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

cat > "$vhost" <<'NGINX_HTTPS'
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

nginx -t
nginx -s reload
curl --fail --silent https://account.muxigame.com/healthz >/dev/null
echo "muxi-auth deployment is healthy and HTTPS is ready"
docker image prune -f >/dev/null 2>&1 || true
