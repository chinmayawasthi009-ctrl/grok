#!/bin/sh
set -eu

umask 077

quality_guard_dir=/var/lib/grok2api-quality-guard
mkdir -p "${quality_guard_dir}"
chown grok2api:grok2api "${quality_guard_dir}"
chmod 0700 "${quality_guard_dir}"

if [ -f "${GROK2API_CONFIG_SOURCE:-}" ]; then
  cp "${GROK2API_CONFIG_SOURCE}" /app/config.yaml
elif [ -f "/etc/secrets/config.yaml" ]; then
  cp /etc/secrets/config.yaml /app/config.yaml
elif [ -f "/run/grok2api/config.yaml" ]; then
  cp /run/grok2api/config.yaml /app/config.yaml
elif [ -f "/app/config.yaml" ]; then
  : # already exists
elif [ -f "/app/config.example.yaml" ]; then
  cp /app/config.example.yaml /app/config.yaml
else
  echo "missing config: neither ${GROK2API_CONFIG_SOURCE:-/run/grok2api/config.yaml} nor /etc/secrets/config.yaml found" >&2
  exit 1
fi

chown grok2api:grok2api /app/config.yaml
chmod 0600 /app/config.yaml

exec su-exec grok2api:grok2api "$@"
