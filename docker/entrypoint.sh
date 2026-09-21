#!/bin/sh
set -eu

umask 077

quality_guard_dir=/var/lib/grok2api-quality-guard
mkdir -p "${quality_guard_dir}"
chown grok2api:grok2api "${quality_guard_dir}"
chmod 0700 "${quality_guard_dir}"

if [ -f "/etc/secrets/config.yaml" ]; then
  GROK2API_CONFIG_SOURCE="/etc/secrets/config.yaml"
elif [ -f "${GROK2API_CONFIG_SOURCE:-}" ]; then
  :
elif [ -f "/app/config.yaml" ]; then
  GROK2API_CONFIG_SOURCE="/app/config.yaml"
fi

if [ ! -f "${GROK2API_CONFIG_SOURCE:-}" ]; then
  echo "missing config: ${GROK2API_CONFIG_SOURCE:-none}" >&2
  echo "provide config.yaml via Secret File or mount to /run/grok2api/config.yaml" >&2
  exit 1
fi

if [ "${GROK2API_CONFIG_SOURCE}" != "/app/config.yaml" ]; then
  cp "${GROK2API_CONFIG_SOURCE}" /app/config.yaml
fi
chown -R grok2api:grok2api /app/config.yaml /app/data 2>/dev/null || true
chmod 0600 /app/config.yaml

if [ -n "${DATABASE_URL:-}" ] && [ -z "${GROK2API_DATABASE_URL:-}" ]; then
  export GROK2API_DATABASE_URL="${DATABASE_URL}"
fi

exec su-exec grok2api:grok2api "$@"
