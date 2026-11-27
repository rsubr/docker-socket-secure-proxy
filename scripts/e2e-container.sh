#!/usr/bin/env bash
# Builds the image, runs it against the local socket, checks redaction. Works with BuildKit or the legacy builder.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-19377}; N=$$
trap 'docker rm -f dssp-proxy-$N dssp-victim-$N >/dev/null 2>&1; docker rmi dssp:e2e-$N >/dev/null 2>&1' EXIT
docker build -q -t dssp:e2e-$N .
docker run -d --name dssp-proxy-$N -p 127.0.0.1:$PORT:$PORT -e PORT=$PORT --read-only --cap-drop ALL \
  -v /var/run/docker.sock:/var/run/docker.sock:ro dssp:e2e-$N >/dev/null
docker run -d --name dssp-victim-$N -e SECRET_KEY=abc123xyz alpine sleep 120 >/dev/null
for _ in $(seq 30); do [ "$(docker inspect -f '{{.State.Health.Status}}' dssp-proxy-$N)" = healthy ] && break; sleep 1; done
out=$(docker -H tcp://127.0.0.1:$PORT inspect dssp-victim-$N)
grep -q 'SECRET_KEY=REDACTED' <<<"$out" && ! grep -q abc123xyz <<<"$out" && echo "PASS: container redaction" || { echo "FAIL"; exit 1; }
