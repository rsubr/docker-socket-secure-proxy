#!/usr/bin/env bash
# End-to-end test against the local Docker daemon. Exits non-zero on any failure.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN=${BIN:-bin/docker-socket-secure-proxy}
PORT=${PORT:-9999}
SOCK=${DOCKER_SOCKET:-/var/run/docker.sock}
NAME=proxytest-$$
OUT=$(mktemp -d)
PROXY="tcp://127.0.0.1:$PORT"
fail=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; fail=1; }

cleanup() {
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null && wait "$PROXY_PID" 2>/dev/null
  docker rm -f "$NAME" >/dev/null 2>&1
  [ "${KEEP:-}" = 1 ] || rm -rf "$OUT"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: make build"; exit 2; }
docker image inspect alpine >/dev/null 2>&1 || docker pull -q alpine >/dev/null || exit 2
docker run -d --name "$NAME" -e OPENAPI_KEY=supersecret123 -e DB_PASSWORD=hunter2 \
  --label traefik.enable=true --label "traefik.http.routers.t.rule=Host(\`t.example.com\`)" \
  alpine sleep 3600 >/dev/null || exit 2

SYSTEM=1 LISTEN_ADDR=127.0.0.1:$PORT DOCKER_SOCKET=$SOCK "$BIN" >"$OUT/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 50); do "$BIN" --listen 127.0.0.1:$PORT --healthcheck 2>/dev/null && break; sleep 0.1; done
"$BIN" --listen 127.0.0.1:$PORT --healthcheck && ok "healthcheck" || bad "healthcheck"

D() { docker -H "$PROXY" "$@"; }
IMG=$(docker inspect -f '{{.Image}}' "$NAME")

# Control: direct socket shows the secrets.
docker inspect "$NAME" >"$OUT/direct.txt"
grep -q supersecret123 "$OUT/direct.txt" && ok "control: direct socket exposes secrets" || bad "control did not show secrets"

run() { # name, args...
  local n=$1; shift
  D "$@" >"$OUT/$n.txt" 2>&1 && ok "docker $*" || bad "docker $* (exit $?): $(head -c 300 "$OUT/$n.txt")"
}
run ps ps
run psa ps -a
run images images
run inspect_c inspect "$NAME"
run inspect_i inspect "$IMG"
run history history alpine
run info info
run version version
run netls network ls
run netinspect network inspect bridge
run volls volume ls
run df system df
run events events --since 1m --until 0s
D events --since 1m --until 0s --filter "container=$NAME" >"$OUT/events.txt" 2>&1

# Secrets must never appear in any proxied output.
if grep -rqE 'supersecret123|hunter2' "$OUT" --include='*.txt' --exclude=direct.txt; then
  bad "secret leaked:"; grep -rnE 'supersecret123|hunter2' "$OUT" --include='*.txt' --exclude=direct.txt | head
else ok "no secret in any proxied output"; fi
grep -q 'OPENAPI_KEY=REDACTED' "$OUT/inspect_c.txt" && ok "env key kept, value redacted" || bad "OPENAPI_KEY=REDACTED missing"
grep -q 'DB_PASSWORD=REDACTED' "$OUT/inspect_c.txt" && ok "DB_PASSWORD redacted" || bad "DB_PASSWORD=REDACTED missing"
grep -q '"traefik.enable": "true"' "$OUT/inspect_c.txt" && ok "labels intact" || bad "labels missing"
grep -q 'traefik.http.routers.t.rule' "$OUT/inspect_c.txt" && ok "router label intact" || bad "router label missing"
D ps -a --format '{{.Labels}}' | grep -q 'traefik.enable=true' && ok "ps labels intact" || bad "ps labels"

# Write commands must fail clearly.
for cmd in "run --rm alpine true" "stop $NAME" "rm -f $NAME" "pull alpine" "exec $NAME id" "cp $NAME:/etc/hostname -" "export $NAME" "save alpine" "logs $NAME" "attach $NAME" "top $NAME"; do
  if D $cmd >"$OUT/w.out" 2>&1; then bad "docker $cmd unexpectedly succeeded"
  else grep -qiE 'docker-socket-secure-proxy|not allowed|denied|blocked|upgrade to tcp' "$OUT/w.out" && ok "blocked: docker $cmd" || bad "docker $cmd failed without proxy message: $(head -c 200 "$OUT/w.out")"; fi
done
docker inspect "$NAME" -f '{{.State.Running}}' | grep -q true && ok "container still running" || bad "container disturbed"

# Traefik-like access via curl.
B=http://127.0.0.1:$PORT
ID=$(docker inspect -f '{{.Id}}' "$NAME")
for p in /_ping /version /v1.47/version /v1.47/containers/json /containers/json?all=1 "/containers/$ID/json" /networks /v1.47/networks /info /volumes /images/json; do
  code=$(curl -s -o "$OUT/c.out" -w '%{http_code}' "$B$p"); cp "$OUT/c.out" "$OUT/curl_$(echo "$p" | tr '/?=' '___').txt"
  [ "$code" = 200 ] && ok "curl $p -> 200" || bad "curl $p -> $code"
done
grep -rqE 'supersecret123|hunter2' "$OUT"/curl_* && bad "secret in curl output" || ok "no secret in curl output"
curl -s "$B/containers/$ID/json" | grep -q 'OPENAPI_KEY=REDACTED' && ok "curl inspect redacted" || bad "curl inspect not redacted"
curl -s "$B/containers/json" | grep -q '"traefik.enable":"true"' && ok "curl list labels intact" || bad "curl list labels"
curl -sI "$B/_ping" | grep -qi '^api-version' && ok "Api-Version header passed" || bad "Api-Version header missing"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/containers/$ID/stop")" = 405 ] && ok "curl POST -> 405" || bad "curl POST not 405"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/containers/$ID/archive?path=/etc")" = 403 ] && ok "archive -> 403" || bad "archive not 403"

# Live event stream: an event must arrive while the stream is still open.
curl -sN --max-time 8 "$B/events" >"$OUT/stream.txt" &
CP=$!
sleep 1
docker run --rm --label token=x -e STREAM_SECRET=streamsecret999 alpine true >/dev/null 2>&1
start=$(date +%s)
for _ in $(seq 40); do grep -q '"Action":"die"\|"status":"die"' "$OUT/stream.txt" && break; sleep 0.1; done
if grep -q '"Type":"container"' "$OUT/stream.txt" && kill -0 $CP 2>/dev/null; then ok "events streamed live (curl still connected)"; else bad "no live events"; fi
kill $CP 2>/dev/null; wait $CP 2>/dev/null
grep -q streamsecret999 "$OUT/stream.txt" && bad "secret in event stream" || ok "event stream clean"

# Graceful shutdown on SIGTERM.
kill -TERM "$PROXY_PID"; wait "$PROXY_PID"; rc=$?; PROXY_PID=
[ $rc = 0 ] && ok "graceful SIGTERM exit" || bad "SIGTERM exit code $rc"

[ $fail = 0 ] && echo "E2E OK" || { echo "E2E FAILED (artifacts: $OUT)"; KEEP=1; }
exit $fail
