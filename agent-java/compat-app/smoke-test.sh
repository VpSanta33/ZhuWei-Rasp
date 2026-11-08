#!/usr/bin/env bash
# Agent compatibility smoke test on a given JDK (8, 11, 17, 21, ...). Standalone mode, no platform needed.
#
#   JAVA=/path/to/jdk/bin/java agent-java/compat-app/smoke-test.sh <dist/rasp> <compat-app.jar>
#
# Checks: -javaagent start-up and javax.servlet hook; file-read alarms on the request thread, in a thread pool
# and in a CompletableFuture (async context); process start hook; no ERROR in rasp.log; dynamic attach and
# detach with the same JDK.
set -uo pipefail
JAVA="${JAVA:-java}"
SRC="${1:?usage: smoke-test.sh <dist/rasp> <compat-app.jar>}"
APP="${2:?usage: smoke-test.sh <dist/rasp> <compat-app.jar>}"
P1="${P1:-18098}" P2="${P2:-18099}"
WORK="$(mktemp -d)"
RASP="$WORK/rasp"
cp -R "$SRC" "$RASP"
rm -rf "$RASP/logs" "$RASP/cache"
mkdir -p "$RASP/logs"
sed -i.bak 's#^server.url=.*#server.url=#' "$RASP/conf/rasp.properties" && rm -f "$RASP/conf/rasp.properties.bak"
FAILED=0
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
ok() { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; FAILED=1; }
wait_http() { for _ in $(seq 1 120); do curl -s -m 1 -o /dev/null "$1" && return 0; sleep 0.5; done; return 1; }
alarm_for() { # <url substring> <expect async true|false> [attack type, default readFile]
  python3 - "$RASP/logs/alarm.log" "$1" "$2" "${3:-readFile}" <<'EOF'
import json, sys
path, needle, want_async, kind = sys.argv[1], sys.argv[2], sys.argv[3] == "true", sys.argv[4]
try:
    lines = open(path, encoding="utf-8").read().splitlines()
except FileNotFoundError:
    sys.exit(1)
for line in lines:
    try:
        a = json.loads(line)
    except ValueError:
        continue
    r = a.get("request") or {}
    if a.get("attack_type") == kind and needle in (r.get("url") or "") and bool(r.get("async")) == want_async:
        sys.exit(0)
sys.exit(1)
EOF
}

echo "== $("$JAVA" -version 2>&1 | head -1)"
"$JAVA" -javaagent:"$RASP/rasp-launcher.jar" -Drasp.sca.enabled=false -jar "$APP" "$P1" > "$WORK/app1.out" 2>&1 &
PIDS+=($!)
if wait_http "http://127.0.0.1:$P1/hello"; then ok "application started with -javaagent"; else bad "application did not start"; cat "$WORK/app1.out"; exit 1; fi
for path in file pool cf; do curl -s -o /dev/null "http://127.0.0.1:$P1/$path?name=readme.txt"; done
curl -s -o /dev/null "http://127.0.0.1:$P1/exec?arg=compat-check"
sleep 3
grep -q "instrumented javax/servlet/http/HttpServlet" "$RASP/logs/rasp.log" && ok "javax.servlet hook installed" || bad "javax.servlet hook missing"
alarm_for "$P1/file?name=readme.txt" false && ok "alarm on request thread" || bad "no alarm on request thread"
alarm_for "$P1/pool?name=readme.txt" true && ok "alarm in ThreadPoolExecutor task (async context)" || bad "no async alarm from thread pool"
alarm_for "$P1/cf?name=readme.txt" true && ok "alarm in CompletableFuture (ForkJoinPool)" || bad "no async alarm from CompletableFuture"
alarm_for "$P1/exec?arg=compat-check" false command && ok "process start hook (ProcessImpl.start)" || bad "no alarm for process start"
if grep -E " ERROR " "$RASP/logs/rasp.log" > /dev/null; then bad "ERROR in rasp.log"; grep -E " ERROR " "$RASP/logs/rasp.log" | head -5; else ok "no ERROR in rasp.log"; fi

# dynamic attach into a JVM started without the agent, using the same JDK
"$JAVA" -Drasp.sca.enabled=false -jar "$APP" "$P2" > "$WORK/app2.out" 2>&1 &
TARGET=$!
PIDS+=("$TARGET")
wait_http "http://127.0.0.1:$P2/hello" || { bad "second application did not start"; exit 1; }
if "$JAVA" -jar "$RASP/rasp-launcher.jar" attach "$TARGET" > "$WORK/attach.out" 2>&1; then
  curl -s -o /dev/null "http://127.0.0.1:$P2/file?name=readme.txt"
  sleep 3
  alarm_for "$P2/file?name=readme.txt" false && ok "dynamic attach detects" || bad "attached agent produced no alarm"
  if "$JAVA" -jar "$RASP/rasp-launcher.jar" detach "$TARGET" > "$WORK/detach.out" 2>&1 \
     && "$JAVA" -jar "$RASP/rasp-launcher.jar" status "$TARGET" 2>&1 | grep -q "RASP loaded:   no"; then
    ok "detach restores the target"
  else
    bad "detach failed"; cat "$WORK/detach.out"
  fi
else
  bad "attach failed"; cat "$WORK/attach.out"
fi

[ "$FAILED" = 0 ] && echo "== all checks passed" || echo "== some checks FAILED"
exit "$FAILED"
