#!/usr/bin/env bash
# Dynamic attach helper. Usage:
#   rasp-attach.sh list
#   rasp-attach.sh status <pid>
#   rasp-attach.sh attach <pid> [--app NAME] [--env ENV]
#   rasp-attach.sh detach <pid>
#
# Must run as the same OS user as the target JVM. The JDK used to run the tool must contain
# the jdk.attach module; by default the target process's own java is used when a pid is given.
set -euo pipefail
HOME_DIR="$(cd "$(dirname "$0")/.." && pwd)"
JAR="$HOME_DIR/rasp-launcher.jar"

pick_java() {
  local pid="${1:-}"
  if [ -n "${RASP_JAVA:-}" ]; then echo "$RASP_JAVA"; return; fi
  if [ -n "$pid" ]; then
    local exe=""
    if [ -e "/proc/$pid/exe" ]; then
      exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
    elif command -v ps >/dev/null; then
      exe="$(ps -o comm= -p "$pid" 2>/dev/null || true)"
    fi
    if [ -n "$exe" ] && [ -x "$exe" ] && [[ "$exe" == */java ]]; then echo "$exe"; return; fi
  fi
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then echo "$JAVA_HOME/bin/java"; return; fi
  echo java
}

JAVA="$(pick_java "${2:-}")"
if [ -n "${2:-}" ] && [ -e "/proc/$2" ]; then
  owner="$(stat -c %U "/proc/$2" 2>/dev/null || true)"
  if [ -n "$owner" ] && [ "$owner" != "$(id -un)" ]; then
    echo "目标进程属于用户 $owner，请切换到该用户执行：sudo -u $owner $0 $*" >&2
    exit 1
  fi
fi
exec "$JAVA" -jar "$JAR" "$@"
