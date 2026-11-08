#!/usr/bin/env bash
# Removes the ZhuWei-RASP Java agent.
#
#   tools/uninstall.sh [--prefix /opt/rasp] [--tomcat CATALINA_BASE] [--jetty JETTY_BASE] [--wildfly JBOSS_HOME]
#                      [--weblogic DOMAIN_HOME] [--liberty SERVER_DIR] [--systemd-unit NAME.service] [--purge] [--force]
#
#   --tomcat ... --systemd-unit   remove what install.sh added for that server (other settings are untouched)
#   --purge   also delete conf/ (credentials) and logs/ — by default they are kept for audit
#   --force   uninstall even if running JVMs still use the agent
#
# A JVM that loaded the agent keeps it until it restarts (or until tools/rasp-attach.sh detach <pid>);
# removing the files under a running JVM does not unload it.
set -euo pipefail

# default: the installation this script belongs to
PREFIX="$(cd "$(dirname "$0")/.." && pwd)" PURGE=0 FORCE=0
INTEG=()
LIB="$(cd "$(dirname "$0")" && pwd)/integrations.sh"
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
    --tomcat|--jetty|--wildfly|--weblogic|--liberty) INTEG+=("${1#--}:${2:?$1 needs a directory}"); shift 2 ;;
    --systemd-unit) INTEG+=("systemd:${2:?--systemd-unit needs a unit name}"); shift 2 ;;
    --purge) PURGE=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "未知参数：$1（--help 查看用法）" >&2; exit 2 ;;
  esac
done

fail() { echo "卸载失败：$*" >&2; exit 1; }
case "$PREFIX" in
  /*) ;;
  *) fail "--prefix 必须是绝对路径：$PREFIX" ;;
esac
while [ "${PREFIX%/}" != "$PREFIX" ]; do PREFIX="${PREFIX%/}"; done
case "$PREFIX" in
  ""|/bin|/boot|/dev|/etc|/home|/lib|/opt|/proc|/root|/sbin|/sys|/tmp|/usr|/var) fail "拒绝操作系统目录 '$PREFIX'" ;;
esac
[ -f "$PREFIX/rasp-launcher.jar" ] || [ -f "$PREFIX/VERSION" ] || fail "$PREFIX 不是 ZhuWei-RASP 安装目录"

# JVMs started with -javaagent:<prefix>/rasp-launcher.jar
running="$(ps -axo pid=,command= 2>/dev/null | grep -F -- "-javaagent:$PREFIX/rasp-launcher.jar" | grep -v grep || true)"
if [ -n "$running" ]; then
  echo "以下进程仍在使用 Agent（重启并去掉 -javaagent 参数，或执行 rasp-attach.sh detach <pid>）：" >&2
  echo "$running" | cut -c1-160 >&2
  [ "$FORCE" = 1 ] || fail "存在运行中的 JVM，确认后可加 --force"
fi

if [ "${#INTEG[@]}" -gt 0 ]; then
  [ -f "$LIB" ] || fail "缺少 $LIB"
  # shellcheck source=integrations.sh
  . "$LIB"
  for spec in "${INTEG[@]}"; do
    "disable_${spec%%:*}" "${spec#*:}"
  done
fi

if [ "$PURGE" = 1 ]; then
  rm -rf "${PREFIX:?}"
  echo "==> 已删除 $PREFIX（包括配置与日志）"
else
  for f in rasp-launcher.jar rasp-bootstrap.jar rasp-core.jar VERSION DISABLE; do
    rm -f "${PREFIX:?}/$f"
  done
  rm -rf "${PREFIX:?}/cache" "${PREFIX:?}/backup" "${PREFIX:?}/dump" "${PREFIX:?}/tools"
  echo "==> 已卸载 Agent，保留 $PREFIX/conf 与 $PREFIX/logs（加 --purge 一并删除）"
fi
