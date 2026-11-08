#!/usr/bin/env bash
# Removes the ZhuWei-RASP Java agent.
#
#   tools/uninstall.sh [--prefix /opt/rasp] [--tomcat CATALINA_BASE] [--purge] [--force]
#
#   --tomcat  remove the block install.sh added to <CATALINA_BASE>/bin/setenv.sh
#   --purge   also delete conf/ (credentials) and logs/ — by default they are kept for audit
#   --force   uninstall even if running JVMs still use the agent
#
# A JVM that loaded the agent keeps it until it restarts (or until tools/rasp-attach.sh detach <pid>);
# removing the files under a running JVM does not unload it.
set -euo pipefail

# default: the installation this script belongs to
PREFIX="$(cd "$(dirname "$0")/.." && pwd)" TOMCAT="" PURGE=0 FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
    --tomcat) TOMCAT="${2:?--tomcat needs CATALINA_BASE}"; shift 2 ;;
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

MARK_BEGIN="# >>> zhuwei-rasp >>>"
MARK_END="# <<< zhuwei-rasp <<<"
if [ -n "$TOMCAT" ]; then
  SETENV="$TOMCAT/bin/setenv.sh"
  if [ -f "$SETENV" ] && grep -qF "$MARK_BEGIN" "$SETENV"; then
    tmp="$SETENV.rasp-tmp"
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip' "$SETENV" > "$tmp"
    # keep the file's mode, drop the blank line install.sh added before the block
    awk 'NR==1{prev=$0;next} {print prev; prev=$0} END{if (NR>0 && prev!="") print prev}' "$tmp" > "$tmp.2"
    chmod --reference="$SETENV" "$tmp.2" 2>/dev/null || chmod "$(stat -f %Lp "$SETENV" 2>/dev/null || echo 755)" "$tmp.2"
    mv -f "$tmp.2" "$SETENV"
    rm -f "$tmp"
    echo "==> 已从 $SETENV 移除 RASP 配置"
  else
    echo "==> $SETENV 中没有 RASP 配置"
  fi
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
