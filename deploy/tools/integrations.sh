# shellcheck shell=bash
# Application-server integrations shared by install.sh and uninstall.sh (sourced, not executed).
#
# Each integration adds the agent the way the server vendor intends and marks what it adds, so uninstall
# removes exactly that and leaves the rest of the configuration byte-for-byte unchanged:
#   tomcat   <CATALINA_BASE>   bin/setenv.sh               CATALINA_OPTS
#   jetty    <JETTY_BASE>      start.d/zhuwei-rasp.ini     --exec + JVM option
#   wildfly  <JBOSS_HOME>      bin/standalone.conf         JAVA_OPTS + jboss.modules.system.pkgs
#   weblogic <DOMAIN_HOME>     bin/setUserOverrides.sh     JAVA_OPTIONS
#   liberty  <server dir>      jvm.options                 one option per line
#   systemd  <unit name>       /etc/systemd/system/<unit>.d/zhuwei-rasp.conf   JAVA_TOOL_OPTIONS
# Traditional WebSphere takes JVM arguments only through its administration tools: websphere_help prints them.
#
# Callers set PREFIX (agent install directory) and DRY (1 = only print).

MARK_BEGIN="# >>> zhuwei-rasp >>>"
MARK_END="# <<< zhuwei-rasp <<<"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

agent_jar() { echo "$PREFIX/rasp-launcher.jar"; }

# add_block <file> <body...>: append a marked block once; keeps the file's mode, creates it if missing
add_block() {
  local file="$1"; shift
  if [ -f "$file" ] && grep -qF "$MARK_BEGIN" "$file"; then
    echo "    $file 已包含 RASP 配置，未重复添加"
    return 0
  fi
  if [ "${DRY:-0}" = 1 ]; then echo "+ append agent block to $file"; return 0; fi
  {
    [ -s "$file" ] && [ -n "$(tail -c1 "$file")" ] && echo ""   # file without trailing newline
    [ -s "$file" ] && echo ""
    echo "$MARK_BEGIN"
    echo "# added by $PREFIX/tools/install.sh; removed by $PREFIX/tools/uninstall.sh"
    for line in "$@"; do echo "$line"; done
    echo "$MARK_END"
  } >> "$file"
}

# remove_block <file>: delete the marked block and the blank line add_block put before it
remove_block() {
  local file="$1"
  if [ ! -f "$file" ] || ! grep -qF "$MARK_BEGIN" "$file"; then
    echo "==> $file 中没有 RASP 配置"
    return 0
  fi
  local tmp="$file.rasp-tmp"
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    $0==b {skip=1; if (pending) {pending=0}; next}
    $0==e {skip=0; next}
    skip {next}
    {if (pending) print ""; if ($0=="") {pending=1} else {pending=0; print}}
    END {if (pending) print ""}' "$file" > "$tmp"
  if [ -s "$tmp" ]; then
    cat "$tmp" > "$file"   # rewrite in place: keeps owner, mode and links of the original file
    echo "==> 已从 $file 移除 RASP 配置"
  else
    rm -f "$file"          # the file held only our block (install.sh created it)
    echo "==> 已删除 $file（其中只有 RASP 配置）"
  fi
  rm -f "$tmp"
}

# write_file <file> <body...>: a whole file owned by RASP (marked so uninstall can recognise it)
write_file() {
  local file="$1"; shift
  if [ "${DRY:-0}" = 1 ]; then echo "+ write $file"; return 0; fi
  mkdir -p "$(dirname "$file")"
  { echo "$MARK_BEGIN"; for line in "$@"; do echo "$line"; done; } > "$file"
}

remove_file() {
  local file="$1"
  if [ -f "$file" ] && head -1 "$file" | grep -qF "$MARK_BEGIN"; then
    rm -f "$file"
    echo "==> 已删除 $file"
  else
    echo "==> 没有 $file（或不是 RASP 生成的文件，未改动）"
  fi
}

# ------------------------------------------------------------------ per server

check_tomcat()   { [ -d "$1/bin" ] && { [ -f "$1/bin/catalina.sh" ] || [ -f "$1/conf/server.xml" ]; } || fail "$1 不是 Tomcat 目录（缺少 bin/catalina.sh 或 conf/server.xml）"; }
enable_tomcat()  {
  add_block "$1/bin/setenv.sh" "CATALINA_OPTS=\"\$CATALINA_OPTS -javaagent:$(agent_jar)\""
  [ "${DRY:-0}" = 1 ] || chmod +x "$1/bin/setenv.sh"
  echo "    Tomcat：已写入 $1/bin/setenv.sh，重启后生效"
}
disable_tomcat() { remove_block "$1/bin/setenv.sh"; }

check_jetty()    { [ -d "$1/start.d" ] || [ -f "$1/start.ini" ] || fail "$1 不是 Jetty base 目录（缺少 start.d/ 或 start.ini）"; }
enable_jetty()   {
  write_file "$1/start.d/zhuwei-rasp.ini" "# ZhuWei-RASP agent; --exec makes start.jar fork a JVM with this option" "--exec" "-javaagent:$(agent_jar)"
  echo "    Jetty：已写入 $1/start.d/zhuwei-rasp.ini，重启后生效"
}
disable_jetty()  { remove_file "$1/start.d/zhuwei-rasp.ini"; }

check_wildfly()  { [ -f "$1/bin/standalone.conf" ] || fail "$1 不是 WildFly/JBoss EAP 目录（缺少 bin/standalone.conf）"; }
enable_wildfly() {
  # JBoss Modules hides boot-class-path packages from deployments unless they are system packages.
  add_block "$1/bin/standalone.conf" \
    "JAVA_OPTS=\"\$JAVA_OPTS -javaagent:$(agent_jar) -Djboss.modules.system.pkgs=\${JBOSS_MODULES_SYSTEM_PKGS:+\$JBOSS_MODULES_SYSTEM_PKGS,}com.zhuwei.rasp.bootstrap\""
  echo "    WildFly/JBoss：已写入 $1/bin/standalone.conf（standalone 模式），重启后生效；domain 模式请在 host.xml 的 jvm-options 中添加 -javaagent"
}
disable_wildfly() { remove_block "$1/bin/standalone.conf"; }

check_weblogic() { [ -f "$1/bin/setDomainEnv.sh" ] || fail "$1 不是 WebLogic 域目录（缺少 bin/setDomainEnv.sh）"; }
enable_weblogic() {
  add_block "$1/bin/setUserOverrides.sh" "JAVA_OPTIONS=\"\${JAVA_OPTIONS} -javaagent:$(agent_jar)\"" "export JAVA_OPTIONS"
  [ "${DRY:-0}" = 1 ] || chmod +x "$1/bin/setUserOverrides.sh"
  echo "    WebLogic：已写入 $1/bin/setUserOverrides.sh（WebLogic 12.1.2+ 自动加载），重启受管服务器后生效"
}
disable_weblogic() { remove_block "$1/bin/setUserOverrides.sh"; }

check_liberty()  { [ -f "$1/server.xml" ] || fail "$1 不是 Liberty 服务器目录（缺少 server.xml）"; }
enable_liberty() {
  add_block "$1/jvm.options" "-javaagent:$(agent_jar)"
  echo "    Liberty：已写入 $1/jvm.options，重启后生效"
}
disable_liberty() { remove_block "$1/jvm.options"; }

check_systemd()  {
  case "$1" in *[!A-Za-z0-9@._:-]*|"") fail "无效的 systemd 单元名：$1" ;; esac
  case "$1" in *.service) ;; *) fail "systemd 单元名需以 .service 结尾：$1" ;; esac
}
enable_systemd() {
  if command -v systemctl > /dev/null && systemctl show -p Environment "$1" 2>/dev/null | grep -q "JAVA_TOOL_OPTIONS="; then
    echo "    注意：$1 已设置 JAVA_TOOL_OPTIONS，本配置会覆盖它；请改为在服务的启动参数中添加 -javaagent" >&2
  fi
  write_file "$SYSTEMD_DIR/$1.d/zhuwei-rasp.conf" "# ZhuWei-RASP agent for every JVM started by this service" "[Service]" \
    "Environment=\"JAVA_TOOL_OPTIONS=-javaagent:$(agent_jar)\""
  echo "    systemd：已写入 $SYSTEMD_DIR/$1.d/zhuwei-rasp.conf；执行 systemctl daemon-reload && systemctl restart $1 后生效"
}
disable_systemd() {
  remove_file "$SYSTEMD_DIR/$1.d/zhuwei-rasp.conf"
  rmdir "$SYSTEMD_DIR/$1.d" 2>/dev/null || true   # only if no other drop-ins remain
  command -v systemctl > /dev/null && echo "    执行 systemctl daemon-reload && systemctl restart $1 后生效"
}

websphere_help() {
  cat <<EOF
    传统 WebSphere Application Server 的 JVM 参数需在管理控制台或 wsadmin 中修改（本脚本不直接改配置文件）：
      管理控制台：服务器 > 服务器类型 > WebSphere Application Server > <服务器> > Java 和进程管理 > 进程定义 >
                  Java 虚拟机 > 通用 JVM 参数，在原有内容后追加：-javaagent:$(agent_jar)
      保存并同步到节点后重启该服务器。卸载时删除该参数即可。
EOF
}
