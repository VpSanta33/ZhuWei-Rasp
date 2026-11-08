#!/usr/bin/env bash
# Builds the Java agent, the management server and assembles dist/.
#   dist/rasp/            agent install directory (copy to /opt/rasp on hosts)
#   dist/rasp-server      management server binary (web console embedded)
#   dist/demo-app.jar     demo application for end-to-end tests
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"

echo "==> building java agent"
# clean: maven-shade would otherwise re-shade its own output on repeated builds
(cd "$ROOT/agent-java" && mvn -q -B clean package)

echo "==> assembling dist/rasp"
rm -rf "$DIST/rasp"
mkdir -p "$DIST/rasp/conf" "$DIST/rasp/logs" "$DIST/rasp/tools"
cp "$ROOT/deploy/tools/"*.sh "$DIST/rasp/tools/"
chmod +x "$DIST/rasp/tools/"*.sh
cp "$ROOT/agent-java/rasp-launcher/target/rasp-launcher.jar" \
   "$ROOT/agent-java/rasp-bootstrap/target/rasp-bootstrap.jar" \
   "$ROOT/agent-java/rasp-core/target/rasp-core.jar" "$DIST/rasp/"
cp "$ROOT/deploy/agent-conf/"* "$DIST/rasp/conf/"
cp "$ROOT/agent-java/demo-app/target/demo-app.jar" "$DIST/"

if [ -d "$ROOT/server" ] && command -v go >/dev/null; then
  echo "==> building server"
  # one source of truth for the default policy: deploy/agent-conf/policy.json
  cp "$ROOT/deploy/agent-conf/policy.json" "$ROOT/server/internal/policy/default_policy.json"
  (cd "$ROOT/server" && CGO_ENABLED=0 go build -o "$DIST/rasp-server" ./cmd/rasp-server)
fi
echo "done: $DIST"
