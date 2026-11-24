#!/usr/bin/env bash
# Restart the vibe-kanban dev environment.
#
# Usage:
#   operation_tool/restart.sh            # full restart: stop everything, start again in background
#   operation_tool/restart.sh --backend  # backend only: let the running cargo watch rebuild + restart
#   operation_tool/restart.sh --fg       # full restart, new server in the foreground

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

mode=full
case "${1:-}" in
  --backend | -B) mode=backend ;;
  --fg) mode=full_fg ;;
  "") ;;
  -h | --help) sed -n '2,7p' "$0"; exit 0 ;;
  *) die "Unknown option: $1 (use --backend, --fg or --help)" ;;
esac

restart_backend() {
  local watcher port old new
  watcher="$(find_cargo_watch)"
  [ -n "$watcher" ] || die "No cargo watch running for this repo. Run a full restart instead."

  port="$(dev_port backend)"
  old="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | head -1 || true)"
  log "Triggering cargo watch (pid $watcher) to rebuild the backend"
  # cargo watch restarts on any change under crates/; touching a file is enough.
  touch "$REPO_DIR/crates/server/src/main.rs"

  for _ in $(seq 1 600); do
    new="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | head -1 || true)"
    if [ -n "$new" ] && [ "$new" != "$old" ] &&
      curl -fsS -o /dev/null "http://localhost:$port/api/health" 2>/dev/null; then
      log "Backend restarted (pid ${old:-none} -> $new) on http://localhost:$port"
      return 0
    fi
    sleep 1
  done
  die "Backend did not come back within 10 minutes. Check the cargo watch output."
}

case "$mode" in
  backend) restart_backend ;;
  full)
    stop_dev
    exec "$OPS_DIR/start.sh" --bg
    ;;
  full_fg)
    stop_dev
    exec "$OPS_DIR/start.sh"
    ;;
esac
