#!/usr/bin/env bash
# Start the vibe-kanban dev environment (`pnpm run dev`: backend with cargo watch + Vite).
#
# Usage:
#   operation_tool/start.sh          # foreground, Ctrl+C to stop
#   operation_tool/start.sh --bg     # background, logs to operation_tool/logs/dev.log
#
# Env: NODE_VERSION=22.23.2 to pick a specific nvm Node.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

background=false
case "${1:-}" in
  --bg | -b) background=true ;;
  "") ;;
  -h | --help) sed -n '2,8p' "$0"; exit 0 ;;
  *) die "Unknown option: $1 (use --bg or --help)" ;;
esac

existing="$(find_dev_roots | sort -u | tr '\n' ' ')"
[ -z "${existing// /}" ] ||
  die "Dev server already running (pid $existing). Use operation_tool/restart.sh"

ensure_node
check_claude
command -v pnpm >/dev/null 2>&1 || die "pnpm not found on PATH"

cd "$REPO_DIR"
[ -d node_modules ] || { log "Installing dependencies"; pnpm i; }

if [ "$background" = true ]; then
  mkdir -p "$LOG_DIR"
  log "Starting in background, logs: $LOG_FILE"
  nohup pnpm run dev >"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"
  log "pid $(cat "$PID_FILE")"
  wait_ready 900
else
  log "Starting in foreground (Ctrl+C to stop)"
  exec pnpm run dev
fi
