#!/usr/bin/env bash
# Shared helpers for operation_tool/*.sh. Source it, don't run it.

set -euo pipefail

OPS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$OPS_DIR/.." && pwd)"
LOG_DIR="$OPS_DIR/logs"
LOG_FILE="$LOG_DIR/dev.log"
PID_FILE="$OPS_DIR/.dev.pid"
PORTS_FILE="$REPO_DIR/.dev-ports.json"

# Vite 7 needs Node >= 20.19 / 22.12. Override with NODE_VERSION=xx.yy.zz.
MIN_NODE_MAJOR=22

log() { printf '\033[36m[ops]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[ops]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[ops]\033[0m %s\n' "$*" >&2; exit 1; }

# Put a new enough Node on PATH (nvm install if available).
ensure_node() {
  local major=0
  if command -v node >/dev/null 2>&1; then
    major="$(node -p 'process.versions.node.split(".")[0]')"
  fi
  if [ "$major" -ge "$MIN_NODE_MAJOR" ]; then
    return
  fi

  local nvm_dir="${NVM_DIR:-$HOME/.nvm}"
  local wanted="${NODE_VERSION:-}"
  if [ -z "$wanted" ] && [ -d "$nvm_dir/versions/node" ]; then
    # Highest installed version with a new enough major.
    wanted="$(ls "$nvm_dir/versions/node" | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n |
      awk -F. -v min="$MIN_NODE_MAJOR" '$1 >= min' | tail -1)"
  fi
  [ -n "$wanted" ] && [ -x "$nvm_dir/versions/node/v$wanted/bin/node" ] ||
    die "Need Node >= $MIN_NODE_MAJOR (found ${major}). Install it with nvm or set NODE_VERSION."

  export PATH="$nvm_dir/versions/node/v$wanted/bin:$PATH"
  log "Using Node v$wanted from nvm"
}

# The vibe-kanban backend now runs the local `claude` CLI, not an npx pin.
check_claude() {
  if command -v claude >/dev/null 2>&1; then
    log "Claude CLI: $(claude --version 2>/dev/null | head -1)"
  else
    warn "'claude' is not on PATH: Claude Code tasks will fail with ExecutableNotFound."
  fi
}

# Read a port from .dev-ports.json (frontend | backend | preview_proxy).
dev_port() {
  [ -f "$PORTS_FILE" ] || return 0
  sed -n "s/.*\"$1\": *\([0-9]*\).*/\1/p" "$PORTS_FILE" | head -1
}

# PIDs of `concurrently` processes running this repo's dev command.
find_dev_roots() {
  local pid cwd
  for pid in $(pgrep -f 'concurrently.*backend:dev:watch' 2>/dev/null || true); do
    cwd="$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | tail -1)"
    [ "$cwd" = "$REPO_DIR" ] && echo "$pid"
  done
  if [ -f "$PID_FILE" ]; then
    pid="$(cat "$PID_FILE")"
    kill -0 "$pid" 2>/dev/null && echo "$pid"
  fi
  return 0
}

# PID of cargo-watch for this repo (backend auto-rebuild).
find_cargo_watch() {
  local pid cwd
  for pid in $(pgrep -f 'cargo-watch watch -w crates' 2>/dev/null || true); do
    cwd="$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | tail -1)"
    [ "$cwd" = "$REPO_DIR" ] && { echo "$pid"; return 0; }
  done
  return 0
}

# All descendants of a PID, children first.
descendants() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null || true); do
    descendants "$child"
    echo "$child"
  done
}

kill_tree() {
  local root="$1" pids
  pids="$(descendants "$root") $root"
  kill -TERM $pids 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$root" 2>/dev/null || break
    sleep 0.5
  done
  kill -KILL $pids 2>/dev/null || true
}

stop_dev() {
  local roots
  roots="$(find_dev_roots | sort -u)"
  if [ -z "$roots" ]; then
    log "No dev server running for $REPO_DIR"
  else
    for root in $roots; do
      log "Stopping dev server (pid $root and children)"
      kill_tree "$root"
    done
  fi
  rm -f "$PID_FILE"

  # Anything still holding the dev ports?
  local port pid
  for name in frontend backend preview_proxy; do
    port="$(dev_port "$name")"
    [ -n "$port" ] || continue
    pid="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | head -1 || true)"
    [ -n "$pid" ] && warn "Port $port ($name) still in use by pid $pid: $(ps -o command= -p "$pid" | cut -c1-80)"
  done
  return 0
}

# Wait until the backend and frontend answer HTTP.
wait_ready() {
  local timeout="${1:-600}" be fe
  for _ in $(seq 1 "$timeout"); do
    be="$(dev_port backend)"; fe="$(dev_port frontend)"
    if [ -n "$be" ] && [ -n "$fe" ] &&
      curl -fsS -o /dev/null "http://localhost:$be/api/health" 2>/dev/null &&
      curl -fsS -o /dev/null "http://localhost:$fe/" 2>/dev/null; then
      log "Ready: frontend http://localhost:$fe  backend http://localhost:$be"
      return 0
    fi
    sleep 1
  done
  warn "Not ready after ${timeout}s. Check $LOG_FILE"
  return 1
}
