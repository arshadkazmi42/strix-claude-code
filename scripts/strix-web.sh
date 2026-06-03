#!/usr/bin/env bash
#
# strix-web.sh — set up, run, and manage the Strix web dashboard (mobile PWA).
#
# The dashboard is an optional, additive component. It reads running `screen`
# sessions and the findings DB (~/.strix/strix.db) and serves a mobile-friendly
# control panel. It does NOT change any CLI behaviour.
#
# Usage:
#   scripts/strix-web.sh start [--screen] [--port N] [--host H]
#   scripts/strix-web.sh stop
#   scripts/strix-web.sh restart [--screen] [--port N] [--host H]
#   scripts/strix-web.sh status
#   scripts/strix-web.sh logs
#   scripts/strix-web.sh set-password [NEW_PASSWORD]
#   scripts/strix-web.sh help
#
# Notes:
#   * `start` (no flags) runs in the foreground. Add `--screen` to run detached
#     in a `screen` session named "strix-app" (survives logout).
#   * First run creates the password file with the default password "changeme".
#     CHANGE IT before exposing the port. See `set-password`.
#   * Env overrides: STRIX_WEB_PORT, STRIX_WEB_HOST, STRIX_WEB_PASSWORD (overrides
#     the file), STRIX_WEB_SCREEN (screen session name).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCREEN_NAME="${STRIX_WEB_SCREEN:-strix-app}"
HOST="${STRIX_WEB_HOST:-0.0.0.0}"
PORT="${STRIX_WEB_PORT:-8800}"
PW_FILE="$HOME/.strix/web_password"
LOG="$HOME/.strix/web_app.log"

# Pick interpreter: project venv if present, else system python.
if [ -x "$ROOT/.venv/bin/python" ]; then
    PY="$ROOT/.venv/bin/python"
else
    PY="$(command -v python3 || command -v python || true)"
fi
[ -n "$PY" ] || { echo "ERROR: no python found. Install Python 3.11+." >&2; exit 1; }

c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'

ensure_deps() {
    if ! "$PY" -c 'import fastapi, uvicorn' >/dev/null 2>&1; then
        echo "Installing web extras (fastapi, uvicorn)…"
        "$PY" -m pip install -e ".[web]" \
            || { echo "ERROR: install failed. Try: $PY -m pip install fastapi uvicorn" >&2; exit 1; }
    fi
}

ensure_password() {
    if [ ! -f "$PW_FILE" ]; then
        mkdir -p "$HOME/.strix"; chmod 700 "$HOME/.strix" 2>/dev/null || true
        printf 'changeme\n' > "$PW_FILE"
        chmod 600 "$PW_FILE" 2>/dev/null || true
        echo "${c_yel}Created $PW_FILE with default password 'changeme' — change it!${c_rst}"
    fi
}

is_running() { screen -list 2>/dev/null | grep -q "\.${SCREEN_NAME}\b"; }

show_access() {
    local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "  Local : http://127.0.0.1:${PORT}"
    [ -n "$ip" ] && echo "  LAN   : http://${ip}:${PORT}"
    echo "  ${c_dim}Password file: ${PW_FILE}${c_rst}"
}

cmd_start() {
    local use_screen=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --screen) use_screen=1 ;;
            --port) PORT="$2"; shift ;;
            --host) HOST="$2"; shift ;;
            *) echo "unknown flag: $1" >&2; exit 1 ;;
        esac; shift
    done
    ensure_deps; ensure_password
    export STRIX_WEB_HOST="$HOST" STRIX_WEB_PORT="$PORT"
    if [ "$use_screen" -eq 1 ]; then
        command -v screen >/dev/null || { echo "ERROR: screen not installed." >&2; exit 1; }
        if is_running; then echo "Already running in screen '${SCREEN_NAME}'. Use 'restart'."; exit 0; fi
        screen -L -Logfile "$LOG" -dmS "$SCREEN_NAME" \
            bash -lc "cd '$ROOT' && exec env STRIX_WEB_HOST='$HOST' STRIX_WEB_PORT='$PORT' '$PY' -m strix_cli_claude.webapp"
        sleep 1
        echo "${c_grn}Started in screen '${SCREEN_NAME}'.${c_rst}"
        show_access
        echo "  ${c_dim}View: screen -r ${SCREEN_NAME}   Logs: $0 logs   Stop: $0 stop${c_rst}"
    else
        echo "${c_grn}Starting dashboard (Ctrl+C to stop)…${c_rst}"; show_access
        exec "$PY" -m strix_cli_claude.webapp
    fi
}

cmd_stop() {
    if is_running; then screen -S "$SCREEN_NAME" -X quit && echo "Stopped '${SCREEN_NAME}'."; else echo "Not running."; fi
}

cmd_status() {
    if is_running; then echo "${c_grn}● running${c_rst} (screen '${SCREEN_NAME}')"; else echo "${c_yel}○ not running in screen${c_rst}"; fi
    if command -v curl >/dev/null; then
        local code; code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${PORT}/login" || true)"
        [ "$code" = "200" ] && echo "HTTP 200 on :${PORT}" || echo "no HTTP response on :${PORT}"
    fi
}

cmd_logs() { [ -f "$LOG" ] && tail -n 200 -f "$LOG" || echo "no log at $LOG"; }

cmd_set_password() {
    mkdir -p "$HOME/.strix"; chmod 700 "$HOME/.strix" 2>/dev/null || true
    local pw="${1:-}"
    if [ -z "$pw" ]; then
        read -r -s -p "New dashboard password: " pw; echo
        local pw2; read -r -s -p "Confirm: " pw2; echo
        [ "$pw" = "$pw2" ] || { echo "ERROR: passwords differ." >&2; exit 1; }
    fi
    [ -n "$pw" ] || { echo "ERROR: empty password." >&2; exit 1; }
    printf '%s\n' "$pw" > "$PW_FILE"; chmod 600 "$PW_FILE" 2>/dev/null || true
    echo "${c_grn}Password updated${c_rst} ($PW_FILE). Takes effect immediately — no restart needed."
}

usage() { sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

case "${1:-help}" in
    start)        shift; cmd_start "$@" ;;
    stop)         cmd_stop ;;
    restart)      shift; cmd_stop || true; cmd_start "$@" ;;
    status)       cmd_status ;;
    logs)         cmd_logs ;;
    set-password) shift; cmd_set_password "${1:-}" ;;
    help|-h|--help) usage ;;
    *) echo "unknown command: $1" >&2; usage; exit 1 ;;
esac
