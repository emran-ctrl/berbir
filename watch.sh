#!/usr/bin/env sh
# Dev loop: rebuild + test the backend, then run the server, while `trunk
# watch` rebuilds the frontend bundle (crates/app/dist) whenever the app
# sources change. The running server picks the new bundle up automatically.
#
# Config lives in `.env` at the project root (BERBIR_TEMPLATES, BERBIR_BIND, ...).
#
# Requires: cargo-watch (cargo install cargo-watch) and trunk (~/.local/bin/trunk).
set -e

cd "$(dirname "$0")"

cleanup() {
  trap - INT TERM EXIT
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "[watch] frontend: trunk watch -> crates/app/dist"
( cd crates/app && ~/.local/bin/trunk watch ) &
FRONTEND_PID=$!

echo "[watch] backend: cargo watch -> build, test, run"
cargo watch -c \
  -i target \
  -i 'crates/app/**' \
  -i '*.db*' \
  -x build \
  -x test \
  -x run &
BACKEND_PID=$!

wait
