#!/usr/bin/env sh
# Dev loop: rebuild + test the backend, then run the server.
# Restarts automatically when source files change.
#
# Requires: cargo-watch  (install once with `cargo install cargo-watch`)
exec cargo watch -c \
  -i target \
  -i 'crates/app/dist' \
  -i '*.db*' \
  -x build \
  -x test \
  -x run
