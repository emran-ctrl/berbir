# berbir

A self-contained web vulnerability scanner written **in Rust**. It ships its own
Nuclei-style YAML template engine, a queue-backed Axum API, SQLite persistence, live
WebSocket streaming, Markdown reports, and a WASM dashboard built with Leptos.

Built as a portfolio project to show an end-to-end system: a pure-Rust scan engine, a
concurrent async backend, a database layer, a real-time UI, and the deployment plumbing
to run it all on one port.

> **⚠️ Legal / authorization.** berbir scans whatever you point it at. Only scan
> systems you own or have explicit written permission to test. The author and project
> assume no liability for misuse.

---

## Features

- **Custom template engine** — YAML signatures (Nuclei-inspired) with word / regex /
  status-code matchers, negative (absence) matching, multi-URL steps, and `and`/`or`
  conditions. Zero external scan-engine dependencies; everything lives in `berbir-engine`.
- **Three scan kinds**
  - `url` — run the template engine against a URL (6 bundled templates, capped body sizes).
  - `port_scan` — subprocess to [RustScan](https://github.com/RustScan/RustScan) (`rustscan -a host --range 1-1000 -g`); skipped gracefully with a log line if the binary is missing.
  - `domain` — passive subdomain discovery via crt.sh, then a child `url` scan per discovered subdomain (parent/child hierarchy in the DB).
- **Real-time dashboard** — Leptos CSR WASM frontend served by the backend on one port; findings and status stream over WebSocket (`/ws/scans/{id}`).
- **Markdown reports** — on-demand per scan at `/api/scans/{id}/report.md`.
- **SQLite persistence** — scans and findings with recursive aggregation for domain children.

## Architecture

```
┌──────────────┐   ┌───────────────────────────────────────────────┐
│  berbir-app  │   │                   berbir-server                │
│  (Leptos WASM)│  │   Axum API · SQLite (sqlx) · JobManager queue  │
│  REST + WS   │──▶│   EventBus broadcast → WebSocket                │
└──────────────┘   └───────────────────────┬───────────────────────┘
                                           ▼
                             ┌──────────────────────────┐
                             │       berbir-engine       │
                             │  YAML template scanner    │
                             │  · matcher (word/regex)   │
                             │  · crt.sh discovery       │
                             │  · RustScan subprocess    │
                             └──────────────────────────┘
                             berbir-shared  (DTOs used by every crate)
```

| Crate | Role |
|-------|------|
| `berbir-shared` | Serializable types shared by server, engine, and dashboard (`Scan`, `Finding`, `ScanEvent`, …). |
| `berbir-engine` | The scanner: YAML template model, pure matchers, HTTP scanning (`reqwest`/rustls), crt.sh discovery, RustScan port scanning, 6 bundled templates. |
| `berbir-server` | Axum API, SQLite layer (sqlx + migrations), background job queue with an mpsc + semaphore architecture, WebSocket event streaming, Markdown report rendering, static file serving. |
| `berbir-app` | Leptos 0.8 CSR dashboard compiled to WASM (trunk). |

## Requirements

- Rust **1.96+** (edition 2024)
- `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
- [trunk](https://github.com/trunk-rs/trunk) ≥ 0.21 (to build the frontend). If `cargo install trunk`
  fails on a `libdeflate-sys` compile error (older toolchains / non-AVX-512 CPUs), grab a
  prebuilt binary from the [releases page](https://github.com/trunk-rs/trunk/releases).
- *(optional)* [RustScan](https://github.com/RustScan/RustScan) on `PATH` for `port_scan` scans.

## Building

```sh
# native crates (server + engine + shared); the wasm `app` crate is excluded
cargo build --release

# frontend WASM bundle -> crates/app/dist/
cd crates/app && trunk build --release && cd ..
```

## Running

```sh
cargo run --release -p berbir-server
```

Then open http://127.0.0.1:3000. The server runs migrations, loads the bundled
templates, and serves the dashboard + API on a single port.

### Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `BERBIR_BIND` | `127.0.0.1:3000` | Listen address. |
| `BERBIR_DB` | `sqlite:berbir.db?mode=rwc` | SQLite connection URL. |
| `BERBIR_DIST` | `crates/app/dist` | Directory containing the built dashboard. |
| `BERBIR_DEV_CORS` | unset | If set, adds a permissive CORS layer (dev convenience for running trunk's dev server against the API). |
| `RUST_LOG` | `berbir_server=info,tower_http=info` | Tracing filter. |

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scans` | Create a scan. Body: `{"kind":"url"\|"port_scan"\|"domain","target":"…","ports":null}`. |
| `GET` | `/api/scans` | List scans (newest first). |
| `GET` | `/api/scans/{id}` | Scan detail + aggregated findings (includes domain children). |
| `GET` | `/api/scans/{id}/findings` | Aggregated findings only. |
| `GET` | `/api/scans/{id}/report.md` | Downloadable Markdown report. |
| `GET` | `/api/templates` | List bundled template metadata. |
| `WS` | `/ws/scans/{id}` | Live events: `finding`, `progress`, `subdomains_found`, `status_change`. |

## Adding scan templates

Templates are YAML files in `crates/engine/templates/` (auto-loaded via
`berbir_engine::builtin_templates()`). Minimal shape:

```yaml
id: my-template
info:
  name: Human Readable Name
  severity: medium        # info | low | medium | high | critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/.well-known/security.txt"
    matchers:
      - type: word        # word | regex | status
        part: body        # body | header | status_code
        words:
          - "Contact:"
        condition: and     # and | or (defaults to or)
  - type: status          # matchers can be a list of dicts or a list
```

Negative matching (`negative: true`) reports when a value is **absent** — used by the
`missing-security-headers` template. Multiple steps must **all** match for a finding
(step-level AND).

## Development

```sh
cargo test --workspace         # 15 engine + 4 server tests
cargo clippy --workspace --all-targets
cargo fmt --all --check
```

Frontend dev loop: `cd crates/app && trunk serve` (hot reload). Point it at the API with
`BERBIR_DEV_CORS=1` and `BERBIR_BIND=127.0.0.1:3000` on the server, then load
`http://127.0.0.1:8080` (trunk default) — the dashboard talks to the API on port 3000.

## License

MIT
