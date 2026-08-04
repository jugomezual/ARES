# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ARES (Automated Red-team Exploit System) is a semi-automated, AI-assisted penetration testing platform with a four-layer architecture:

1. **React frontend** (`web-ui/autopwn-ui/`) — Dashboard UI served by Vite on port 5173.
2. **Node.js/Express backend** (`backend/server.js`) — REST API on port 3000. It orchestrates a persistent `msfconsole` process (over stdin/stdout), Nmap, and the C binaries, and it separates the LLM reasoning (the "AI decision engine") from Metasploit-based execution.
3. **C binaries** (`core/`) — Low-level helpers for network scanning (`network_scan`) and VPN/Netcat connections (`vpn_connect`). The backend invokes them via `child_process.execFile()`.
4. **MariaDB/MySQL storage layer** — All state (jobs, hosts, scans, vulnerabilities, attempts, sessions, and activity logs) is persisted here. Pipeline stages communicate through the database rather than by invoking each other directly, which is also what lets the AI decision engine accumulate historical context across runs.

Key backend files: `server.js` (API and orchestrator), `ia.js` (LLM integration: Ollama / Gemini / OpenWebUI), `ia_funciones_especificas.js` (pentesting-specific AI prompt/parse helpers).

## Build Commands

### C core (requires gcc and Nmap installed)
```bash
cd core
make          # Builds both vpn_connect and network_scan binaries
make clean    # Remove object files and binaries
make run      # Build and run vpn_connect
```

Binaries output to `core/vpn_connect` and `core/network_scan`. C code style follows Google style (`.clang-format` at root).

### Backend
```bash
cd backend
npm install
node server.js    # Starts API on http://localhost:3000
```

Before first run, create the local config files from their templates (both are gitignored):
```bash
cp db.js.example db.js               # set your DB credentials
cp ia_config.js.example ia_config.js # uncomment and fill the LLM provider block
```

### Frontend
```bash
cd web-ui/autopwn-ui
npm install
npm run dev       # Dev server at http://localhost:5173
npm run build     # Production build
npm run lint      # ESLint check
npm run preview   # Preview production build
```

### Database
```bash
# Create the DB and user (see README), then import the schema:
mysql -u ares -p --skip-ssl ares < docs/ares.sql
```

## Running the Full Stack

Three terminals are required:
1. `cd core && make` — compile C binaries (prerequisite for backend).
2. `cd backend && node server.js` — start API server (requires `db.js` and a running MariaDB).
3. `cd web-ui/autopwn-ui && npm run dev` — start frontend.

## Architecture Details

### Backend API
The backend exposes ~30 REST endpoints covering connection, scanning, CVE detection, exploitation, session management, and reporting. See the "API reference" table in `README.md` for the full list. Representative endpoints:
- `POST /connect` — runs `core/vpn_connect` with `[type, ip, port, user, password]`.
- `POST /scan-network` — runs `core/network_scan` with `[network]` (e.g. `192.168.1.0/24`).
- `POST /exploit`, `POST /run-exploit` — Metasploit module orchestration.
- `GET /report/:jobId` — full job report in JSON (also CSV and PDF variants).

### AI decision engine
`ia.js` builds prompts and parses the LLM's JSON responses; the returned plan is executed by `server.js`. The LLM layer only decides — it does not run exploits itself. Provider and model are selected in `backend/ia_config.js`.

### Database model
Schema in `docs/ares.sql`; a narrative reference is in `docs/database.md` and an ER diagram in `docs/ER_AutoPwn.drawio`. The `jobs` table is the root; every other table cascades on delete from it.

### C module structure
- `core/src/connection_manager.c` + `core/include/connection_manager.h` — shared connection state used by both executables.
- `core/src/network_scan.c` — Nmap wrapper, takes network CIDR as argv[1].
- `core/src/vpn_connect.c` — VPN/Netcat CLI interface, parses argv for connection params.

## Public release note

In this public version, the actual **exploit launch is disabled**: modules are loaded (`use <module>`) but the target/payload configuration and the `run` command are commented out across the exploitation, privilege-escalation, and persistence paths. The full orchestration logic remains intact and reviewable, but the tool will not open sessions against a target out of the box. This is intentional; see the legal notice in `README.md`.
