# ARES — Automated Red-team Exploit System

**Author:**  Miguel Ruíz Ramírez and Julio Gómez López  
**Platform:** Kali Linux  

---

ARES is a web platform for semi-automated, AI-assisted penetration testing. It
integrates network discovery, service enumeration, Metasploit exploitation,
session management, and report generation in a single interface. The **AI
decision engine** plans and runs attacks autonomously, adjusting its strategy in
real time based on the history of successes and failures.

---

## Quick setup (fresh server)

> Full installation guide from scratch. Run the commands in order.

### 1. System dependencies

```bash
sudo apt update
sudo apt install -y nodejs npm gcc make nmap sshpass ncat mariadb-server
```

Check that Metasploit is available (preinstalled on Kali):

```bash
which msfconsole
```

### 2. Clone the repository

```bash
git clone <repository-url>
cd AutoPwn
```

### 3. Database

Start MariaDB:

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb   # optional: start on boot
```

Create the user and database (replace `YOUR_PASSWORD` with one of your choosing):

```bash
sudo mysql -u root <<EOF
CREATE DATABASE ares CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ares'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD';
GRANT ALL PRIVILEGES ON ares.* TO 'ares'@'localhost';
FLUSH PRIVILEGES;
EOF
```

Import the schema:

```bash
mysql -u ares -p --skip-ssl ares < docs/ares.sql
```

### 4. Configure the backend

Install the Node dependencies:

```bash
cd backend
npm install
```

Create the database connection file:

```bash
cp db.js.example db.js
```

Edit `backend/db.js` and set the password chosen in step 3:

```js
password: "YOUR_PASSWORD",
```

Create the AI configuration file:

```bash
cp ia_config.js.example ia_config.js
```

Edit `backend/ia_config.js` and uncomment the block for the provider you want to
use (Ollama, Gemini, or OpenWebUI), filling in the corresponding URL and token.

```bash
cd ..
```

### 5. Build the C binaries

```bash
cd core
make
cd ..
```

This should produce `core/vpn_connect` and `core/network_scan` without errors.

### 6. Install the frontend dependencies

```bash
cd web-ui/autopwn-ui
npm install
cd ../..
```

### 7. Start the application

You need **three terminals** open at the project root:

**Terminal 1 — Backend:**

```bash
cd backend && node server.js
```

**Terminal 2 — Frontend:**

```bash
cd web-ui/autopwn-ui && npm run dev
```

**Terminal 3 — (optional) Live AI logs:**

```bash
tail -f backend/ia_logs/*.log
```

Open the browser at **`http://localhost:5173`** and the application is ready.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  FRONTEND   React 19 + Vite                      :5173   │
│  Dashboard · Scan · Exploitation · Sessions · AI         │
└─────────────────────┬────────────────────────────────────┘
                      │  REST API
┌─────────────────────▼────────────────────────────────────┐
│  BACKEND    Node.js / Express                    :3000   │
│  server.js · ia.js · ia_funciones_especificas.js         │
│                                                          │
│   ┌─────────────┐   ┌──────────┐   ┌────────────────┐    │
│   │ msfconsole  │   │  nmap    │   │  C binaries    │    │
│   │ (persistent │   │          │   │  network_scan  │    │
│   │  stdin/out) │   │          │   │  vpn_connect   │    │
│   └─────────────┘   └──────────┘   └────────────────┘    │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│  DATABASE   MariaDB / MySQL                      :3306   │
│  jobs · hosts · host_nmap · host_vuln                    │
│  exploit_attempt · exploit_session · activity_logs       │
└──────────────────────────────────────────────────────────┘
```

---

## Features

- **Network scan**: discovery of live hosts and open ports over a CIDR range
- **Deep analysis**: service and OS version detection with Nmap `-sV` and NSE scripts
- **CVE detection**: vulnerability identification with severity (critical / high / medium / low)
- **Automated exploitation**: Metasploit with a persistent `msfconsole` process and payload fallback
- **Privilege escalation**: MSF privesc modules on active sessions
- **Persistence**: administrator user creation (Linux SSH / Windows RDP)
- **Session management**: view and access Meterpreter, SSH, and raw shell sessions
- **AI decision engine**: autonomous attack planning with history-based learning
- **Reports**: JSON · CSV · PDF with pentest metrics and narrative analysis

### Exploited protocols (confirmed in the lab)

| Protocol | CVE | Module |
|---|---|---|
| SMB | CVE-2017-0143 / 0145 | `exploit/windows/smb/ms17_010_psexec` |
| SMB | CVE-2017-0144 | `exploit/windows/smb/ms17_010_eternalblue` |
| SMB | CVE-2020-0796 | `exploit/windows/smb/samba_symlink_traversal` |
| RDP | CVE-2019-0708 | `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` |
| RPC/DCOM | CVE-2003-0352 | `exploit/windows/dcerpc/ms03_026_dcom` |
| FTP (vsftpd) | CVE-2011-2523 | `exploit/unix/ftp/vsftpd_234_backdoor` |
| FTP (wu-ftpd) | CVE-2000-0573 | `7350wurm` binary (ExploitDB #348) |
| Samba | CVE-2007-2447 | `exploit/multi/samba/usermap_script` |
| HTTP | CVE-2014-6271 | `exploit/multi/http/apache_mod_cgi_bash_env_exec` |
| Log4j | CVE-2021-44228 | `exploit/multi/http/log4shell_header_injection` |
| Sudo | CVE-2021-3156 | `exploit/linux/local/sudo_baron_samedit` |

---

## Prerequisites

| Tool | Minimum version | Installation |
|---|---|---|
| Node.js | 18+ | `apt install nodejs` |
| npm | 9+ | included with Node.js |
| MariaDB / MySQL | 10.6+ | `apt install mariadb-server` |
| gcc | 11+ | `apt install gcc` |
| nmap | 7.80+ | `apt install nmap` |
| Metasploit Framework | 6+ | preinstalled on Kali |
| sshpass | any | `apt install sshpass` |
| ncat | any | `apt install ncat` |

> **Recommended operating system:** Kali Linux. Inside a VM, Metasploit
> performance may be limited.

---

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd AutoPwn
```

### 2. Database

Start MariaDB if it is not already running:

```bash
sudo systemctl start mariadb
```

Log in as root and create the user and database:

```bash
sudo mysql -u root
```

```sql
CREATE DATABASE ares CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ares'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD';
GRANT ALL PRIVILEGES ON ares.* TO 'ares'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Import the schema (tables only):

```bash
mysql -u ares -p --skip-ssl ares < docs/ares.sql
```

### 3. Backend

Install the dependencies:

```bash
cd backend
npm install
```

Create the database configuration file from the template:

```bash
cp db.js.example db.js
```

Edit `backend/db.js` with the password chosen in the previous step:

```js
const pool = mysql.createPool({
  host:     "localhost",
  user:     "ares",
  password: "YOUR_PASSWORD",   // ← change here
  database: "ares",
  waitForConnections: true,
  connectionLimit: 10,
});
```

### 4. AI provider

Edit `backend/ia_config.js` to point to the available LLM server.

**Option A — Ollama (local or lab server):**

```js
module.exports = {
  tipo:          "ollama",
  llama_api_url: "http://localhost:11434/api/generate",
  ia_modelo:     "gemma4:e4b",
};
```

**Option B — OpenWebUI (OpenAI-compatible API):**

```js
module.exports = {
  tipo:           "openwebui",
  llama_api_url:  "http://SERVER:8080/api/chat/completions",
  llama_api_key:  "YOUR_JWT_TOKEN",
  ia_modelo:      "gemma4:26b",
};
```

**Option C — Google Gemini (free API):**

```js
module.exports = {
  tipo:      "gemini",
  api_key:   "YOUR_API_KEY",     // get it at aistudio.google.com
  ia_modelo: "gemini-2.5-flash",
};
```

### 5. C binaries (core)

```bash
cd core
make
```

Produces `core/vpn_connect` and `core/network_scan`. You only need to build the
first time or after modifying the C code.

### 6. Frontend

```bash
cd web-ui/autopwn-ui
npm install
```

---

## Running

Three simultaneous terminals are required:

**Terminal 1 — Backend:**

```bash
cd backend
node server.js
```

Starts the REST API at `http://localhost:3000`.

**Terminal 2 — Frontend:**

```bash
cd web-ui/autopwn-ui
npm run dev
```

Open `http://localhost:5173` in the browser.

**Terminal 3 — (optional) live logs:**

```bash
tail -f backend/ia_logs/*.log
```

---

## Quick start

### Manual mode

1. **Connect** to the target network from the *Network Connection* tab
2. **Scan the network** by entering the CIDR range (e.g. `192.168.1.0/24`)
3. On each discovered host: **Deep scan → Detect CVEs → Exploit**
4. With a session open: run commands, escalate privileges, create persistence
5. Export the **report** from the *Results* tab

### AI mode

1. Launch the network scan in **AI** mode
2. The AI decision engine plans the attack order based on history and discovered ports
3. It runs the phases autonomously: CVE analysis, payload selection, failure handling
4. The user can monitor progress and decisions from the dashboard in real time

---

## API reference

| Method | Route | Description |
|---|---|---|
| `POST` | `/connect` | Connect to target network (VPN / ncat) |
| `POST` | `/scan-network` | CIDR scan — discovers hosts and ports |
| `POST` | `/scan-host` | Deep service enumeration (`-sV`) |
| `POST` | `/scan-vulns` | NSE vulnerability scripts |
| `POST` | `/find-vulns` | CVE detection and severity mapping |
| `POST` | `/exploit` | Launch a Metasploit module |
| `POST` | `/session-privesc` | Privilege escalation on an active session |
| `POST` | `/session-persist` | Create persistence (SSH / RDP user) |
| `POST` | `/exploit-cmd` | Run a command in a session |
| `POST` | `/session-close` | Close a session |
| `GET` | `/sessions` | List active sessions |
| `GET` | `/jobs` | List all recorded pentests |
| `GET` | `/report/:jobId` | Full report in JSON |
| `GET` | `/report/:jobId/csv` | Export to CSV |
| `POST` | `/report/:jobId/save-pdf` | Save report as PDF |
| `POST` | `/reset` | Clear backend state |

---

## Repository structure

```
AutoPwn/
├── backend/
│   ├── server.js                    # Main API and orchestrator
│   ├── ia.js                        # LLM integration (Ollama / Gemini / OpenWebUI)
│   ├── ia_config.js                 # Active AI provider and model
│   ├── ia_funciones_especificas.js  # AI functions specialized for pentesting
│   ├── db.js.example                # Database configuration template
│   ├── package.json
│   └── outputs/                     # PDF reports generated at runtime
│
├── core/
│   ├── src/
│   │   ├── network_scan.c           # nmap wrapper → JSON
│   │   ├── vpn_connect.c            # VPN / ncat connection management
│   │   └── connection_manager.c     # Shared connection state
│   ├── include/
│   └── Makefile
│
├── web-ui/autopwn-ui/
│   ├── src/
│   │   ├── App.jsx                  # Entry point, routing, and global state
│   │   └── components/
│   │       ├── AracniAttack.jsx     # AI attack orchestration
│   │       ├── AIAutoPwn.jsx        # Automated exploitation flow
│   │       ├── AIAssistant.jsx      # Chat with the AI decision engine
│   │       ├── Dashboard.jsx
│   │       ├── NetworkScan.jsx
│   │       ├── Exploitation.jsx
│   │       ├── Results.jsx
│   │       ├── TargetAcquired.jsx
│   │       ├── SessionManager.jsx
│   │       └── ReportCharts.jsx
│   └── package.json
│
└── docs/
    ├── ares.sql                     # Database schema (structure only)
    ├── database.md                  # Data model documentation
    ├── internal-functions.md        # Backend internal functions reference
    ├── tools_schema.json            # Tool definitions for the AI agent
    └── ER_AutoPwn.drawio            # Entity–relationship diagram
```

---

## Common troubleshooting

**Database connection error when starting the backend:**
Check that MariaDB is running (`sudo systemctl status mariadb`) and that the
credentials in `backend/db.js` match those created during installation.

**`msfconsole` not found:**
Make sure Metasploit is in the PATH: `which msfconsole`. On Kali it is usually at
`/usr/bin/msfconsole`.

**TLS error when connecting to MySQL:**
Add `ssl: false` to the `db.js` pool or use `--skip-ssl` in the `mysql` /
`mysqldump` commands.

**The C binaries do not compile:**
Install the dependencies: `sudo apt install gcc make`. Then
`cd core && make clean && make`.

**The frontend does not connect to the backend:**
Check that the backend is running on port 3000 and that no firewall is blocking
the local connection.

---

## Legal notice

ARES is designed exclusively for use in **controlled lab environments with
explicit authorization**. Using this tool against systems without permission is
illegal. The authors are not responsible for any misuse of the software.

---

## License

Released under the MIT License — see [`LICENSE`](LICENSE).
© 2026 Miguel Ruíz Ramírez and Julio Gómez López.

To cite this software, see [`CITATION.cff`](CITATION.cff).
