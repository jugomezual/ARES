
# AutoPwn – Technical Development Plan

## Overview

AutoPwn is a semi-automated penetration testing framework designed to scan, exploit, and report on devices within a local or VPN-linked network. The system is split into a centralized control server (with web interface and logic) and distributed agents (client nodes) which execute real-world offensive operations using Nmap, Metasploit, or local scripts.

---

## 1. Architecture Diagram (Conceptual)

```
+--------------------------+
|     Web Dashboard        |
| (HTML/CSS/JS frontend)   |
+-----------+--------------+
            |
            v
+-----------+--------------+
|  Decision Engine (server)|
| - Target selection       |
| - Task coordination      |
| - Result storage         |
+-----------+--------------+
            |
        Communication (netcat/VPN/SSH)
            |
+-----------+--------------+
|    Client Node (Agent)   |
| - Receives command       |
| - Executes tools         |
| - Sends back result      |
+--------------------------+
```

---

## 2. Development Steps (Detailed)

### ✅ Step 0: Project Setup
- Initialize Git repository.
- Create basic folder structure.
- Prepare README and architecture draft.

### ✅ Step 1: Basic Web UI (HTML/CSS/JS)
- Create static HTML layout.
- Add placeholder buttons:
  - "Scan Network"
  - "List Hosts"
  - "Exploit Target"
- Setup local preview using Python HTTP server.

### 🔄 Step 2: Web UI to Server Communication
- Option 1: Use a backend script (Python or PHP) to handle POST requests.
- Option 2: Pure shell interface (form actions trigger shell commands).

### 🔄 Step 3: Command Dispatch Mechanism
- Use `netcat` or `ncat --ssl` for sending tasks to remote clients.
- Format: `COMMAND|ARG1|ARG2`

### 🔄 Step 4: Agent Implementation in C
- Passive listener (always-on netcat-style server).
- Parses received commands (e.g. run nmap, send file).
- Executes and returns output.

### 🔄 Step 5: Execute Network Scan (Nmap)
- Trigger scan from dashboard.
- Server sends nmap task to agent.
- Agent runs: `nmap -sV -oN result.txt IP_RANGE`
- Result is returned and saved.

### 🔄 Step 6: Metasploit Integration
- Prepare auxiliary scripts that automate Metasploit via `msfconsole -r script.rc`
- Agent receives `.rc` script path or raw commands.
- Executes them and sends output back.

### 🔄 Step 7: Result Storage & Display
- Store each result in `/results/YYYY-MM-DD/`
- Show output in the UI (simple iframe, textarea, or custom styling).

### 🔄 Step 8: Basic Hardening
- Add basic authentication to dashboard.
- Restrict client commands to a whitelist.

### ⏭️ Future (Optional)
- Use WebSockets for live updates.
- Multi-agent routing and management.
- Centralized SQLite or flat file DB for session tracking.

---

## 3. Folder Structure

```
AutoPwn/
├── web-ui/                 # HTML/CSS/JS for the dashboard
├── server/                 # Backend logic (bash/python/php)
├── client-node/            # C-based agent listener
├── scripts/                # Metasploit rc files, bash helpers
├── results/                # Scan and exploit outputs
├── docs/                   # Project documentation
│   └── project-overview.md
└── README.md               # Main readme
```

---

## 4. Communication Protocol

A simple text-based message protocol:

```
SCAN|192.168.1.0/24
MSFEXPLOIT|target=192.168.1.10|exploit=ms08_067_netapi
SCRIPT|/scripts/privilege_escalation.sh
```
Clients parse and execute commands and return raw output to the server.

---

## 5. Tooling Summary

| Tool          | Purpose                              |
|---------------|--------------------------------------|
| Nmap          | Network scanning                     |
| Metasploit    | Exploitation framework               |
| Netcat/Ncat   | Communication between nodes          |
| C             | Low-level agent implementation       |
| HTML/CSS/JS   | Web dashboard                        |
| Python/Bash   | Scripts and server logic             |
| Git           | Version control                      |

---

## 6. Security Considerations

- Commands sent to clients must be validated.
- Output should be sanitized before displaying in web UI.
- Communication should be optionally encrypted (`ncat --ssl` or stunnel).
- Authentication for dashboard and command execution.

---

## 7. Milestones

| Phase       | Description                         | Status   |
|-------------|-------------------------------------|----------|
| Repo setup  | Git, README, base structure         | ✅ Done  |
| UI layout   | Static HTML dashboard               | ✅ Done  |
| C Agent     | Listener + exec commands            | 🔄 WIP   |
| Netcat Comm | Text-based messaging system         | 🔄 WIP   |
| Nmap        | Remote scan via agent               | ⏳       |
| Exploits    | Automate metasploit runs            | ⏳       |
| Storage     | Save & show results                 | ⏳       |
| Security    | Add simple auth & restrictions      | ⏳       |

---

## 8. License

MIT (To be confirmed)
