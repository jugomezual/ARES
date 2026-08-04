# ARES — Backend Internal Functions

Summary of the algorithms and utilities implemented in `backend/server.js`. This
document is a reference for the non-obvious internal helpers that support the
audit pipeline; it is not an exhaustive API listing (see the README for the REST
endpoints).

## Metasploit engine (persistent process)

### `ensureMsf()`

- **What it does:** Starts a persistent `msfconsole -q` process if one is not
  already running. If the process dies, the next call restarts it automatically.
- **Parameters:** none
- **Returns:** `void`
- **Why:** Keeping `msfconsole` alive avoids the startup cost (~5–10 s) on every
  request to the backend.

### `msfRun(commands, timeoutMs)`

- **What it does:** Sends a list of commands to the `msfconsole` process and waits
  for the full output using a sentinel token (`echo ARES_xxxx`). Resolves the
  promise when the sentinel appears in stdout, or when the timeout elapses.
- **Parameters:** `commands: string[]`, `timeoutMs: number`
- **Returns:** `Promise<{ output: string, timedOut: boolean }>`
- **Why:** This is the central piece that lets `msfconsole` be operated as if it
  were an asynchronous API.

### `msfOnData(chunk)`

- **What it does:** Handler for the `msfconsole` `stdout.on('data')` event. It
  accumulates chunks in a buffer and, when it detects the sentinel token of a
  pending request, extracts its output and resolves the corresponding promise.
- **Parameters:** `chunk: Buffer`
- **Returns:** `void`

## Decision algorithms

### `findMsfModule(cve)`

- **What it does:** Given a CVE, returns the most suitable Metasploit module. It
  first checks a static map (`CVE_MODULES`); if not found, it runs
  `search cve:XXXX` in `msfconsole` in real time, parses the results table, and
  selects the highest-ranked module (preferring `exploit/` over `auxiliary/`).
- **Parameters:** `cve: string` (e.g. `"CVE-2011-2523"`)
- **Returns:** `Promise<{ module: string, payload: string } | null>`
- **Why:** It is the bridge between a CVE detected by Nmap and the concrete module
  to run, combining static knowledge with a dynamic query to Metasploit.

### `guessPayload(modulePath)`

- **What it does:** Infers the most likely bind payload for a module from its
  path. Windows modules → `windows/x64/meterpreter/bind_tcp`; Unix/multi modules
  → `cmd/unix/bind_perl`; Linux → `linux/x64/meterpreter/bind_tcp`. Returns
  `null` for self-contained modules (e.g. vsftpd).
- **Parameters:** `modulePath: string`
- **Returns:** `string | null`

### `resolveRport(modulePath, nmapPort)`

- **What it does:** Returns the correct target port for a module. It ignores the
  port Nmap reported and forces the canonical value for the protocol: SMB→445,
  FTP→21, RDP→3389, SSH→22, Telnet→23, VNC→5900. For anything else it uses the
  Nmap port.
- **Parameters:** `modulePath: string`, `nmapPort: number | null`
- **Returns:** `number | null`
- **Why:** Nmap may tag an SMB CVE while scanning port 8080; without this function
  the exploit would be launched against the wrong port.

### `getPayloadList(modulePath, preferredPayload)`

- **What it does:** Builds an ordered list of payloads to try for a given module.
  It places the preferred payload first, followed by the native payloads of the
  inferred operating system, and finally those of the remaining platforms. If the
  module is self-contained it returns `[null]`.
- **Parameters:** `modulePath: string`, `preferredPayload: string | null`
- **Returns:** `string[]`
- **Why:** Maximizes the chance of success by trying the payloads most compatible
  with the target architecture first.

### `canOpenSession(modulePath)`

- **What it does:** Returns `false` for modules that never open a session
  (scanners, DoS, gather, fuzz, post-exploitation). Avoids useless attempts in the
  exploitation loop.
- **Parameters:** `modulePath: string`
- **Returns:** `boolean`

### `parseVulnOutput(raw)`

- **What it does:** Parses the text output of Nmap (NSE vulnerability scripts) and
  extracts a structured list of findings: port, script name, CVEs found, risk
  level, CVSS score, and a short description.
- **Parameters:** `raw: string` (stdout of `nmap --script vuln`)
- **Returns:** `Array<{ port, script, state, cves, risk, cvss, description }>`

## SSH module

### `sshExec(user, ip, password, command, timeoutMs)`

- **What it does:** Runs a remote command over SSH using `sshpass`. It implements
  an automatic profile system with four compatibility levels: modern profile →
  profile with `+ssh-rsa` → legacy RSA + old-cipher profile → minimal profile
  without host verification. It caches the profile that worked for each IP.
- **Parameters:** `user: string`, `ip: string`, `password: string`,
  `command: string`, `timeoutMs: number`
- **Returns:** `Promise<{ stdout: string, stderr: string, code: number }>`
- **Why:** Legacy servers such as Metasploitable2 use deprecated algorithms
  (`ssh-rsa`, 3DES ciphers) that the modern SSH client rejects by default.

## Utilities

### `getLhost()`

- **What it does:** Detects the local IP of the auditing host by inspecting the
  network interfaces. It prioritizes VPN/private interfaces (ranges 10.x, 172.x,
  192.168.x) so that the `LHOST` of payloads is always reachable from the target.
- **Parameters:** none
- **Returns:** `string` (IPv4)

### `stripAnsi(s)`

- **What it does:** Removes all ANSI escape codes (colors, cursor moves) from a
  string. Needed because `msfconsole` emits terminal-formatted output that breaks
  text parsers.
- **Parameters:** `s: string`
- **Returns:** `string`
