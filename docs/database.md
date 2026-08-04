# ARES — Database Model

This document describes the data model that backs ARES. The executable schema
(DDL) lives in [`ares.sql`](ares.sql); this file explains what each table is for
and how they relate.

The database is the backbone of the system: the five pipeline stages
(reconnaissance, vulnerability detection, exploitation, persistence, reporting)
communicate through it rather than by invoking each other directly, and it is
what lets the AI decision engine accumulate historical context across audit runs.

Every table hangs off `jobs`. Deleting a job cascades to all of its hosts, scans,
vulnerabilities, attempts, sessions and logs.

## Experiment design: Normal vs AI

The model is built around a comparison between two execution modes, recorded in
`jobs.type`:

- **`normal`** — iterative mode without AI. The backend loops internally, trying
  every candidate payload.
- **`ia`** — the LLM agent (AI decision engine) chooses the exact parameters it
  considers optimal, typically in a single attempt.

Because every atomic action (`exploit_attempt`, `ssh_attempt`, `exploit_session`)
carries its `jobs_id` and a `duration_ms`, results can be filtered by `jobs.type`
to compare both modes directly. For example, total attempts and total time per
mode:

```sql
SELECT jobs.type,
       COUNT(*)          AS attempts,
       SUM(duration_ms)  AS total_time_ms
FROM   exploit_attempt
JOIN   jobs ON jobs.id = exploit_attempt.jobs_id
GROUP  BY jobs.type;
```

## Tables

### `jobs` — root of the tree

The audit "job" or run. Each time ARES is launched against a network a job is
created; everything else hangs off it.

- `type` distinguishes **Normal** (iterative, no AI) from **AI** (LLM agent) mode.
- `model` stores the LLM name when in AI mode (e.g. `gemma4:26b`); it is `NULL`
  in normal mode.

Key columns: `id` (PK), `type`, `model`, `timestamp`.

### `hosts` — discovered hosts

Hosts discovered within a job. Each IP that appears in the network scan is stored
here. A job over `10.0.0.0/24` that finds five hosts creates five rows, all with
the same `jobs_id`.

Key columns: `id` (PK), `jobs_id` (FK → `jobs`), `target_host`, `os_info`,
`state` (`pending` / `running` / `error` / `done`), `timestamp`.

### `host_nmap` — service enumeration

The result of the Nmap scan for each open port of a host. Stores the service and
version detected by `nmap -sV`. For a host with FTP (21), SSH (22) and SMB (445),
three rows are created; `nmap_version` would hold values such as `vsftpd 2.3.4`,
`OpenSSH 4.7`, `Samba 3.0.20`.

Key columns: `id` (PK), `host_id` (FK → `hosts`), `port`, `nmap_state`,
`nmap_service`, `nmap_version`, `state`, `timestamp`.

### `host_vuln` — detected vulnerabilities

Vulnerabilities found on a specific host by `nmap --script vuln`. Each identified
CVE generates a row, linked via `host_nmap_id` to the exact port where it was
detected. This table is the bridge between scanning (`host_nmap`) and
exploitation (`exploit_attempt`): the AI decision engine queries it to decide what
to exploit first, ordering by `severity = 'critical'`.

Example: for a host running vsftpd on port 21, Nmap detects CVE-2011-2523
(critical) and a row is created with `host_nmap_id` pointing to port 21.

Key columns: `id` (PK), `host_id` (FK → `hosts`), `host_nmap_id`
(FK → `host_nmap`), `cve`, `severity` (`low` / `medium` / `high` / `critical`),
`service`, `state`, `timestamp`.

### `exploit_attempt` — atomic exploitation attempts

The central experiment table. Records each atomic exploitation attempt — a
concrete module, a concrete payload, against a concrete IP and port. It
corresponds to the `POST /run-exploit` endpoint.

Why it is atomic: in Normal mode the code loops internally trying every payload,
so one CVE with several payloads generates several rows (typically one with
`success = 1` and the rest with `success = 0`). In AI mode the engine calls the
endpoint once with the parameters it considers optimal, so a successful attempt is
a single row. Each call is one row.

Key columns: `id` (PK), `jobs_id` (FK → `jobs`), `host_id` (FK → `hosts`),
`port`, `success` (0/1), `duration_ms`, `output`, `state`, `timestamp`.

### `exploit_session` — opened sessions

The access session opened after a successful exploit or SSH login — the final
result ("access to this host was achieved, this way, in this time"). It lets you
compare not just attempts but outcomes: how many sessions were opened per job, in
what total time, and by which method.

Key columns: `id` (PK), `jobs_id` (FK → `jobs`), `host_id` (FK → `hosts`),
`type` (`meterpreter` / `shell` / `ssh`), `method` (`exploit` / `ssh`), `cve`,
`user`, `duration_ms`, `state`, `timestamp`.

### `ssh_attempt` — atomic SSH credential attempts

An atomic SSH credential attempt — one user, one password, against one IP. It
corresponds to the `POST /run-ssh` endpoint; same concept as `exploit_attempt`
but for credential-based SSH access. Filtering by `jobs.type` shows how many SSH
attempts each mode made.

Key columns: `id` (PK), `jobs_id` (FK → `jobs`), `host_id` (FK → `hosts`),
`user`, `password`, `success` (0/1), `duration_ms`, `state`, `timestamp`.

### `activity_logs` — event log

A chronological log of all events in a job. Each relevant action is recorded with
a reference to the table and row that generated it. This is what backs the
historical context the AI decision engine reuses across runs.

ARES-specific event types include `vuln_identified`, `exploit_success`,
`exploit_failed`, `ssh_success`, `ssh_failed` and `session_opened`.

Key columns: `id` (PK), `jobs_id` (FK → `jobs`), `event_type`, `reference_id`,
`reference_table`, `details_json`, `intentos`, `duration_ms`, `observaciones`,
`comentarios`, `timestamp`.

> Note: the columns `intentos`, `observaciones` and `comentarios` keep their
> original Spanish names because they are referenced verbatim by the backend code.
