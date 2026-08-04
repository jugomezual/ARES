# ARES — Project Logical Flow

> Early design notes describing the intended end-to-end flow. Some details (e.g.
> the remote agent-node model) differ from the final implementation, where the
> backend drives Nmap and Metasploit directly.

## Phase 1 — Dashboard access

- The attacker (you) opens the web dashboard from the browser.
- A friendly interface is shown with options such as:
  - "Connect to Network"
  - "Scan for Hosts"
  - "Exploit Target"
  - "Show Results"

Note: this interface does not run anything yet; it only acts as the frontend.

## Phase 2 — Connecting to the target network

Before scanning or exploiting, a connection to the network is needed:

- **VPN:** the attacker connects to a VPN that places them "inside" the target
  network — for example, using `openvpn file.ovpn`.
- **Reverse shell / Netcat listener:** alternatively, a netcat-style channel is
  established with an already-compromised node that acts as an "agent" — e.g.
  `ncat -lvp 4444` on the server and a connection from the client.
- **Local mode:** for testing, operations can run over the local network (LAN).

## Phase 3 — Agent detection

- The dashboard detects (or you inform it manually) whether there are active
  agents connected to or reachable on the network.
- For example, you can keep an `agents.txt` file with the active IPs, or use a
  simple ping test / handshake.

## Phase 4 — Network scan

When "Scan Network" is pressed:

- `nmap` runs from the agent node (not from the main server).
- The scan command is sent over netcat or the defined channel.
- The result (nmap output) returns to the server.

## Phase 5 — Selection and exploitation

- The detected hosts are shown in the web UI.
- The user can select an IP and choose an exploit — for example,
  `ms08_067_netapi`.
- The server builds a Metasploit `.rc` script or a command.
- It is sent to the agent node.
- The agent runs it and returns the result.

## Phase 6 — Visualization and reporting

- All results are stored in `.txt` / `.json` files or a lightweight database.
- The dashboard displays them organized by date/target.

## Security (important)

- The dashboard must be protected with a login.
- Communication between the dashboard and the agents can be encrypted
  (`ncat --ssl`, `stunnel`, etc.).
- Actions must be logged for auditing.

## Flow summary

```
[User] -> [Web UI]
       -> (Connects to network via VPN or netcat)
       -> (Detects agents)
       -> (Sends commands: scan / exploit)
       <- (Receives results, organized by date/target)
```
