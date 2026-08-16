# goNetWatch Usage Guide

`goNetWatch` provides a clean, coherent CLI for monitoring active network connections and traffic volume on Linux.

## CLI Syntax

```text
goNetWatch [flags] [filter]
```

### Positional Arguments

The first non-flag argument is automatically interpreted as either a **port number** or a **process name**:

- If the argument is an integer between 1 and 65535, it filters by **port**.
- Otherwise, it filters by **process name** (case-insensitive substring match).

---

## Modes

| Flag | Description |
| --- | --- |
| *(default)* | Display active connections partitioned by External vs Local Network |
| `--watch` | Live monitoring mode (auto-refreshing table) |
| `--remote` | Aggregate statistics by remote host/IP |
| `--process` | Aggregate statistics by process/PID |
| `--hours <N>` | Display hourly historical traffic and connection activity for the last N hours |
| `--clear-history` | Purge local historical records |

---

## Filters

| Flag | Description |
| --- | --- |
| `--pid <PID>` | Filter connections by Process ID |
| `--proc <name>` | Filter connections by process name (e.g. `chrome`, `code`) |
| `--host <ip/host>` | Filter connections by remote IP address or hostname |
| `--port <port>` | Filter connections by local or remote port number |
| `--local` | Show local network connections only |
| `--external` | Show external/internet connections only |
| `--all` | Include listening and idle sockets |

---

## Options

| Flag | Description |
| --- | --- |
| `--interval <sec>` | Set refresh interval in seconds for `--watch` mode (default: `2`) |
| `--resolve` | Enable reverse DNS resolution for remote IP addresses |
| `--json` | Output results in structured JSON format |
| `--no-color` | Disable ANSI color output (or set `NO_COLOR=1`) |
| `--version` | Display version information |
| `--help` | Show usage help |

---

## Examples & Common Workflows

### 1. Default Connection View

```bash
goNetWatch
```

Output:
```text
NETWORK ACTIVITY

EXTERNAL / INTERNET (3 connections)
────────────────────────────────────────────────────────────────────────────────────────
REMOTE                         PROCESS          PID      STATE                  RX         TX
142.250.190.46:443             chrome           3812     ESTABLISHED       42.0 MB     8.0 MB
20.1.2.3:443                   code             4210     ESTABLISHED       12.0 MB     3.0 MB
140.82.113.25:443              brave            3107     ESTABLISHED        2.7 MB    10.1 KB

LOCAL NETWORK (1 connections)
────────────────────────────────────────────────────────────────────────────────────────
REMOTE                         PROCESS          PID      STATE                  RX         TX
192.168.1.20:445               smbclient        2101     ESTABLISHED        3.2 MB     1.1 MB

SUMMARY
────────────────────────────────────────
  Total Connections: 4 (External: 3, Local: 1)
  Total RX:          59.9 MB
  Total TX:          12.1 MB
```

### 2. Live Monitoring

```bash
# Refresh every 2 seconds
goNetWatch --watch

# Refresh every 5 seconds
goNetWatch --watch --interval 5
```

### 3. Remote Host Aggregation

```bash
goNetWatch --remote
```

Output:
```text
NETWORK ACTIVITY — REMOTE HOSTS

────────────────────────────────────────────────────────────────────────────────────────────
REMOTE HOST                SCOPE           CONNS   PROCESSES                    RX         TX
142.250.190.46             EXTERNAL        18      chrome                  84.0 MB    12.0 MB
20.1.2.3                   EXTERNAL         7      code                    22.0 MB     5.0 MB
192.168.1.20               LOCAL NETWORK   11      smbclient               18.0 MB     9.0 MB

SUMMARY
────────────────────────────────────────
  Total Hosts:       3
  Total Connections: 36
  Total RX:          124.0 MB
  Total TX:          26.0 MB
```

### 4. Process Aggregation

```bash
goNetWatch --process
```

Output:
```text
NETWORK ACTIVITY — PROCESSES

────────────────────────────────────────────────────────────────────────────────────────────
PROCESS            PID      USER       CONNS   REMOTE HOSTS                     RX         TX
chrome             3812     mint       18      142.250.190.46              84.0 MB    12.0 MB
code               4210     mint        7      20.1.2.3                    22.0 MB     5.0 MB
smbclient          2101     mint       11      192.168.1.20                18.0 MB     9.0 MB

SUMMARY
────────────────────────────────────────
  Total Processes:   3
  Total Connections: 36
  Total RX:          124.0 MB
  Total TX:          26.0 MB
```

### 5. Historical Hourly Summary

```bash
goNetWatch --hours 24
```

Output:
```text
NETWORK ACTIVITY — LAST 24 HOURS

────────────────────────────────────────────────────────────
TIME       CONNECTIONS                RX             TX
00:00      12                    24.0 MB         5.0 MB
01:00       8                    12.0 MB         2.0 MB
02:00       4                     4.0 MB         1.0 MB
...
23:00      17                    51.0 MB         9.0 MB

SUMMARY
────────────────────────────────────────────────────────────
  Average connections/hour: 14.7
  Average RX/hour:          18.4 MB
  Average TX/hour:           5.2 MB

  Total RX:                 442.0 MB
  Total TX:                 125.0 MB
```

### 6. Filtering

```bash
# Filter by process name
goNetWatch --proc chrome
goNetWatch chrome

# Filter by port number
goNetWatch --port 443
goNetWatch 443

# Filter by remote host or IP
goNetWatch --host 142.250

# Filter local network only
goNetWatch --local

# Filter external/internet only
goNetWatch --external
```

### 7. Structured JSON Output

```bash
goNetWatch --json
goNetWatch --remote --json
goNetWatch --hours 24 --json
```

---

## Environment Variables

- `NO_COLOR=1`: Disable ANSI color escape codes in standard terminal output.
- `GONETWATCH_DATA_DIR`: Custom directory path for local historical snapshot storage (defaults to `~/.local/share/goNetWatch/`).
