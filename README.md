# goNetWatch

`goNetWatch` is a lightweight, privacy-focused Linux command-line tool written in Go for monitoring local network traffic, active connections, and communication changes over time.

## Primary Purpose

`goNetWatch` answers the core network observability and privacy questions:

> **"Which external and local machines is my computer communicating with, which local processes are responsible, and how much network traffic (RX/TX) is being transferred?"**

It is designed as a host-level network observability tool, not a packet-sniffing replacement for Wireshark or tcpdump. It does not inspect or capture packet contents, has no cloud telemetry or account requirements, and runs completely locally.

## Features

- **Active Connection Discovery**: Enumerate active TCP and UDP connections with endpoints, ports, protocol, and socket states using direct Linux kernel Netlink `sock_diag` and `/proc/net` interfaces.
- **Traffic Volume & Bandwidth (RX / TX)**: Extract exact cumulative received (RX) and transmitted/acknowledged (TX) byte counts per connection directly from kernel `tcp_info`.
- **Local vs External Scope Classification**: Automatically partitions connections into `EXTERNAL / INTERNET` vs `LOCAL NETWORK` based on RFC 1918, RFC 4193 (ULA), loopback, link-local, and multicast ranges.
- **Process Correlation**: Maps socket inodes to owning Process IDs (`PID`), process names, and system users via `/proc/[pid]/fd`.
- **Aggregation Modes**:
  - `--remote`: Aggregate total traffic and connection count grouped by remote host/IP.
  - `--process`: Aggregate total traffic and connection count grouped by process/PID.
- **Live Monitoring Mode (`--watch`)**: Real-time terminal auto-refresh with live throughput rate calculations (KB/s, MB/s).
- **Historical Analysis (`--hours <N>`)**: Hourly historical activity summaries and averages over the last N hours using a lightweight local JSON store.
- **Selective DNS Resolution (`--resolve`)**: Safe, non-blocking reverse DNS lookups with strict timeouts and caching (disabled by default to prevent DNS traffic leaks).
- **Zero Third-Party Dependencies**: Built entirely with Go standard library and Linux-native syscalls.

## Installation & Build

Requires Go 1.22+.

```bash
git clone git@github.com:arthurgray2k/goNetWatch.git
cd goNetWatch
go build -o goNetWatch ./cmd/goNetWatch
```

## Quick Start

```bash
# View current active network connections
./goNetWatch

# Live monitoring mode with 2-second refresh
./goNetWatch --watch

# Group activity by remote host/IP
./goNetWatch --remote

# Group activity by local process
./goNetWatch --process

# View hourly activity over the last 24 hours
./goNetWatch --hours 24

# Filter by process name
./goNetWatch chrome

# Filter by port number
./goNetWatch 443

# Output structured JSON
./goNetWatch --json
```

## License

Subject to the terms of the Mozilla Public License, v. 2.0. Copyright (c) 2026 Arthur Gray. See [LICENSE](LICENSE) for details.
