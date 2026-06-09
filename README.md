# XDP NAT Forwarder (`forward`)

`forward` is a high-performance network address translation (NAT) and packet forwarding daemon written in Rust, leveraging Linux eBPF XDP technology to perform fast packet rewrites at the network driver level. It supports dynamic rules management via both a local Unix Domain Socket (UDS) CLI and a secure, signed HTTP API.

---

## Features

- **High-Performance Forwarding**: Rewrites packets directly at the XDP layer (driver level), supporting both default and generic (SKB) mode fallback.
- **Dynamic Rule Management**: Create, delete, and list NAT forwarding mappings for TCP/UDP traffic on-the-fly.
- **Session Tracking & Automated Cleanup**: Periodically monitors active forwarding sessions and purges idle flows based on protocol-specific (TCP/UDP) configurable timeouts.
- **Secure HTTP API**:
  - Complete REST endpoints to manage NAT rules.
  - **HMAC-SHA256 Signature Authentication** on all routes to prevent unauthorized API requests.
  - **Replay Attack Protection**: Rejects requests where the request timestamp (`X-Timestamp`) deviates from the server's system clock by more than ±300 seconds.
  - Configurable shared secret key configured via the `--secret` CLI flag.
- **Daemon-Client CLI Architecture**: Inter-process communication via Unix Domain Socket (UDS) for local management.

---

## Prerequisites

1. **Stable Rust Toolchain**:
   ```bash
   rustup toolchain install stable
   ```
2. **Nightly Rust Toolchain** (required to compile eBPF):
   ```bash
   rustup toolchain install nightly --component rust-src
   ```
3. **BPF Linker**:
   ```bash
   cargo install bpf-linker
   ```
   *(On macOS, build with `--no-default-features`)*
4. **Cross-compilation Tooling** (if building on macOS for Linux):
   - LLVM: `brew install llvm` (on macOS)
   - Musl target: `rustup target add x86_64-unknown-linux-musl` (or target architecture)

---

## Build Instructions

### Native Compilation (Linux)
Compile the daemon and client CLI with:
```bash
cargo build --release
```
The compiled binary will be placed under `target/release/forward`.

### Cross-compilation (From macOS to Linux)
To compile on macOS for a target Linux machine:
```bash
cargo build --package forward --release \
  --target=x86_64-unknown-linux-musl \
  --config=target.x86_64-unknown-linux-musl.linker="rust-lld"
```
Substitute `x86_64` with `aarch64` if targeting ARM64 Linux systems.

---

## Deployment & Running

### 1. Run the Daemon
The daemon requires root privileges (`sudo`) to load eBPF maps and attach to the XDP hook.

```bash
sudo ./target/release/forward [FLAGS]
```

#### Daemon Command Line Flags
- `-i, --iface <interface>`: Network interface to attach to (default: `eth0`).
- `-s, --socket <path>`: Local UDS path for CLI management socket (default: `/tmp/forward.sock`).
- `-a, --addr <ip:port>`: Binding address for the HTTP API (default: `127.0.0.1:8080`).
- `--secret <key>`: Shared secret key for HTTP signature authentication (default: `forward-secret-key`).
- `--rules-path <path>`: Optional file path to persist configured NAT rules to a JSON file. If not set, rules are not persisted and will not be restored upon daemon restart.

**Example Run Command:**
```bash
sudo ./target/release/forward --iface eth0 --addr 127.0.0.1:8080 --secret my-secure-shared-secret
```

---

## Local Management (UDS CLI Client)

Run the client command by passing the subcommand and UDS path to the `forward` binary.

### Add a NAT Rule
Map incoming traffic on a local port to a destination IP/port.
```bash
./target/release/forward --socket /tmp/forward.sock add <proto> <local_port> <forward_ip> <forward_port>
```
*Example:*
```bash
./target/release/forward --socket /tmp/forward.sock add tcp 8080 192.168.1.100 80
```

### Delete a NAT Rule
Remove an existing mapping.
```bash
./target/release/forward --socket /tmp/forward.sock del <proto> <local_port>
```
*Example:*
```bash
./target/release/forward --socket /tmp/forward.sock del tcp 8080
```

### List NAT Rules
View all active rules.
```bash
./target/release/forward --socket /tmp/forward.sock list
```

### Configure Flow Timeouts
Set session timeout limits for TCP or UDP in seconds.
```bash
./target/release/forward --socket /tmp/forward.sock timeout <proto> <seconds>
```
*Example:*
```bash
./target/release/forward --socket /tmp/forward.sock timeout tcp 600
```

---

## Secure HTTP API

All HTTP requests to the daemon endpoints must include signature headers to pass authentication.

### Authentication Specification

Every HTTP request must include:
- `X-Timestamp`: Current Unix timestamp in seconds.
- `X-Signature`: Hex-encoded HMAC-SHA256 signature calculated over the payload `{timestamp}.{HTTP_METHOD}.{REQUEST_PATH}` using the pre-shared secret key.

#### Signature Calculation Example (Bash)
```bash
# Set configuration
host="http://127.0.0.1:8080"
secret="my-secure-shared-secret"
timestamp=$(date +%s)
method="GET"
path="/rules"

# Calculate signature
signature=$(echo -n "${timestamp}.${method}.${path}" | openssl dgst -sha256 -hmac "${secret}" | sed 's/^.* //')

# Perform request
curl -s -H "X-Timestamp: ${timestamp}" -H "X-Signature: ${signature}" "${host}${path}"
```

### REST Endpoints

#### `GET /rules`
Retrieve a list of all active rules.
- **Request Headers**: `X-Timestamp`, `X-Signature`
- **Response**: `200 OK` with JSON array of active rule definitions.

#### `POST /rules`
Add a new NAT rule.
- **Request Headers**: `X-Timestamp`, `X-Signature`, `Content-Type: application/json`
- **Body**:
  ```json
  {
    "proto": "tcp",
    "local_port": 1818,
    "forward_ip": "192.168.4.96",
    "forward_port": 18180
  }
  ```
- **Response**: `200 OK` with JSON including the resolved target MAC address.

#### `DELETE /rules/{proto}/{local_port}`
Remove a NAT rule.
- **Request Headers**: `X-Timestamp`, `X-Signature`
- **Response**: `200 OK`

#### `POST /timeout`
Configure TCP/UDP idle session timeouts.
- **Request Headers**: `X-Timestamp`, `X-Signature`, `Content-Type: application/json`
- **Body**:
  ```json
  {
    "proto": "tcp",
    "seconds": 300
  }
  ```
- **Response**: `200 OK`

---

## Running Unit Tests

To verify cryptographic and validation logic:
```bash
cargo test
```

---

## License

With the exception of eBPF code, forward is distributed under the terms of either the [MIT license] or the [Apache License] (version 2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the [GNU General Public License, Version 2] or the [MIT license], at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the GPL-2 license, shall be dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
