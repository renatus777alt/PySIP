# PySIP 1.0.1 - Rust SIP core

This folder is a Rust rewrite of the SIP service from PySIP 1.0. The existing
Python `web_panel.py` is intentionally not rewritten: it continues to manage
accounts and the same SQLite database (`pysip.db`). The Rust service opens that
same database and uses the existing `users`, `registrations`, `sip_contacts`,
`settings`, and `calls` tables.


## 1.0.1 compiler fixes

This patch corrects the Rust ownership and lifetime errors reported when
compiling the initial 1.0 source archive:

- `SipMessage::cseq` now keeps the header string alive while parsing its tokens.
- SIP response header additions use `mem::take` before replacing an `Outbound`
  packet, avoiding moves out of indexed vector elements.
- `Transaction` now stores the callee username used by late-fork cleanup.
- In-dialog target URI construction no longer uses a moved `String`.
- Removed the unused `mut` bindings and unused timeout tuple variable.

Build and test from the directory containing `Cargo.toml`:

```bash
cargo test
cargo build --release
```

## Files

- `Cargo.toml` - Rust package and dependencies.
- `src/main.rs` - SIP registrar/proxy, SQLite access, call routing and RTP relay.

Keep your existing `web_panel.py` beside the project and keep `pysip.db` in the
working directory used by both processes. Back up `pysip.db` before the first
run of the Rust version.

## Features ported

- SIP Digest authentication using the existing `sip_ha1` database value
  (`MD5(username:realm:password)`) for compatibility with existing accounts.
- REGISTER with multiple Contacts per account, contact expiry, wildcard
  unregister, Call-ID/CSeq ordering and legacy `registrations` migration.
- Username and generated `+190...` phone-number destination lookup.
- OPTIONS, INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, REFER, MESSAGE,
  SUBSCRIBE, NOTIFY and PUBLISH handling/routing.
- INVITE forking to multiple registered devices; the first 2xx answer wins and
  other ringing branches receive CANCEL.
- Busy, decline, timeout and call-history updates.
- IPv4 UDP SIP on port 5060 by default.
- One audio media stream using an RTP/RTCP UDP relay. SDP rewriting keeps codec
  attributes, changes the media ports and removes `rtcp-mux` so RTP and RTCP use
  the separate relay sockets.
- SQLite WAL mode, expiry cleanup, bounded packet/header sizes, Max-Forwards
  checks, per-source packet rate limiting, signed Digest nonces and nonce-count
  replay checks.
- Interactive selection of the advertised LAN/VPN IPv4 address. Set
  `PYSIP_ADVERTISED_HOST` to bypass the prompt.

The server handles REGISTER and OPTIONS locally. It proxies the listed call,
message and event methods to registered endpoints. SUBSCRIBE/NOTIFY/PUBLISH
are not a presence/event server: event-package behavior is the endpoint's job.
Unknown methods receive `501 Not Implemented`.

## WSL2 Debian installation using the Rsproxy mirror

The commands below use the Rsproxy Rustup distribution mirror and its sparse
Cargo registry mirror. They are optional alternatives to the default Rust
servers.

1. Install build prerequisites:

```bash
sudo apt update
sudo apt install -y build-essential curl ca-certificates pkg-config
```

2. Install Rust stable via Rsproxy:

```bash
export RUSTUP_DIST_SERVER=https://rsproxy.cn
export RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup
curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh
```

When the installer finishes, load Cargo into the current shell:

```bash
. "$HOME/.cargo/env"
rustup default stable
rustc --version
cargo --version
```

If `cargo` is not found in a newly opened terminal, run `. "$HOME/.cargo/env"`
or reopen the terminal.

3. Configure Cargo to download crates through Rsproxy:

```bash
mkdir -p "$HOME/.cargo"
cat > "$HOME/.cargo/config.toml" <<'TOML'
[source.crates-io]
replace-with = "rsproxy-sparse"

[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"

[net]
git-fetch-with-cli = true
TOML
```

The sparse registry configuration requires a modern stable Rust toolchain.

## Build and test

Run these commands from the directory containing `Cargo.toml`:

```bash
cargo test
cargo build --release
```

The optimized executable is:

```text
target/release/pysip-server
```

To run it:

```bash
./target/release/pysip-server
```

The server lists available local IPv4 addresses. Select the LAN/VPN address
that your SIP clients can reach. It listens on `0.0.0.0:5060/UDP` by default,
but it must advertise a real reachable interface address, not `0.0.0.0` or
`127.0.0.1`.

You can skip the prompt by setting an explicit address:

```bash
PYSIP_ADVERTISED_HOST=192.168.0.103 ./target/release/pysip-server
```

Relevant environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PYSIP_DB_PATH` | `pysip.db` | Shared SQLite database path |
| `PYSIP_REALM` | `pysip.local` | SIP Digest realm; must match the web panel's realm |
| `PYSIP_HOST` | `0.0.0.0` | SIP bind address |
| `PYSIP_PORT` | `5060` | SIP UDP port |
| `PYSIP_ADVERTISED_HOST` | interactive | Address inserted into SIP/SDP |
| `PYSIP_RTP_PORT_MIN` | `20000` | Lowest RTP/RTCP relay port |
| `PYSIP_RTP_PORT_MAX` | `30000` | Highest RTP/RTCP relay port |

## Run with the existing Python web panel

Run both programs from the same project/data directory so they use the same
`pysip.db` file. In one WSL terminal:

```bash
python3 web_panel.py
```

In a second WSL terminal:

```bash
./target/release/pysip-server
```

Open the web panel at `http://127.0.0.1:8080/` from the Windows browser if your
existing panel is bound to `0.0.0.0` or localhost forwarding is available in
WSL2. The web panel remains Python and is not included in this Rust-source ZIP.

## Network ports

For LAN/VPN testing, allow these ports only on the trusted LAN/VPN interface:

- UDP 5060 - SIP signaling.
- UDP 20000-30000 - RTP/RTCP relay.
- TCP 8080 - Python web panel (managed by the existing Python service).

Do not expose this service directly to the public internet. Keep it behind a
private VPN or trusted LAN.

## Important scope and limitations

This is a source port of the current PySIP prototype, not a certified PBX or a
complete implementation of every SIP extension. The server supports IPv4 UDP
signaling and one RTP/RTCP audio stream per call. It does not provide SIP over
TCP/TLS, SRTP, ICE/STUN/TURN, transcoding, recording, multi-party conference
bridging, or a presence server. Keep it on a private LAN/VPN.

### Validation status

The database schema/table compatibility was checked against the uploaded
PySIP Python server source, and Rust unit tests are included for SIP parsing,
keepalives, digest formatting, phone-number normalization, SDP codec preservation,
and the existing SQLite account/contact schema.

The Rust toolchain and crate registry were not available in the build
container, so this source archive has **not been compiled or executed here**.
Run `cargo test` first in WSL2. Treat the Rust port as an initial test build
until it compiles cleanly and you have exercised registration, two-device
ringing, answer/decline/BYE, and real phone-to-PC audio with your existing
clients. Keep the original Python `sip_server.py` as a rollback copy.
