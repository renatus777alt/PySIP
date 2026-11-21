# PySIP

**Rust SIP service + Python web control panel**

PySIP is a small SIP registrar/proxy intended for testing and use on a trusted home network or private VPN. The SIP signaling and RTP/RTCP relay are implemented in Rust. The account and administrator web interface remains a Python standard-library application. Both services share one SQLite database, `pysip.db`.

> **Status:** community/personal project, not a production-grade PBX or a security-audited SIP platform. Keep it on a trusted LAN or private VPN. Do not expose the SIP, RTP, or web-panel ports directly to the public internet.

## Features

- SIP Digest account authentication compatible with existing PySIP accounts (`sip_ha1`).
- Account lookup by username or generated `+190...` phone number.
- Multiple active Contact registrations per account, with a configured maximum of 16 devices.
- INVITE forking to registered devices; first successful 2xx answer wins and other ringing branches receive CANCEL.
- Core call signaling: INVITE, ACK, CANCEL, BYE.
- Local REGISTER and OPTIONS handling.
- Proxying for PRACK, UPDATE, INFO, REFER, MESSAGE, SUBSCRIBE, NOTIFY, and PUBLISH. These extension methods are routed to endpoints; PySIP does not implement application-specific presence/event-package services.
- Busy, decline, unavailable, and unanswered-call handling with call-history updates.
- One IPv4 audio stream using a pass-through RTP/RTCP relay. PySIP does not decode, record, or transcode audio.
- SDP rewriting that preserves codec attributes while directing media through the relay.
- SQLite schema creation/migration, WAL mode, contact expiry, bounded SIP packet/header sizes, Max-Forwards handling, source-IP rate limiting, signed Digest nonces, and nonce-count replay checks.
- Interactive advertised-IPv4 selection, with an environment-variable override.
- Retro-style Python web panel for registration, personal account management, and administration.

## Project layout

```text
PySIP/
├── Cargo.toml
├── Cargo.lock                 # Generate and commit this for reproducible builds
├── README.md
├── LICENSE
├── SECURITY.md
├── .gitignore
├── src/
│   └── main.rs
├── web_panel.py
└── pysip.db                   # Created at first run; DO NOT distribute
```

The source archive intentionally does not contain a live database, account credentials, logs, or compiled binaries.

## Requirements

### Runtime

- Rust SIP service: a compatible Windows or Linux binary built from this source.
- Web panel: Python 3.10 or newer. It uses only the Python standard library; there is no `pip install` step.
- A writable application/data directory for `pysip.db` and SQLite's temporary `-wal`/`-shm` files.

### Build

- Current stable Rust toolchain (`rustc` and `cargo`).
- A C toolchain for the bundled SQLite build used by `rusqlite`.
- For Windows GNU cross-compilation from WSL2/other: `mingw-w64`.

## Build and test on Debian / WSL2 / other distro

Install build tools:

```bash
sudo apt update
sudo apt install -y build-essential curl ca-certificates pkg-config
```

Install Rust with Rustup. If the default Rust distribution host is slow or inaccessible from your network, an optional Rsproxy mirror setup is shown below.

```bash
export RUSTUP_DIST_SERVER=https://rsproxy.cn
export RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup
curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh
. "$HOME/.cargo/env"
rustup default stable
rustc --version
cargo --version
```

Optional Cargo registry mirror configuration:

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

Run the tests and build the Linux binary:

```bash
cargo test
cargo build --release
```

The executable is `target/release/pysip-server`.

## Build a Windows x64 executable from WSL2/Debian/other

Install MinGW and the Rust Windows GNU target:

```bash
sudo apt install -y mingw-w64
rustup target add x86_64-pc-windows-gnu
```

Configure the linker from the project root:

```bash
mkdir -p .cargo
cat > .cargo/config.toml <<'TOML'
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
TOML
```

Build:

```bash
export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
cargo test
cargo build --release --target x86_64-pc-windows-gnu
```

The executable is:

```text
target/x86_64-pc-windows-gnu/release/pysip-server.exe
```

A GNU-target executable may require MinGW runtime DLLs on Windows. Before distributing it, test it on a clean Windows machine. Alternatively, build the MSVC target on Windows with the Visual Studio C++ Build Tools installed.

## Start PySIP

Run both programs from the same directory so they use the same `pysip.db` and realm configuration. Keep the web panel and SIP service running together.

Terminal 1, start the web panel:

```bash
python3 web_panel.py
```

On Windows:

```cmd
python web_panel.py
```

The web panel prints a generated administrator password when `PYSIP_ADMIN_PASSWORD` is not set. Save it securely. The panel's default bind address is `127.0.0.1:8080`, so it is only reachable from the local machine by default.

Terminal 2, start the Rust SIP service:

```bash
./target/release/pysip-server
```

On Windows, run the compiled `pysip-server.exe` from the same working directory.

At startup, select the LAN or VPN IPv4 address that SIP clients can reach. The service binds to `0.0.0.0:5060/UDP` by default, but the advertised address must be a real interface address. Do not advertise `0.0.0.0` or `127.0.0.1` to remote clients.

You can bypass the prompt with:

```bash
PYSIP_ADVERTISED_HOST=192.168.0.103 ./target/release/pysip-server
```

Windows CMD:

```cmd
set PYSIP_ADVERTISED_HOST=192.168.0.103
pysip-server.exe
```

Replace the example address with the address reachable by your SIP clients. For VPN use, select the VPN adapter's address.

## Shared database and existing accounts

Both services use `pysip.db` in the current working directory unless `PYSIP_DB_PATH` is set. The SIP Digest realm defaults to `pysip.local`; it must match the realm used by the web panel and existing account `sip_ha1` values.

Before upgrading an existing installation:

1. Stop both services.
2. Make a private backup of `pysip.db`.
3. Put the database in the directory from which both services will run, or set the same `PYSIP_DB_PATH` for both.
4. Start the web panel and SIP service.
5. Verify account registration and a test call before deleting any backup.

**Never commit or publish `pysip.db`.** It contains account password hashes, SIP Digest HA1 values, assigned phone numbers, registered Contact information, client IP addresses, user-agent strings, and call metadata. SQLite may also create `pysip.db-wal` and `pysip.db-shm`; those are private runtime data too.

## Configuration

The Rust SIP service reads these environment variables:

| Variable | Default | Purpose |
|---|---:|---|
| `PYSIP_DB_PATH` | `pysip.db` | Shared SQLite database path |
| `PYSIP_REALM` | `pysip.local` | SIP Digest realm; keep it consistent with the web panel and existing accounts |
| `PYSIP_HOST` | `0.0.0.0` | SIP bind address |
| `PYSIP_PORT` | `5060` | SIP UDP port |
| `PYSIP_ADVERTISED_HOST` | interactive selection | IPv4 address advertised in SIP/SDP |
| `PYSIP_RTP_PORT_MIN` | `20000` | First port in the RTP/RTCP relay range |
| `PYSIP_RTP_PORT_MAX` | `30000` | Last port in the RTP/RTCP relay range |

The Python web panel additionally reads:

| Variable | Default | Purpose |
|---|---:|---|
| `PYSIP_WEB_HOST` | `127.0.0.1` | Web-panel bind address |
| `PYSIP_WEB_PORT` | `8080` | Web-panel TCP port |
| `PYSIP_ADMIN_USERNAME` | `admin` | Administrator username |
| `PYSIP_ADMIN_PASSWORD` | generated at startup | Set a strong private value to avoid a newly generated password each start |

Set shared variables such as `PYSIP_DB_PATH` and `PYSIP_REALM` consistently for both processes.

## Network ports

For a private LAN/VPN test setup, permit traffic only from trusted client devices:

| Port | Protocol | Purpose |
|---|---|---|
| `5060` | UDP | SIP signaling |
| `20000-30000` | UDP | RTP/RTCP relay |
| `8080` | TCP | Web panel; loopback-only by default |

If you deliberately bind the web panel to a LAN/VPN interface, restrict TCP 8080 to trusted peers using the host firewall. Do not expose it directly to the internet.

## Security notes

- Use PySIP only on a trusted LAN or private VPN.
- Do not port-forward SIP, RTP, or the web panel from your router to the public internet.
- SIP Digest compatibility uses MD5 HA1, which is a legacy SIP authentication scheme. It is not a substitute for TLS/SRTP.
- SIP over TCP/TLS, SRTP, ICE/STUN/TURN, IPv6 media, transcoding, recording, and conference bridging are not provided by this version.
- The web panel uses plain HTTP and has no TLS of its own. Its default `127.0.0.1` bind is intentional.
- Use a unique, strong password for every SIP account and a strong administrator password.
- Keep the database and logs private; do not paste them into public issue trackers without removing account data, addresses, and call details.
- Back up the database while the services are stopped, or use SQLite's online backup facility.

## Source and binary distribution

For a **source release**, publish:

- `Cargo.toml`
- `Cargo.lock` (generate it with Cargo and commit it for reproducible dependency resolution)
- `src/main.rs`
- `web_panel.py`
- `README.md`
- `LICENSE`
- `SECURITY.md`
- `.gitignore`

For a **Windows x64 binary release**, publish a ZIP containing:

- `pysip-server.exe`
- `web_panel.py`
- `README.md`
- `LICENSE`
- a small launch script if desired

For a **Linux x64** or **Linux ARM64 binary release**, publish a separate archive for each architecture containing:

- `pysip-server` built for that architecture
- `web_panel.py`
- `README.md`
- `LICENSE`
- a small launch script if desired

Binary releases still require Python 3.10+ for the web panel. No third-party Python packages are required. Do not bundle a real database. The first run creates the database and the administrator password is printed by the web panel.

Never include `pysip.db`, SQLite WAL/SHM files, real logs, `.env` files, private keys, production passwords, session secrets, real account exports, or machine-specific configuration in either source or binary releases.

## License

The Rust package metadata declares MIT. Include the corresponding `LICENSE` file in every source and binary distribution, and confirm the copyright holder and licensing rights for all included project files before publishing.
