# wireguard-status

A tiny, dependency-free Go service that serves a **status dashboard** for your
WireGuard interfaces and peers plus a **`/status` JSON endpoint** that returns
**HTTP 503 while any monitored peer is down**, so
[Uptime-Kuma](https://github.com/louislam/uptime-kuma) (or any HTTP check) can
alert you. It is **read-only** — it never touches your links; restarting is left
to an external watchdog driven by the per-interface `/status/{iface}` endpoint
(so wg-status needs no root/`wg-quick` privileges).

Built for the `nat-instance` pattern: a host that is simultaneously a NAT exit,
a WireGuard server for site VPNs (`wg0`, `wg2`, …), and part of a VPC mesh
(`wg-mesh`, `wg-mesh-stg`).

## What it shows

For every interface and peer: full public key, listen port, endpoint, allowed
IPs, **link state** (up / down / never), **rx/tx counters**, **last handshake**,
and persistent-keepalive. A peer is **down** when its last handshake is older
than `thresholds.handshake_stale` (default 180s). Hovering an endpoint shows its
**reverse-DNS** name (resolved in the background and cached in memory for a day).
The page is a small client that renders from `GET /status` and re-polls it every
~10s — no full reloads. It pauses in background tabs and shows a *disconnected*
state if `/status` becomes unreachable.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | Dashboard shell (HTML+JS). Always **200** — it renders itself from `/status`. |
| `GET /status` | **Complete JSON** of every interface and peer, with overall `peers_total` / `peers_down`. **503** while any peer is down (or collection failed); append `?strict=0` for 200. This is the health endpoint. |
| `GET /status/{iface}` | Same JSON for **one** interface (404 if unknown); **503** while that interface is degraded. Point a per-link watchdog here to restart interfaces individually. |
| `GET /robots.txt` | Disallows all crawlers. Public, no auth. |
| `GET /favicon.svg` | Site icon. Public, no auth. |

Any other path returns **404**.

**Monitoring:** point an [Uptime-Kuma](https://github.com/louislam/uptime-kuma)
HTTP monitor (with the basic-auth credentials) at `GET /status` — it returns
**503 while any peer is down**, which fires the alert. To restart links, run a
watchdog that polls `GET /status/{iface}` per interface and runs
`wg-quick`/`systemctl` itself when it sees a 503 — wg-status stays privilege-free.

The status routes are behind **HTTP basic auth** (`robots.txt` and the favicon
are public). The password is stored as a salted
**PBKDF2-HMAC-SHA256 hash**, never plaintext — generate one with:

```bash
printf '%s' 'your-password' | wg-status -hash-password
# -> pbkdf2-sha256$210000$<salt>$<hash>   (put this in [Auth] PasswordHash)
```

(Successful verifications are cached so PBKDF2 doesn't run on every request.)

## Peers are auto-detected

You do **not** list peers or interfaces. Every interface and peer that WireGuard
reports is discovered automatically and monitored — any stale peer flips
`/status` to 503. There is no per-peer or per-interface config.

Once an interface has been seen it is **expected to stay present**: if it later
disappears from WireGuard (or collection fails), it is reported as **down** — so a
vanished link still alerts, and `GET /status/{iface}` keeps returning 503 for it.
(A genuinely decommissioned interface therefore shows as down until wg-status is
restarted.)

## Run it locally (full demo, no WireGuard needed)

```bash
docker compose up --build
# open http://localhost:8600   (admin / secret)
```

The demo uses the **fake collector**: four interfaces with live counters, and one
mesh peer whose handshake is frozen so it ages out and shows the interface as
**down (503)**. The demo endpoints use real public IPs so the endpoint
reverse-DNS hover works locally. Watch the status code:

```bash
watch -n2 'curl -s -o /dev/null -w "%{http_code}\n" -u admin:secret localhost:8600/status'
```

Or without Docker:

```bash
WG_COLLECTOR=fake WG_LISTEN=:8600 WG_AUTH_USER=admin WG_AUTH_PASS=secret \
  WG_HANDSHAKE_STALE=45s WG_POLL_INTERVAL=2s \
  go run ./cmd/wg-status
```

## Run it in production (nat-instance)

Reading WireGuard state over netlink needs host network access (the `wg`
collector wants `CAP_NET_ADMIN` and the host network namespace), so the cleanest
deploy is a **static binary under systemd**, not a container:

```bash
# Grab the latest prebuilt static binary (arm64: swap amd64 → arm64).
# Or build it yourself:  go build -o wg-status ./cmd/wg-status
curl -fsSL -o wg-status https://github.com/DigitalTolk/wireguard-status/releases/latest/download/wg-status_linux_amd64
install -m0755 wg-status /usr/local/bin/wg-status
wg-status version   # check what you got
mkdir -p /etc/wg-status && install -m0640 wg-status.example.conf /etc/wg-status/wg-status.conf   # then edit
install -m0644 deploy/wg-status.service /etc/systemd/system/wg-status.service
systemctl daemon-reload && systemctl enable --now wg-status
```

Then add an Uptime-Kuma HTTP monitor for `http://<nat-instance>:8080/status`
with basic-auth creds; it alerts on the 503.

## Configuration

WireGuard-style **INI** file — `[Sections]` with `Key = Value` lines, the same
look and feel as `wgX.conf` (path via `-config` or `WG_CONFIG`, default
`wg-status.conf`; a missing file is fine — defaults + env are used). See
[`wg-status.example.conf`](wg-status.example.conf). The recognised sections are
`[Server]`, `[Auth]` and `[Monitor]`; interfaces and peers are auto-detected, not
configured.

Env overrides for the common knobs: `WG_LISTEN`, `WG_COLLECTOR` (`wg`|`fake`),
`WG_AUTH_USER`, `WG_AUTH_PASS_HASH` (preferred), `WG_HANDSHAKE_STALE`,
`WG_POLL_INTERVAL`, `WG_TLS_CERT`, `WG_TLS_KEY`.

### TLS (HTTPS)

Set both `TLSCert` and `TLSKey` under `[Server]` (or `WG_TLS_CERT` / `WG_TLS_KEY`)
to PEM file paths and the server listens with HTTPS; leave both empty for plain
HTTP. Setting only one is a config error.

```ini
[Server]
Listen  = :8443
TLSCert = /etc/wg-status/tls/cert.pem
TLSKey  = /etc/wg-status/tls/key.pem
```

For local/dev convenience you may instead supply a plaintext password via
`[Auth] Password` or `WG_AUTH_PASS` — it is hashed in memory at startup (with a
warning). The docker-compose demo uses this. For production, set `PasswordHash`.

## Restarting links

wg-status never restarts anything itself. Run a small watchdog that polls
`GET /status/{iface}` for each interface and, on a 503, restarts that link with
whatever it has privileges for (e.g. `systemctl restart wg-quick@wg0`). Keeping
restarts out of wg-status means it needs no root and can't bounce a link on its
own.

## Layout

```
cmd/wg-status/      entrypoint + wiring + `-hash-password`
internal/auth/      PBKDF2 password hashing & verification
internal/config/    INI config (WireGuard-style) + env overrides
internal/wg/        data model, wgctrl (netlink) collector, fake demo collector
internal/status/    state evaluation + down-since tracking (read-only)
internal/web/       basic auth, JSON status API + static dashboard shell
deploy/             systemd unit
```
