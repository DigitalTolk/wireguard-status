# wireguard-status

A tiny, dependency-free Go service that renders a **server-side status page** for
your WireGuard interfaces and peers, and returns **HTTP 503 while any monitored
peer is down** so [Uptime-Kuma](https://github.com/louislam/uptime-kuma) (or any
HTTP check) can alert you. It can also **restart a failing link** — manually from
the page, or automatically once a link has been down long enough.

Built for the `nat-instance` pattern: a host that is simultaneously a NAT exit,
a WireGuard server for site VPNs (`wg0`, `wg2`, …), and part of a VPC mesh
(`wg-mesh`, `wg-mesh-stg`).

## What it shows

For every interface and peer: public key, listen port, endpoint, allowed IPs,
**link state** (up / down / never), **rx/tx counters**, **last handshake**, and
persistent-keepalive. A peer is **down** when its last handshake is older than
`thresholds.handshake_stale` (default 180s).

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | SSR status page. Returns **503** (still rendering the page) when any monitored peer is down. Append `?strict=0` to always get 200 for browsing. |
| `GET /healthz` | JSON summary; 503 while degraded. Point Uptime-Kuma here if you'd rather not parse HTML. |
| `POST /restart/{iface}` | Restart an interface (the page's button posts here). |

Everything is behind **HTTP basic auth**. The password is stored as a salted
**PBKDF2-HMAC-SHA256 hash**, never plaintext — generate one with:

```bash
printf '%s' 'your-password' | wg-status -hash-password
# -> pbkdf2-sha256$210000$<salt>$<hash>   (put this in [Auth] PasswordHash)
```

(Successful verifications are cached so PBKDF2 doesn't run on every request.)

## Peers are auto-detected

You do **not** list peers or interfaces. Every interface and peer that WireGuard
reports is discovered automatically and monitored — any stale peer flips the page
to 503. There is no per-peer or per-interface config; auto-restart is a single
global setting (`[AutoRestart] Enabled`).

## Run it locally (full demo, no WireGuard needed)

```bash
docker compose up --build
# open http://localhost:8600   (admin / secret)
```

The demo uses the **fake collector**: four interfaces with one mesh peer that
flaps. With the short demo thresholds you'll watch it go **up → stale (503) →
auto-restart → up** roughly once a minute. Watch the status code:

```bash
watch -n2 'curl -s -o /dev/null -w "%{http_code}\n" -u admin:secret localhost:8600/healthz'
```

Or without Docker:

```bash
WG_COLLECTOR=fake WG_LISTEN=:8600 WG_AUTH_USER=admin WG_AUTH_PASS=secret \
  WG_HANDSHAKE_STALE=45s WG_POLL_INTERVAL=2s WG_AUTORESTART_DOWNFOR=20s \
  go run ./cmd/wg-status
```

## Run it in production (nat-instance)

Reading `wg show all dump` and running `wg-quick`/`systemctl` need host network
access and privileges, so the cleanest deploy is a **static binary under
systemd**, not a container:

```bash
go build -o wg-status ./cmd/wg-status
install -m0755 wg-status /usr/local/bin/wg-status
mkdir -p /etc/wg-status && install -m0640 wg-status.example.conf /etc/wg-status/wg-status.conf   # then edit
install -m0644 deploy/wg-status.service /etc/systemd/system/wg-status.service
systemctl daemon-reload && systemctl enable --now wg-status
```

Then add an Uptime-Kuma HTTP monitor for `http://<nat-instance>:8080/` with
basic-auth creds; it alerts on the 503.

## Configuration

WireGuard-style **INI** file — `[Sections]` with `Key = Value` lines, the same
look and feel as `wgX.conf` (path via `-config` or `WG_CONFIG`, default
`wg-status.conf`; a missing file is fine — defaults + env are used). See
[`wg-status.example.conf`](wg-status.example.conf). Per-interface overrides go in
repeated `[Interface]` blocks (with a `Name =`), and per-peer metadata in
repeated `[Peer]` blocks (with a `PublicKey =`), just like a WireGuard config.

Env overrides for the common knobs: `WG_LISTEN`, `WG_COLLECTOR` (`wg`|`fake`),
`WG_AUTH_USER`, `WG_AUTH_PASS_HASH` (preferred), `WG_HANDSHAKE_STALE`,
`WG_POLL_INTERVAL`, `WG_AUTORESTART`, `WG_AUTORESTART_DOWNFOR`.

For local/dev convenience you may instead supply a plaintext password via
`[Auth] Password` or `WG_AUTH_PASS` — it is hashed in memory at startup (with a
warning). The docker-compose demo uses this. For production, set `PasswordHash`.

### Auto-restart safety

A link must be **continuously degraded for `down_for`** before a restart is
attempted; restarts are then rate-limited by `cooldown` and capped at
`max_attempts` per outage (the counter resets when the link recovers). This
prevents restart loops on a genuinely-broken link. Set `[AutoRestart] Enabled`
to `false` to keep restarts manual-only.

## Layout

```
cmd/wg-status/      entrypoint + wiring + `-hash-password`
internal/auth/      PBKDF2 password hashing & verification
internal/config/    INI config (WireGuard-style) + env overrides
internal/wg/        data model, `wg show all dump` parser, fake demo collector
internal/status/    state evaluation, down-since tracking, auto-restart loop
internal/web/       basic auth, SSR handlers, embedded template + CSS
deploy/             systemd unit
```
