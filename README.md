# RinP IPv6 Rotator

> **rinp-ipv6-rotator**

Modern VPS plans ship **one IPv4 address but a whole routed IPv6 block** (usually a /64). This tool turns that block into a **per-connection rotating proxy**: every outbound connection is bound to a random address from the block before it leaves the server, so the target sees a different source IP on every request. Zero extra cost, no proxy vendor, no address-by-address setup.

```
client ──► SOCKS5 / HTTP CONNECT ──► rotator ── binds random 2a01:…:a3f9 ──► target
                                          └── binds random 2a01:…:7c11 ──► target
                                          └── binds random 2a01:…:f00d ──► target
```

Built for authorized engagements that need many source addresses from one box: WAF and rate-limit testing, IP-reputation and geo-block checks, connection throttling research, and fingerprinting defenses that key on source IP.

## How it works

Linux lets you make an entire routed prefix locally bindable with a single route, with no `ip addr add` loops and no per-address configuration:

```sh
ip -6 route add local 2a01:db8:1::/64 dev lo   # the whole block, one command
sysctl -w net.ipv6.ip_nonlocal_bind=1
```

After that, any address in the block works as a `bind()` source address. `setup.sh` automates detection and installation (including a systemd unit for persistence), and `rotator.py` picks a random address per connection.

## Quick start (Linux VPS)

```sh
sudo ./setup.sh --check        # which source mode does this provider support?
sudo ./setup.sh                # whole-block providers: install the local route
python3 rotator.py             # SOCKS5 :1080 + HTTP CONNECT :8080

# per-address providers (e.g. Contabo):
sudo ./setup.sh --pool 100     # configure 100 addresses on the interface
python3 rotator.py --sources iface
```

Point anything proxy-aware at it:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.co         # rotated v6 source
proxychains -q nmap -6 -sT target.corp                             # through proxychains
python3 -c "import requests; print(requests.get(
    'https://ifconfig.co', proxies={'https':'socks5h://127.0.0.1:1080'}).text)"
```

On a laptop without a routed block, or to override detection: `python3 rotator.py --block 2a01:db8:1::/64`.

## Modes

**Proxy (default):** SOCKS5 (RFC 1928, optional RFC 1929 auth) and HTTP CONNECT (optional Basic auth) listeners; every upstream connection rotates:

```sh
python3 rotator.py --no-http                         # SOCKS5 only, no auth
python3 rotator.py --auth operator:s3cret            # both protocols, auth on
python3 rotator.py --listen 10.0.0.5 --socks5 9050   # custom bind/ports
python3 rotator.py --workers 4                       # one process per core (SO_REUSEPORT)
python3 rotator.py --sources iface                   # rotate configured addresses only
```

**Direct (`--target`):** a mini HAProxy-style prober for a single address. It fires requests at one target from rotating sources, with HAProxy-familiar controls (`option httpchk GET /`, `forwardfor`, `set-header Host` analogs):

```sh
# balance roundrobin + option httpchk GET / + option forwardfor
python3 rotator.py --target https://corp-example.com/ \
    --method GET --path / --xff --count 50 --interval 0.5

# http-request set-header Host corp-example.com
python3 rotator.py --target http://203.0.113.10/ --host-header corp-example.com
```

Every attempt logs the chosen source and the response status; `--count 0` (the default) runs until Ctrl+C.

## Performance

The data path is opaque byte pumping: SOCKS5/CONNECT headers are parsed once at connection setup, then bytes flow socket-to-socket. On the author's laptop (loopback, stock CPython 3.14, single worker) the full path (handshake, CONNECT, rotated bind, upstream request) sustains **~1,600–2,700 req/s at 50 concurrent clients, 0 failures across 1,000 requests**; the upstream test server was the bottleneck, not the proxy.

For heavier relaying:

- `--workers N` runs N independent processes sharing the same ports (SO_REUSEPORT): one event loop per core, kernel-balanced.
- `pip install uvloop` is picked up automatically when present (~2–4× loop throughput).
- Sustained multi-gigabit bulk relaying is a job for a C proxy (3proxy, gost, HAProxy). This tool is built for many-connection, per-request rotation workloads of the kind WAF, rate-limit and reputation testing actually produce, and stays well beyond that class of traffic.

## Requirements & limitations

- Linux for the block trick (`setup.sh`); the proxy itself is stdlib-only Python 3.8+ and runs anywhere (pass `--block`).
- **Targets must be reachable over IPv6** (AAAA record). IPv4-only targets fail with an explicit error: IPv6 rotation cannot reach them (no NAT64 in v1). Some networks deliberately block IPv6 egress; this tool is for the ones that do not.
- Providers come in two flavors; `sudo ./setup.sh --check` tells you which one yours is in ~15 seconds:
  - **Whole-block** (Hetzner/OVH/Vultr class): the /64 is statically routed to the VM, every address egresses out of the box (`setup.sh` + `--sources block`).
  - **Per-address** (verified live on Contabo, 2026-09): the upstream only lets through sources **configured on the interface**; a local route alone is silently dropped (SYN leaves, NDP gets answered, nothing returns). Use `setup.sh --pool 100` + `rotator.py --sources iface`. End-to-end verified: 8/8 requests from 8 different addresses.
  - A single assigned address or a dynamic DHCPv6 prefix cannot rotate.
- Rotating sources do not defeat fingerprinting that keys on TLS stack, headers or timing. Pair with appropriate tradecraft for your engagement.
- Open proxies get found: keep listeners on loopback or behind `--auth`, and restrict the firewall to operator-only access.

## Files

| File | Purpose |
|---|---|
| `setup.sh` | detect the block; local route or address pool (`--check`, `--pool N`, `--undo`, `--undo-pool N`, `--persist`) |
| `rotator.py` | SOCKS5 + HTTP CONNECT proxy and direct-mode prober, one file, no deps |

## Disclaimer

Published for **educational purposes and authorized red-team engagements only**. Use exclusively against systems and networks you have written permission to test. The authors accept no liability for misuse.

## License

MIT, see the [LICENSE](LICENSE) file. By **Red in Pulse — Mr.Gedik** (<https://redinpulse.com>).
