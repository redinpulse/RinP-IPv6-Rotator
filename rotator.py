#!/usr/bin/env python3
"""
RinP IPv6 Rotator - turn a routed IPv6 block into a per-connection rotating proxy.

Modes:
  proxy (default)   SOCKS5 and HTTP CONNECT listeners; every outbound connection
                    is bound to a random address from the block before connecting.
  direct            fire requests at a single target (--target), each request
                    from a random source; optional Host override, X-Forwarded-For,
                    method and path control (a mini HAProxy-style prober).

Targets must be reachable over IPv6 (AAAA). IPv4-only targets fail with an
explicit error: this tool rotates IPv6 source addresses only.

Linux: run setup.sh once so the whole block becomes bindable
(`ip -6 route add local <block> dev lo`), or pass --block explicitly.
"""

import argparse
import asyncio
import base64
import hmac
import ipaddress
import logging
import secrets
import socket
import ssl
import subprocess
import sys
import urllib.parse

LOG = logging.getLogger("rotator")

DEFAULT_SOCKS5_PORT = 1080
DEFAULT_HTTP_PORT = 8080
CONNECT_TIMEOUT = 10.0
HTTP_HEAD_LIMIT = 65536

SOCKS_REPLY_OK = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
SOCKS_REPLY_GENERAL = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
SOCKS_REPLY_NOT_ALLOWED = b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00"


class BlockPool:
    """Random source-address generator: a whole prefix or a fixed address list."""

    def __init__(self, cidr, addresses=None):
        self.net = ipaddress.IPv6Network(cidr, strict=False)
        self._bits = self.net.max_prefixlen - self.net.prefixlen
        self._pool = [str(ipaddress.IPv6Address(a)) for a in addresses] \
            if addresses else None
        if self._pool is not None and len(self._pool) < 2:
            raise ValueError("per-address mode needs at least 2 addresses")

    def random(self):
        """Return a random source address (skips the all-zero IID in block mode)."""
        if self._pool is not None:
            return self._pool[secrets.randbelow(len(self._pool))]
        if self._bits == 0:
            return str(self.net.network_address)
        while True:
            offset = secrets.randbits(self._bits)
            if offset:
                return str(ipaddress.IPv6Address(int(self.net.network_address) + offset))

    def __str__(self):
        return str(self.net)


def detect_configured_addresses(cidr):
    """
    List block addresses actually configured on any interface - per-address
    providers (e.g. Contabo) route only configured sources.
    """
    if sys.platform != "linux":
        return []
    net = ipaddress.IPv6Network(cidr, strict=False)
    try:
        out = subprocess.run(["ip", "-6", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for line in out.splitlines():
        parts = line.split()
        if "inet6" in parts:
            addr = parts[parts.index("inet6") + 1].split("/")[0]
            try:
                if ipaddress.IPv6Address(addr) in net:
                    found.append(addr)
            except ValueError:
                continue
    return found


def make_pool(cidr, sources):
    """Build the rotation pool from --sources: the whole block or configured IPs."""
    if sources == "iface":
        addresses = detect_configured_addresses(cidr)
        if len(addresses) < 2:
            raise SystemExit("--sources iface needs >= 2 configured addresses "
                             "from the block - run: sudo ./setup.sh --pool 100")
        LOG.info("per-address pool: %d configured addresses", len(addresses))
        return BlockPool(cidr, addresses)
    return BlockPool(cidr)


def detect_block():
    """
    Auto-detect the first global IPv6 prefix on the default-route interface
    (Linux). Returns None when detection is not possible.
    """
    if sys.platform != "linux":
        return None
    try:
        route = subprocess.run(["ip", "-6", "route", "show", "default"],
                               capture_output=True, text=True, check=True).stdout
        dev = next((part for i, part in enumerate(route.split()) if i and
                    route.split()[i - 1] == "dev"), None)
        if not dev:
            return None
        addrs = subprocess.run(["ip", "-6", "addr", "show", "dev", dev, "scope", "global"],
                               capture_output=True, text=True, check=True).stdout
        best = None
        for line in addrs.splitlines():
            parts = line.split()
            if "inet6" in parts:
                try:
                    net = ipaddress.IPv6Network(
                        parts[parts.index("inet6") + 1], strict=False)
                except ValueError:
                    continue
                if best is None or net.prefixlen < best.prefixlen:
                    best = net
        return str(best) if best else None
    except (OSError, subprocess.SubprocessError):
        return None
    return None


async def open_rotated(pool, host, port, ssl_ctx=None, server_hostname=None):
    """
    Connect to (host, port) over IPv6, binding to a random block address first.

    Returns (reader, writer, source_ip). Raises RuntimeError with an explicit
    reason when the target has no AAAA record or the source bind fails.
    """
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(
            f"{host}: no AAAA record (or unresolvable) - target is IPv4-only; "
            "this tool rotates IPv6 sources only") from exc
    if not infos:
        raise RuntimeError(f"{host}: no AAAA record - target is IPv4-only")
    dst = infos[0][4][0]
    if dst.startswith("::ffff:"):
        raise RuntimeError(f"{host}: resolves to an IPv4-mapped address - target "
                           "is IPv4-only; this tool rotates IPv6 sources only")

    src = pool.random()
    kwargs = {"host": dst, "port": port, "family": socket.AF_INET6,
              "local_addr": (src, 0)}
    if ssl_ctx is not None:
        kwargs["ssl"] = ssl_ctx
        kwargs["server_hostname"] = server_hostname or host
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(**kwargs), CONNECT_TIMEOUT)
    except asyncio.TimeoutError as exc:
        raise RuntimeError(
            f"connect timeout {src} -> {dst} (if this persists for every "
            "source, the provider routes the block via NDP - install ndppd, "
            "see setup.sh --ndp)") from exc
    except OSError as exc:
        raise RuntimeError(
            f"cannot bind/connect source {src} -> {dst} (run setup.sh on the VPS "
            f"or pass --block): {exc}") from exc
    return reader, writer, src


async def _pump(src_reader, dst_writer):
    """Copy bytes one way until EOF or error, then close the destination."""
    try:
        while True:
            data = await src_reader.read(65536)
            if not data:
                break
            dst_writer.write(data)
            await dst_writer.drain()
    except (ConnectionError, OSError, asyncio.TimeoutError):
        pass
    finally:
        try:
            dst_writer.close()
        except (ConnectionError, OSError):
            pass


async def _tunnel(client_reader, client_writer, upstream_reader, upstream_writer):
    await asyncio.gather(_pump(client_reader, upstream_writer),
                         _pump(upstream_reader, client_writer))


class ProxyAuth:
    """Optional user:pass credentials shared by SOCKS5 (RFC 1929) and HTTP Basic."""

    def __init__(self, spec):
        user, _, password = spec.partition(":")
        self.user = user.encode()
        self.password = password.encode()

    def check(self, user, password):
        return hmac.compare_digest(user, self.user) and \
            hmac.compare_digest(password, self.password)

    def basic_challenge(self):
        token = base64.b64encode(self.user + b":" + self.password).decode()
        return "Basic " + token


async def handle_socks5(client_reader, client_writer, pool, auth):
    """Minimal SOCKS5 CONNECT server with per-connection source rotation."""
    peer = client_writer.get_extra_info("peername")
    try:
        greeting = await client_reader.readexactly(2)
        methods = await client_reader.readexactly(greeting[1])
        if auth:
            if b"\x02" not in methods:
                client_writer.write(b"\x05\xff")
                raise ConnectionError("client refuses SOCKS5 auth")
            client_writer.write(b"\x05\x02")
            neg = await client_reader.readexactly(2)
            user = await client_reader.readexactly(neg[1])
            plen = (await client_reader.readexactly(1))[0]
            password = await client_reader.readexactly(plen)
            ok = auth.check(user, password)
            client_writer.write(b"\x01\x00" if ok else b"\x01\x01")
            if not ok:
                raise ConnectionError("bad SOCKS5 credentials")
        else:
            client_writer.write(b"\x05\x00")

        head = await client_reader.readexactly(4)
        if head[1] != 0x01:
            client_writer.write(SOCKS_REPLY_NOT_ALLOWED)
            raise ConnectionError("only CONNECT is supported")
        if head[3] == 0x01:
            await client_reader.readexactly(4 + 2)
            client_writer.write(SOCKS_REPLY_NOT_ALLOWED)
            raise ConnectionError("IPv4 target literal - IPv6 rotation impossible")
        if head[3] == 0x03:
            dlen = (await client_reader.readexactly(1))[0]
            host = (await client_reader.readexactly(dlen)).decode("idna")
        elif head[3] == 0x04:
            raw = await client_reader.readexactly(16)
            host = str(ipaddress.IPv6Address(raw))
        else:
            client_writer.write(SOCKS_REPLY_GENERAL)
            raise ConnectionError("bad SOCKS5 address type")
        port = int.from_bytes(await client_reader.readexactly(2), "big")

        try:
            upstream_reader, upstream_writer, src = await open_rotated(pool, host, port)
        except RuntimeError as exc:
            LOG.warning("%s: %s", peer[0], exc)
            client_writer.write(SOCKS_REPLY_GENERAL)
            raise ConnectionError(str(exc)) from exc

        client_writer.write(SOCKS_REPLY_OK)
        LOG.info("%s -> [%s]:%d via %s", peer[0], host, port, src)
        await _tunnel(client_reader, client_writer, upstream_reader, upstream_writer)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        try:
            client_writer.close()
        except (ConnectionError, OSError):
            pass


def _parse_head(head):
    """Split a raw HTTP request head into (method, target, version, [header lines])."""
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 3:
        raise ValueError("malformed request line")
    return parts[0], parts[1], parts[2], [line for line in lines[1:] if line]


def _hop_headers(lines):
    return [line for line in lines if not line.lower().startswith(
        ("proxy-authorization:", "proxy-connection:"))]


async def handle_http(client_reader, client_writer, pool, auth):
    """HTTP CONNECT + absolute-form forward proxy with source rotation."""
    peer = client_writer.get_extra_info("peername")
    try:
        head = await asyncio.wait_for(
            client_reader.readuntil(b"\r\n\r\n"), CONNECT_TIMEOUT)
        method, target, version, lines = _parse_head(head[:-4])
        headers = dict()
        for line in lines:
            name, _, value = line.partition(":")
            headers.setdefault(name.strip().lower(), value.strip())

        if auth:
            supplied = headers.get("proxy-authorization", "")
            if not hmac.compare_digest(supplied, auth.basic_challenge()):
                client_writer.write(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"rotator\"\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                raise ConnectionError("bad HTTP proxy credentials")

        if method.upper() == "CONNECT":
            host, _, port = target.rpartition(":")
            port = int(port or 443)
            host = host.strip("[]")
            try:
                upstream_reader, upstream_writer, src = await open_rotated(pool, host, port)
            except RuntimeError as exc:
                LOG.warning("%s: %s", peer[0], exc)
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                                    b"Connection: close\r\n\r\n")
                raise ConnectionError(str(exc)) from exc
            client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            LOG.info("%s -> CONNECT %s:%d via %s", peer[0], host, port, src)
            await _tunnel(client_reader, client_writer, upstream_reader, upstream_writer)
        else:
            url = urllib.parse.urlsplit(target)
            if url.scheme != "http" or not url.hostname:
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                                    b"Connection: close\r\n\r\n")
                raise ConnectionError("only http:// absolute-form is supported")
            port = url.port or 80
            path = url.path or "/"
            if url.query:
                path += "?" + url.query
            host_display = f"[{url.hostname}]" if ":" in url.hostname else url.hostname
            out = [f"{method} {path} {version}",
                   f"Host: {host_display}" + (f":{url.port}" if url.port else "")]
            for line in _hop_headers(lines):
                if not line.lower().startswith("host:"):
                    out.append(line)
            out.append("Connection: close")
            request = ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")

            try:
                upstream_reader, upstream_writer, src = await open_rotated(pool, url.hostname, port)
            except RuntimeError as exc:
                LOG.warning("%s: %s", peer[0], exc)
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                                    b"Connection: close\r\n\r\n")
                raise ConnectionError(str(exc)) from exc
            upstream_writer.write(request)
            LOG.info("%s -> %s %s:%d%s via %s", peer[0], method, url.hostname, port, path, src)
            await _tunnel(client_reader, client_writer, upstream_reader, upstream_writer)
    except (asyncio.IncompleteReadError, ValueError, ConnectionError, OSError,
            asyncio.TimeoutError, asyncio.LimitOverrunError):
        pass
    finally:
        try:
            client_writer.close()
        except (ConnectionError, OSError):
            pass


async def run_direct(args, pool):
    """
    Direct mode: fire --method/--path requests at --target, one random source
    per request, logging status per attempt. --xff adds X-Forwarded-For with
    the chosen source; --host-header overrides the Host header.
    """
    url = urllib.parse.urlsplit(args.target if "//" in args.target
                                else "//" + args.target, scheme="http")
    if url.scheme not in ("http", "https") or not url.hostname:
        raise SystemExit("--target must be http(s)://host[:port][/path]")
    port = url.port or (443 if url.scheme == "https" else 80)
    path = args.path or url.path or "/"
    ssl_ctx = ssl.create_default_context() if url.scheme == "https" else None
    host_header = args.host_header or url.hostname
    done, failed = 0, 0

    async def one():
        nonlocal done, failed
        reader, writer, src = await open_rotated(
            pool, url.hostname, port, ssl_ctx=ssl_ctx, server_hostname=url.hostname)
        out = [f"{args.method} {path} HTTP/1.1", f"Host: {host_header}",
               "User-Agent: RinP-IPv6-Rotator/1.0", "Accept: */*",
               "Connection: close"]
        if args.xff:
            out.append(f"X-Forwarded-For: {src}")
        writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        status = (await asyncio.wait_for(reader.readline(), CONNECT_TIMEOUT)
                  ).decode("latin-1").strip()
        await reader.read()
        writer.close()
        LOG.info("[%s] %s %s -> %s", src, args.method, args.target,
                 status or "(no response)")

    try:
        while args.count == 0 or done + failed < args.count:
            try:
                await one()
                done += 1
            except RuntimeError as exc:
                failed += 1
                LOG.warning("%s", exc)
                if "IPv4-only" in str(exc):
                    break
            if args.count == 0 or done + failed < args.count:
                await asyncio.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    LOG.info("direct mode finished: %d ok, %d failed", done, failed)


def build_parser():
    parser = argparse.ArgumentParser(
        description="RinP IPv6 Rotator - per-connection rotating proxy from an "
                    "IPv6 block (SOCKS5 + HTTP CONNECT, or direct single-target prober)")
    parser.add_argument("--block", metavar="CIDR",
                        help="IPv6 block to rotate (default: auto-detect on Linux)")
    parser.add_argument("--sources", choices=("block", "iface"), default="block",
                        help="block: rotate through the whole prefix (providers "
                             "that route it, e.g. Hetzner/OVH/Vultr); iface: "
                             "rotate only through configured addresses (per-address "
                             "providers, e.g. Contabo - see setup.sh --pool)")
    parser.add_argument("--target", metavar="URL",
                        help="direct mode: probe this single target with rotating "
                             "sources (disables the proxy listeners)")
    parser.add_argument("--method", default="GET", help="direct mode: HTTP method")
    parser.add_argument("--path", help="direct mode: override request path")
    parser.add_argument("--host-header", metavar="HOST",
                        help="direct mode: override the Host header")
    parser.add_argument("--xff", action="store_true",
                        help="direct mode: send X-Forwarded-For with the chosen source")
    parser.add_argument("--count", type=int, default=0, metavar="N",
                        help="direct mode: stop after N requests (0 = until Ctrl+C)")
    parser.add_argument("--interval", type=float, default=1.0, metavar="SEC",
                        help="direct mode: delay between requests (default 1.0)")
    parser.add_argument("--socks5", type=int, default=DEFAULT_SOCKS5_PORT, metavar="PORT",
                        help="SOCKS5 listen port (default %(default)s)")
    parser.add_argument("--no-socks5", action="store_true", help="disable SOCKS5 listener")
    parser.add_argument("--http", type=int, default=DEFAULT_HTTP_PORT, metavar="PORT",
                        help="HTTP CONNECT listen port (default %(default)s)")
    parser.add_argument("--no-http", action="store_true", help="disable HTTP listener")
    parser.add_argument("--listen", default="::", metavar="ADDR",
                        help="proxy listen address (default ::, dual-stack)")
    parser.add_argument("--auth", metavar="USER:PASS",
                        help="require proxy authentication (SOCKS5 RFC1929 / HTTP Basic)")
    parser.add_argument("--workers", type=int, default=1, metavar="N",
                        help="run N proxy worker processes sharing the ports via "
                             "SO_REUSEPORT (default 1; direct mode ignores this)")
    parser.add_argument("--log", metavar="FILE", help="also log to FILE")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def _apply_loop_policy():
    """Prefer uvloop when installed; stdlib selector loop otherwise."""
    try:
        import uvloop
    except ImportError:
        return False
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    LOG.info("uvloop available - using accelerated event loop")
    return True


async def _serve(host, port, factory, reuse_port):
    """
    Start a listener; a wildcard :: address gets a dual-stack socket
    (IPV6_V6ONLY=0) so IPv4-loopback clients work on Linux too.
    """
    if host in ("::", ""):
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            if reuse_port:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("::", port))
            sock.listen(128)
            return await asyncio.start_server(factory, sock=sock)
        except OSError:
            pass
    try:
        return await asyncio.start_server(factory, host, port, reuse_port=reuse_port)
    except OSError:
        return await asyncio.start_server(factory, host, port)


async def run_proxy(listen, socks_port, http_port, no_socks, no_http,
                    pool, auth, reuse_port=False):
    servers = []
    if not no_socks:
        servers.append(await _serve(
            listen, socks_port,
            lambda r, w: handle_socks5(r, w, pool, auth), reuse_port))
        LOG.info("SOCKS5 listening on [%s]:%d%s", listen, socks_port,
                 " (reuse_port)" if reuse_port else "")
    if not no_http:
        servers.append(await _serve(
            listen, http_port,
            lambda r, w: handle_http(r, w, pool, auth), reuse_port))
        LOG.info("HTTP CONNECT listening on [%s]:%d%s", listen, http_port,
                 " (reuse_port)" if reuse_port else "")
    if not servers:
        raise SystemExit("nothing to do: both listeners disabled and no --target")
    await asyncio.Event().wait()


def _proxy_worker(cidr, sources, auth_spec, listen, socks_port, http_port,
                  no_socks, no_http):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    _apply_loop_policy()
    pool = make_pool(cidr, sources)
    auth = ProxyAuth(auth_spec) if auth_spec else None
    try:
        asyncio.run(run_proxy(listen, socks_port, http_port, no_socks, no_http,
                              pool, auth, reuse_port=True))
    except KeyboardInterrupt:
        pass


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")
    if args.log:
        logging.getLogger().addHandler(logging.FileHandler(args.log))

    cidr = args.block or detect_block()
    if not cidr:
        raise SystemExit("no IPv6 block detected - pass --block <cidr> "
                         "(Linux auto-detect needs `ip`)")
    pool = make_pool(cidr, args.sources)
    LOG.info("rotating block: %s (%s mode)", pool, args.sources)
    auth = ProxyAuth(args.auth) if args.auth else None

    try:
        if args.target:
            asyncio.run(run_direct(args, pool))
        elif args.workers > 1:
            import multiprocessing as mp
            LOG.info("starting %d workers (SO_REUSEPORT)", args.workers)
            procs = [mp.Process(
                target=_proxy_worker,
                args=(cidr, args.sources, args.auth, args.listen, args.socks5,
                      args.http, args.no_socks5, args.no_http), daemon=True)
                for _ in range(args.workers)]
            for proc in procs:
                proc.start()
            try:
                for proc in procs:
                    proc.join()
            except KeyboardInterrupt:
                for proc in procs:
                    proc.terminate()
        else:
            asyncio.run(run_proxy(args.listen, args.socks5, args.http,
                                  args.no_socks5, args.no_http, pool, auth))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
