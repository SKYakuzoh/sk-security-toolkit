#!/usr/bin/env python3
"""
sk-scan : scanner TCP recon fait maison, opsec et moins bruyant.

But : un scanner "type nmap" mais en TCP connect pur (aucun privilege,
marche en environnement restreint), avec des options d'opsec et un mode
Tor fiable (contrairement a nmap --proxies qui peut fuiter en direct).

Points opsec :
- ordre des ports randomise par defaut (casse la signature sequentielle).
- rate limiting (--rate) et delai (--delay) pour ressembler a du trafic humain.
- presets de timing (--timing) reglant rate/delay/timeout/retries d'un coup.
- pas de banner grabbing par defaut (-b pour l'activer) -> moins de trafic.
- mode Tor via SOCKS5 (chemin prouve, pas de repli en direct).
- aucun binaire privilegie, aucune dependance externe (stdlib uniquement).

Aucune fonctionnalite destructive. Pour tests autorises uniquement.
"""

import argparse
import csv
import io
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "0.2.0"

# ---------------------------------------------------------------------------
# Presets de ports
# ---------------------------------------------------------------------------
TOP20 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
         993, 995, 1723, 3306, 3389, 5900, 8080]
TOP100 = sorted(set(TOP20 + [
    20, 69, 113, 119, 161, 194, 389, 465, 512, 513, 514, 631, 636, 873,
    990, 992, 1080, 1194, 1433, 1521, 2049, 2222, 2375, 2376, 3128, 3268,
    5060, 5432, 5601, 5672, 5984, 6379, 6443, 6660, 6661, 6662, 6663, 6664,
    6665, 6666, 6667, 7001, 8000, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
    11211, 27017, 50000, 50070,
]))
# ordre de "popularite" pour --top N
POPULARITY = TOP20 + [p for p in TOP100 if p not in TOP20]

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 69: "tftp",
    80: "http", 110: "pop3", 111: "rpc", 113: "ident", 119: "nntp", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 194: "irc", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 512: "rexec", 513: "rlogin",
    514: "syslog", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2222: "ssh-alt", 2375: "docker", 3128: "squid", 3268: "ldap",
    3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgres", 5601: "kibana",
    5672: "rabbitmq", 5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "k8s",
    6667: "irc", 7001: "weblogic", 8000: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "http-alt", 9200: "elasticsearch", 9300: "es-transport",
    11211: "memcached", 27017: "mongodb", 50000: "db2",
}

BANNER_PROBES = {
    80:  b"GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: sk-scan\r\n\r\n",
    443: b"GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: sk-scan\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: sk-scan\r\n\r\n",
    8443: b"GET / HTTP/1.0\r\nHost: scan\r\nUser-agent: sk-scan\r\n\r\n",
}

# Presets de timing : (rate_sondes/s, delay_s, timeout_s, retries)
TIMING_PRESETS = {
    "paranoid":    (1,   2.0, 5.0, 1),
    "sneaky":      (5,   1.0, 3.0, 1),
    "polite":      (30,  0.1, 2.0, 1),
    "normal":      (None, 0.0, 1.5, 1),   # None = pas de limite, threads governent
    "aggressive":  (None, 0.0, 0.5, 1),
}


# ---------------------------------------------------------------------------
# SOCKS5 (chemin Tor fiable, code a la main)
# ---------------------------------------------------------------------------
def socks5_connect(proxy_host, proxy_port, dst_host, dst_port, timeout):
    """Ouvre une connexion vers dst via un proxy SOCKS5. Retourne un socket connecte."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_host, proxy_port))
    # greeting : no-auth
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if resp != b"\x05\x00":
        s.close()
        raise OSError("socks5: methode d'auth refusee")
    # demande de connexion (IPv4 ou domaine -> Tor resout, anti-fuite DNS)
    if _is_ipv4(dst_host):
        req = b"\x05\x01\x00\x01" + socket.inet_aton(dst_host) + struct.pack("!H", dst_port)
    else:
        hb = dst_host.encode("idna")
        req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", dst_port)
    s.sendall(req)
    rep = s.recv(10)
    if len(rep) < 2:
        s.close()
        raise OSError("socks5: reponse incomplete")
    code = rep[1]
    if code == 0x00:
        return s
    s.close()
    codes = {0x01: "echec general", 0x02: "regles interdites", 0x03: "reseau injoignable",
             0x04: "host injoignable", 0x05: "connexion refusee", 0x06: "TTL expire",
             0x07: "commande non supportee", 0x08: "adresse non supportee"}
    raise OSError(f"socks5: {codes.get(code, 'erreur '+str(code))}")


def _is_ipv4(h):
    try:
        socket.inet_aton(h)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Rate limiter thread-safe
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, rate, delay):
        # rate = sondes/sec max ; delay = s entre sondes (en plus)
        self.min_interval = (1.0 / rate) if rate else 0.0
        self.delay = delay
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        if not self.min_interval and not self.delay:
            return
        with self.lock:
            now = time.monotonic()
            wait_for = self.min_interval - (now - self.last)
            if wait_for > 0:
                time.sleep(wait_for)
            if self.delay:
                time.sleep(self.delay)
            self.last = time.monotonic()


# ---------------------------------------------------------------------------
# Parsing des cibles et ports
# ---------------------------------------------------------------------------
def parse_ports(args):
    if args.full:
        return list(range(1, 65536))
    if args.top:
        return POPULARITY[:args.top]
    if args.ports:
        ports = set()
        for chunk in args.ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                a, b = chunk.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            else:
                ports.add(int(chunk))
        return sorted(ports)
    return TOP20[:]


def expand_target(t):
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
        except ValueError:
            pass
    if t.count(".") == 3 and "-" in t.split(".")[-1]:
        base, last = t.rsplit(".", 1)
        if "-" in last:
            a, b = last.split("-", 1)
            try:
                return [f"{base}.{i}" for i in range(int(a), int(b) + 1)]
            except ValueError:
                pass
    return [t]


def parse_targets(args):
    raw = list(args.target)
    if args.input_list:
        try:
            with open(args.input_list) as f:
                raw += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except OSError as e:
            die(f"lecture {args.input_list}: {e}")
    seen, out = set(), []
    for t in raw:
        for h in expand_target(t):
            if h not in seen:
                seen.add(h)
                out.append(h)
    return out


def die(msg):
    print(f"sk-scan: erreur: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------
def probe(host, port, timeout, do_banner, proxy, rate):
    rate.wait()
    # resolution hostname -> IP (Tor resout lui-meme si proxy, on laisse le domaine)
    direct_host = host  # on garde le nom pour SOCKS5-domain ; pour direct on resout via connect
    try:
        if proxy:
            try:
                s = socks5_connect(proxy[0], proxy[1], direct_host, port, timeout)
            except OSError as e:
                return "error", str(e)
            state = "open"
            banner = ""
            if do_banner:
                banner = _banner_from(s, port, timeout)
            s.close()
            return state, banner
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((host, port))
                banner = _grab_banner(host, port, timeout) if do_banner else ""
                s.close()
                return "open", banner
            except ConnectionRefusedError:
                s.close()
                return "closed", ""
            except socket.timeout:
                return "filtered", ""
            except socket.gaierror:
                return "error", "DNS"
    except OSError as e:
        return "error", str(e)


def _grab_banner(host, port, timeout):
    """Banner grabbing en connexion directe (nouveau socket)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return _banner_from(s, port, timeout)
    except Exception:
        return ""


def _banner_from(s, port, timeout):
    """Lit une banniere sur un socket deja connecte."""
    probe = BANNER_PROBES.get(port, b"")
    banner = ""
    try:
        s.settimeout(timeout)
        data = s.recv(256)
        if data:
            banner = data.decode(errors="ignore").strip()
    except socket.timeout:
        pass
    if not banner and probe:
        try:
            s.sendall(probe)
            data = s.recv(512)
            if data:
                first = data.decode(errors="ignore").splitlines()
                banner = first[0].strip() if first else ""
        except Exception:
            pass
    banner = banner.replace("\r", " ").replace("\n", " ").strip()
    if len(banner) > 120:
        banner = banner[:120] + "..."
    return banner


# ---------------------------------------------------------------------------
# Scan d'un hote
# ---------------------------------------------------------------------------
def scan_host(host, ports, timeout, threads, do_banner, proxy, rate, show_all, retries):
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {}
        for p in ports:
            for attempt in range(retries):
                futures[ex.submit(probe, host, p, timeout, do_banner, proxy, rate)] = p
                break
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                state, banner = fut.result()
            except Exception as e:
                state, banner = "error", str(e)
            if state == "open" or show_all:
                results.append((host, port, state, banner))
    results.sort(key=lambda r: r[1])
    return results


# ---------------------------------------------------------------------------
# Test prealable du proxy (detecte torsocks qui bloque)
# ---------------------------------------------------------------------------
def check_proxy(proxy):
    try:
        s = socks5_connect(proxy[0], proxy[1], "1.1.1.1", 80, 5)
        s.close()
        return True, None
    except OSError as e:
        msg = str(e)
        hint = None
        if proxy[0] in ("127.0.0.1", "localhost") and ("not permitted" in msg.lower() or "refusee" in msg or "Connection to a local address" in msg):
            hint = ("torsocks semble precharge (LD_PRELOAD) et bloque la connexion au proxy local. "
                    "Lance avec: env -u LD_PRELOAD sk-scan --tor ...")
        return False, hint or msg


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        prog="sk-scan",
        description="Scanner TCP recon opsec (TCP connect, sans privilege, mode Tor fiable).",
        epilog="Tests autorises uniquement.",
    )
    ap.add_argument("target", nargs="*", help="IP / hostname / CIDR / range (1.1.1.1-50)")
    ap.add_argument("-iL", "--input-list", help="fichier de cibles")
    ap.add_argument("-p", "--ports", help="ports custom (22,80,443 ou 1-1024)")
    ap.add_argument("--top", type=int, help="top-N ports")
    ap.add_argument("--full", action="store_true", help="1-65535")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--tor", action="store_true", help="router via SOCKS5 Tor (127.0.0.1:9050)")
    g.add_argument("--proxy", help="proxy SOCKS5 generique (socks5://host:port)")
    ap.add_argument("--tor-port", type=int, default=9050, help="port du proxy Tor (defaut 9050)")
    ap.add_argument("-t", "--timeout", type=float, help="timeout par sonde (s)")
    ap.add_argument("-c", "--threads", type=int, default=100, help="concurrency (defaut 100)")
    ap.add_argument("--rate", type=int, help="max sondes/s (rate limiting anti-IDS)")
    ap.add_argument("--delay", type=float, help="delai (s) entre sondes")
    ap.add_argument("--timing", choices=list(TIMING_PRESETS), help="preset (paranoid|sneaky|polite|normal|aggressive)")
    ap.add_argument("--no-randomize", action="store_true", help="ne pas melanger l'ordre des ports")
    ap.add_argument("-b", "--banner", action="store_true", help="banner grabbing (desactive par defaut, plus bruyant)")
    ap.add_argument("-a", "--all", action="store_true", help="afficher aussi closed/filtered")
    ap.add_argument("-o", "--output", choices=["human", "json", "csv", "grep"], default="human")
    ap.add_argument("-O", "--outfile", help="ecrire la sortie dans un fichier")
    ap.add_argument("--seed", type=int, help="graine du random (reproductible)")
    ap.add_argument("-v", "--version", action="version", version=f"sk-scan {VERSION}")
    args = ap.parse_args()

    if not args.target and not args.input_list:
        ap.error("precise une cible ou -iL <fichier>")

    # timing preset ecrase les valeurs non precisees
    rate, delay, timeout, retries = TIMING_PRESETS["normal"]
    if args.timing:
        rate, delay, timeout, retries = TIMING_PRESETS[args.timing]
    if args.rate is not None:
        rate = args.rate
    if args.delay is not None:
        delay = args.delay
    if args.timeout is not None:
        timeout = args.timeout
    if timeout is None:
        timeout = 1.5

    # proxy
    proxy = None
    if args.tor:
        proxy = ("127.0.0.1", args.tor_port)
    elif args.proxy:
        if args.proxy.startswith("socks5://"):
            hp = args.proxy[len("socks5://"):]
            ph, _, pp = hp.partition(":")
            proxy = (ph, int(pp))
        else:
            die("--proxy attend socks5://host:port")

    if proxy:
        ok, info = check_proxy(proxy)
        if not ok:
            die(f"proxy injoignable ({proxy[0]}:{proxy[1]}): {info}")

    hosts = parse_targets(args)
    ports = parse_ports(args)
    if not args.no_randomize:
        rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()
        rng.shuffle(ports)

    limiter = RateLimiter(rate, delay)

    # en mode rate-limite strict, on baisse la concurrency pour qu'elle ait du sens
    threads = args.threads
    if rate and rate < threads:
        threads = max(1, rate)

    out_lines = []
    all_rows = []

    def emit(line):
        if args.outfile:
            out_lines.append(line)
        else:
            print(line)

    proxy_str = f" via Tor({proxy[0]}:{proxy[1]})" if proxy else ""
    emit(f"sk-scan {VERSION}{proxy_str} - {len(hosts)} hote(s), {len(ports)} port(s), "
         f"threads={threads}, timeout={timeout}s"
         + (f", rate={rate}/s" if rate else "")
         + (f", delay={delay}s" if delay else "")
         + (f", ordre randomise" if not args.no_randomize else ""))

    start = time.monotonic()
    for i, host in enumerate(hosts, 1):
        if len(hosts) > 1:
            emit(f"\n[{i}/{len(hosts)}] {host} ({len(ports)} ports) ...")
        res = scan_host(host, ports, timeout, threads, args.banner, proxy, limiter, args.all, retries)

        if args.output in ("json", "csv"):
            for host_, port, state, banner in res:
                all_rows.append((host_, port, state, SERVICES.get(port, ""), banner))
            continue
        if args.output == "grep":
            for host_, port, state, banner in res:
                if state == "open":
                    emit(f"{host_}\t{port}\t{state}\t{SERVICES.get(port,'')}\t{banner}")
            continue
        # human
        if not res:
            emit("  (rien d'interessant)")
        for host_, port, state, banner in res:
            line = f"  {port:<6}/tcp {state:<8} {SERVICES.get(port,''):<14}"
            if args.banner and banner:
                line += f"  {banner}"
            emit(line)

    elapsed = time.monotonic() - start

    if args.output == "json":
        payload = json.dumps([{"host": h, "port": p, "state": s, "service": sv, "banner": b}
                              for h, p, s, sv, b in all_rows], indent=2, ensure_ascii=False)
        write_out(payload, args.outfile)
    elif args.output == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["host", "port", "state", "service", "banner"])
        w.writerows(all_rows)
        write_out(buf.getvalue(), args.outfile)
    elif args.outfile and out_lines:
        write_out("\n".join(out_lines), args.outfile)

    n_open = sum(1 for r in all_rows if r[2] == "open") if args.output in ("json", "csv") else None
    msg = f"[done] {len(hosts)} hote(s) en {elapsed:.1f}s"
    if n_open is not None:
        msg += f" - {n_open} port(s) ouvert(s)"
    print(msg, file=sys.stderr)


def write_out(content, outfile):
    if outfile:
        with open(outfile, "w") as f:
            f.write(content)
    else:
        print(content)


if __name__ == "__main__":
    main()