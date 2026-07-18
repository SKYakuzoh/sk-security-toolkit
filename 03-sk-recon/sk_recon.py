#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import xml.etree.ElementTree as ET
from colorama import Fore, Style, init

init(autoreset=True)

# ============================================================
# LOOKUP TABLE : service detecte → suggestions enum/attaque
# ============================================================

SERVICE_HINTS = {
    "ssh":        ["hydra -L users.txt -P rockyou.txt ssh://IP", "ssh-audit IP"],
    "ftp":        ["ftp IP (anonymous/anonymous)", "nmap --script ftp-anon IP"],
    "http":       ["whatweb IP", "feroxbuster IP", "nikto -h IP"],
    "https":      ["whatweb IP", "feroxbuster IP", "sslscan IP"],
    "smb":        ["netexec smb IP --shares", "enum4linux-ng -A IP", "netexec smb IP --users"],
    "microsoft-ds": ["netexec smb IP --shares", "enum4linux-ng -A IP"],
    "msrpc":      ["rpcclient -U '' -N IP", "impacket-rpcdump IP"],
    "ldap":       ["ldapsearch -x -H ldap://IP -b 'DC=x,DC=x'", "netexec ldap IP --users"],
    "ldaps":      ["ldapsearch -x -H ldaps://IP -b 'DC=x,DC=x'"],
    "mssql":      ["impacket-mssqlclient IP", "netexec mssql IP -u '' -p ''"],
    "mysql":      ["mysql -u root -h IP", "netexec mysql IP -u root -p ''"],
    "rdp":        ["xfreerdp /v:IP", "crowbar -b rdp -s IP/32 -U users.txt -c pass"],
    "winrm":      ["evil-winrm -i IP -u user -p pass"],
    "wsman":      ["evil-winrm -i IP -u user -p pass"],
    "kerberos":   ["kerbrute userenum -d domain.local --dc IP users.txt", "impacket-GetNPUsers domain/ -dc-ip IP -no-pass -usersfile users.txt"],
    "dns":        ["dig axfr @IP domain.local", "dnsenum --enum domain.local"],
    "snmp":       ["snmpwalk -v2c -c public IP", "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt IP"],
    "nfs":        ["showmount -e IP", "mount -t nfs IP:/ /mnt/nfs"],
    "smtp":       ["smtp-user-enum -M VRFY -U users.txt -t IP"],
    "pop3":       ["hydra -L users.txt -P rockyou.txt pop3://IP"],
    "imap":       ["hydra -L users.txt -P rockyou.txt imap://IP"],
}

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

# ============================================================
# ARGS
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(description="SK Recon — scanner automatise")
    parser.add_argument("-ip", required=True, help="Adresse IP cible")
    parser.add_argument("-u", required=False, help="Domaine/URL cible (optionnel)")
    return parser.parse_args()

# ============================================================
# ROOT CHECK
# ============================================================

def check_root():
    if os.geteuid() != 0:
        print(Fore.RED + "[!] Lance le script en sudo.")
        sys.exit(1)

# ============================================================
# NMAP
# ============================================================

def run_nmap(ip):
    output_file = f"/tmp/sk_nmap_{ip.replace('.', '_')}"
    print(Fore.YELLOW + f"\n[*] Lancement nmap top 200 sur {ip}...")
    cmd = [
        "nmap", "-sV", "--top-ports", "200",
        "-oX", f"{output_file}.xml",
        "-oN", f"{output_file}.txt",
        ip
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(Fore.GREEN + f"[+] Nmap termine. Output : {output_file}.xml")
    return f"{output_file}.xml"

# ============================================================
# PARSE XML
# ============================================================

def parse_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    open_ports = []

    for host in root.findall("host"):
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid   = port.get("portid")
            proto    = port.get("protocol")
            service  = port.find("service")
            svc_name = service.get("name", "unknown") if service is not None else "unknown"
            version  = ""
            if service is not None:
                product = service.get("product", "")
                ver     = service.get("version", "")
                version = f"{product} {ver}".strip()
            open_ports.append({
                "port":    portid,
                "proto":   proto,
                "service": svc_name,
                "version": version,
            })

    return open_ports

# ============================================================
# DISPLAY SUMMARY
# ============================================================

def display_summary(open_ports, ip):
    if not open_ports:
        print(Fore.RED + "\n[!] Aucun port ouvert detecte.")
        return

    print(Fore.CYAN + f"\n{'='*65}")
    print(Fore.CYAN + f"  PORTS OUVERTS — {ip}")
    print(Fore.CYAN + f"{'='*65}")
    print(f"{'PORT':<8} {'PROTO':<7} {'SERVICE':<15} {'VERSION'}")
    print(f"{'-'*65}")

    for p in open_ports:
        print(
            Fore.GREEN + f"{p['port']:<8}" +
            Fore.WHITE + f"{p['proto']:<7}" +
            Fore.YELLOW + f"{p['service']:<15}" +
            Fore.WHITE + f"{p['version']}"
        )

    print(Fore.CYAN + f"{'='*65}")

# ============================================================
# SUGGESTIONS ENUM / ATTAQUE
# ============================================================

def suggest_next(open_ports, ip):
    print(Fore.CYAN + f"\n{'='*65}")
    print(Fore.CYAN + "  SUGGESTIONS ENUM / ATTAQUE")
    print(Fore.CYAN + f"{'='*65}")

    found_any = False
    for p in open_ports:
        svc = p["service"].lower()
        matched = None
        for key in SERVICE_HINTS:
            if key in svc:
                matched = key
                break
        if matched:
            found_any = True
            print(Fore.YELLOW + f"\n[Port {p['port']}] {p['service']}")
            for hint in SERVICE_HINTS[matched]:
                print(Fore.WHITE + f"  → {hint.replace('IP', ip)}")

    if not found_any:
        print(Fore.WHITE + "  Aucune suggestion automatique pour ces services.")

    print(Fore.CYAN + f"{'='*65}")

# ============================================================
# EXTRACT DOMAIN DEPUIS NMAP XML
# ============================================================

def extract_domain(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    domains = set()

    for script in root.iter("script"):
        output = script.get("output", "")
        # http-title, ssl-cert, rdns
        for word in output.split():
            if "." in word and any(tld in word for tld in [".htb", ".vl", ".local", ".lab", ".internal", ".corp"]):
                cleaned = word.strip("(),;:")
                if cleaned:
                    domains.add(cleaned)

    # hostname dans nmap
    for hostname in root.iter("hostname"):
        name = hostname.get("name", "")
        if name:
            domains.add(name)

    return list(domains)

# ============================================================
# UPDATE /ETC/HOSTS
# ============================================================

def update_hosts(ip, domains):
    if not domains:
        return

    with open("/etc/hosts", "r") as f:
        content = f.read()

    added = []
    for domain in domains:
        entry = f"{ip}\t{domain}"
        if domain in content:
            print(Fore.YELLOW + f"[~] Deja dans /etc/hosts : {entry}")
        else:
            with open("/etc/hosts", "a") as f:
                f.write(f"\n{entry}")
            print(Fore.GREEN + f"[+] Ajoute dans /etc/hosts : {entry}")
            added.append(domain)

    return added

# ============================================================
# WEB CHECKS
# ============================================================

def run_web_checks(ip, open_ports, domain=None):
    web_found = [p for p in open_ports if int(p["port"]) in WEB_PORTS]
    if not web_found:
        return

    urls = []
    for p in web_found:
        port = p["port"]
        scheme = "https" if port in ["443", "8443"] else "http"
        url = f"{scheme}://{ip}" if port in ["80", "443"] else f"{scheme}://{ip}:{port}"
        if url not in urls:
            urls.append(url)

    for url in urls:
        print(Fore.CYAN + f"\n{'='*65}")
        print(Fore.CYAN + f"  WEB CHECKS — {url}")
        print(Fore.CYAN + f"{'='*65}")

        print(Fore.YELLOW + "\n[*] WhatWeb...")
        subprocess.run(["whatweb", url], capture_output=False)

        print(Fore.YELLOW + "\n[*] Feroxbuster...")
        subprocess.run([
            "feroxbuster", "-u", url,
            "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "--insecure", "--no-recursion", "-q"
        ])

        if domain:
            print(Fore.YELLOW + f"\n[*] Vhost fuzzing sur {domain}...")
            subprocess.run([
                "ffuf",
                "-u", f"{url}",
                "-H", f"Host: FUZZ.{domain}",
                "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                "-ac", "-t", "100", "-mc", "200,301,302,403"
            ])

# ============================================================
# MAIN
# ============================================================

def main():
    args = parse_args()
    ip = args.ip
    user_domain = args.u

    check_root()

    xml_file = run_nmap(ip)
    open_ports = parse_xml(xml_file)

    display_summary(open_ports, ip)
    suggest_next(open_ports, ip)

    # Domaine : depuis arg ou depuis nmap
    detected_domains = extract_domain(xml_file)
    if user_domain:
        detected_domains.append(user_domain)
    detected_domains = list(set(detected_domains))

    if detected_domains:
        print(Fore.CYAN + f"\n[*] Domaines detectes : {', '.join(detected_domains)}")
        update_hosts(ip, detected_domains)

    domain = detected_domains[0] if detected_domains else None
    run_web_checks(ip, open_ports, domain)

if __name__ == "__main__":
    main()
