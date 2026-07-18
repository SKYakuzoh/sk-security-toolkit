#!/usr/bin/env bash
# ============================================================
#  Linux Privilege Escalation Enumerator
#  Usage: bash privesc_enum.sh [--full] [--output FILE]
# ============================================================

FULL=0
OUTFILE=""

for arg in "$@"; do
    case "$arg" in
        --full)   FULL=1 ;;
        --output) shift; OUTFILE="$1" ;;
        --output=*) OUTFILE="${arg#*=}" ;;
    esac
done

# ── colours ──────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

out() { echo -e "$*"; }
title()  { out "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; out "${BOLD}${CYAN}  $1${NC}"; out "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }
hit()    { out "  ${RED}[!] $*${NC}"; }
info()   { out "  ${GREEN}[+] $*${NC}"; }
warn()   { out "  ${YELLOW}[-] $*${NC}"; }
run()    { result=$(eval "$1" 2>/dev/null); [ -n "$result" ] && out "$result"; }

# Redirect to file if requested
[ -n "$OUTFILE" ] && exec > >(tee -a "$OUTFILE") 2>&1

out "${BOLD}${GREEN}"
out "  ██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗"
out "  ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝"
out "  ██████╔╝██████╔╝██║██║   ██║█████╗  ███████╗██║"
out "  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║██║"
out "  ██║     ██║  ██║██║ ╚████╔╝ ███████╗███████║╚██████╗"
out "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝  ENUM"
out "${NC}"
out "  Linux PrivEsc Enumerator | $(date '+%Y-%m-%d %H:%M:%S')"
out "  User: $(id) | Host: $(hostname)"

# ─────────────────────────────────────────────────────────────
title "1. SYSTEM INFO"
# ─────────────────────────────────────────────────────────────
info "OS / Kernel"
run "uname -a"
run "cat /etc/os-release 2>/dev/null || cat /etc/issue"

info "CPU architecture"
run "uname -m"

info "Environment variables"
run "env | grep -iE 'pass|pwd|secret|key|token|api|db|sql|user|cred'"

# ─────────────────────────────────────────────────────────────
title "2. CURRENT USER & GROUPS"
# ─────────────────────────────────────────────────────────────
run "id"
run "groups"
run "who"
run "last | head -20"

info "All users with shell"
run "grep -E '/bin/(ba)?sh|/bin/zsh|/bin/fish' /etc/passwd"

info "Users with UID 0 (root-level)"
run "awk -F: '\$3==0{print \$1}' /etc/passwd"

# ─────────────────────────────────────────────────────────────
title "3. SUDO"
# ─────────────────────────────────────────────────────────────
info "sudo -l output"
run "sudo -l 2>/dev/null"

info "/etc/sudoers snippets (if readable)"
run "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'"
run "cat /etc/sudoers.d/* 2>/dev/null | grep -v '^#' | grep -v '^$'"

# Check for interesting sudo entries
SUDO_L=$(sudo -l 2>/dev/null)
for bin in nmap vim vi nano less more awk sed python python3 perl ruby lua bash sh env find wget curl tee cp chmod chown dd tar zip unzip git strace gdb man ftp socat nc netcat docker lxc kubectl; do
    echo "$SUDO_L" | grep -qi "$bin" && hit "sudo access to: $bin  →  check GTFOBins!"
done

# ─────────────────────────────────────────────────────────────
title "4. CRON JOBS"
# ─────────────────────────────────────────────────────────────
info "System-wide crontabs"
for f in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [ -f "$f" ] && { info "  $f"; run "cat '$f'"; }
done

info "User crontabs under /var/spool/cron"
run "ls -la /var/spool/cron/crontabs/ 2>/dev/null"
run "cat /var/spool/cron/crontabs/* 2>/dev/null"

info "Anacron jobs"
run "cat /etc/anacrontab 2>/dev/null"

info "systemd timers"
run "systemctl list-timers --all 2>/dev/null"

# Scripts referenced in crons that are world-writable
info "Writable scripts referenced in cron"
grep -hEo '[^ ]+\.(sh|py|pl|rb)' /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null | sort -u | while read -r f; do
    [ -w "$f" ] && hit "WRITABLE cron script: $f"
done

# ─────────────────────────────────────────────────────────────
title "5. SUID / SGID BINARIES"
# ─────────────────────────────────────────────────────────────
info "SUID files"
SUID=$(find / -perm -4000 -type f 2>/dev/null | sort)
out "$SUID"

info "SGID files"
SGID=$(find / -perm -2000 -type f 2>/dev/null | sort)
out "$SGID"

# Cross-reference with GTFOBins-known binaries
GTFO="bash sh nmap vim vi nano python python3 perl ruby lua awk find cp mv tee env less more man ftp curl wget nohup strace gdb xxd base64 dd tar zip tclsh expect php node node.js socat nc netcat"
info "SUID/SGID matches against known GTFOBins"
for bin in $GTFO; do
    echo "$SUID $SGID" | grep -q "/$bin$" && hit "GTFOBins SUID/SGID: $bin"
done

# ─────────────────────────────────────────────────────────────
title "6. CAPABILITIES"
# ─────────────────────────────────────────────────────────────
info "Files with Linux capabilities"
run "getcap -r / 2>/dev/null"
CAPS=$(getcap -r / 2>/dev/null)
echo "$CAPS" | grep -qE 'cap_setuid|cap_net_raw|cap_dac_read_search|cap_sys_admin' && \
    hit "Dangerous capability found — check GTFOBins!"

# ─────────────────────────────────────────────────────────────
title "7. WRITABLE DIRECTORIES & FILES"
# ─────────────────────────────────────────────────────────────
info "World-writable directories (excl. /proc /sys /dev)"
run "find / -writable -type d ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null | sort"

info "World-writable files owned by root"
run "find / -writable -type f -user root ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -40"

info "/etc/passwd writable?"
[ -w /etc/passwd ] && hit "/etc/passwd is WRITABLE — you can add a root user!" || warn "/etc/passwd not writable"

info "/etc/shadow readable?"
[ -r /etc/shadow ] && hit "/etc/shadow is READABLE — dump hashes!" || warn "/etc/shadow not readable"

info "Writable PATH directories"
echo "$PATH" | tr ':' '\n' | while read -r d; do
    [ -w "$d" ] && hit "Writable PATH dir: $d  →  PATH hijacking possible"
done

# ─────────────────────────────────────────────────────────────
title "8. DATABASES"
# ─────────────────────────────────────────────────────────────

# MySQL / MariaDB
info "MySQL / MariaDB"
if command -v mysql &>/dev/null; then
    info "Trying unauthenticated root login"
    mysql -u root --password='' -e "SHOW DATABASES;" 2>/dev/null && hit "MySQL root login with empty password!"
    mysql -u root -proot -e "SHOW DATABASES;" 2>/dev/null && hit "MySQL root:root works!"
fi

info "MySQL config files (credentials)"
for f in /etc/mysql/my.cnf /etc/my.cnf ~/.my.cnf /var/lib/mysql/my.cnf /etc/mysql/debian.cnf; do
    [ -r "$f" ] && { hit "Readable: $f"; run "grep -iE 'pass|user|socket' '$f'"; }
done

info "MySQL data directory"
run "ls -la /var/lib/mysql/ 2>/dev/null"

# PostgreSQL
info "PostgreSQL"
if command -v psql &>/dev/null; then
    PGPASS=$(psql -U postgres -c '\l' 2>/dev/null)
    [ -n "$PGPASS" ] && hit "PostgreSQL accessible as current user without password" && out "$PGPASS"
fi
run "ls -la /etc/postgresql/ 2>/dev/null"
for f in /etc/postgresql/*/main/pg_hba.conf; do
    [ -r "$f" ] && { hit "Readable pg_hba.conf: $f"; run "cat '$f'"; }
done

# SQLite
info "SQLite databases on disk"
run "find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null | grep -v '/proc' | head -30"

# MongoDB
info "MongoDB"
if command -v mongo &>/dev/null || command -v mongosh &>/dev/null; then
    BIN=$(command -v mongosh 2>/dev/null || command -v mongo)
    OUT=$($BIN --quiet --eval "db.adminCommand({listDatabases:1})" 2>/dev/null)
    [ -n "$OUT" ] && hit "MongoDB accessible without auth!" && out "$OUT"
fi
run "ls -la /var/lib/mongodb/ 2>/dev/null"

# Redis
info "Redis"
if command -v redis-cli &>/dev/null; then
    REDIS=$(redis-cli ping 2>/dev/null)
    [ "$REDIS" = "PONG" ] && hit "Redis running without auth (ping OK)!"
fi

# Config files with DB credentials
info "Config files leaking DB credentials"
find /var/www /srv /opt /home /etc /root 2>/dev/null -maxdepth 6 \
    \( -name "*.conf" -o -name "*.config" -o -name "*.env" -o -name "*.php" \
       -o -name "wp-config.php" -o -name "settings.py" -o -name "database.yml" \
       -o -name "*.xml" -o -name ".env" \) 2>/dev/null | while read -r f; do
    [ -r "$f" ] && grep -qiE 'password|passwd|DB_PASS|DB_USER|DB_HOST|mysqli|PDO|connectionstring' "$f" 2>/dev/null && \
        { hit "Possible creds in: $f"; grep -iE 'password|passwd|DB_PASS|DB_USER|DB_HOST' "$f" 2>/dev/null | head -5; }
done

# ─────────────────────────────────────────────────────────────
title "9. NETWORK"
# ─────────────────────────────────────────────────────────────
info "Listening ports (internal)"
run "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"

info "Hosts file"
run "cat /etc/hosts"

info "NFS exports (no_root_squash?)"
run "cat /etc/exports 2>/dev/null"
grep -q 'no_root_squash' /etc/exports 2>/dev/null && hit "NFS no_root_squash found!"

info "ARP / routing"
run "arp -a 2>/dev/null"
run "ip route 2>/dev/null || route -n 2>/dev/null"

# ─────────────────────────────────────────────────────────────
title "10. RUNNING PROCESSES"
# ─────────────────────────────────────────────────────────────
info "Processes running as root"
run "ps aux 2>/dev/null | awk 'NR==1 || \$1==\"root\"'"

info "Interesting processes"
run "ps aux 2>/dev/null | grep -iE 'mysql|postgres|redis|mongo|memcache|docker|k8s|kubectl|vault|jenkins|tomcat|apache|nginx|php'"

# ─────────────────────────────────────────────────────────────
title "11. DOCKER / CONTAINERS"
# ─────────────────────────────────────────────────────────────
info "Docker socket"
[ -S /var/run/docker.sock ] && hit "/var/run/docker.sock exists — mount host filesystem via container!"
run "ls -la /var/run/docker.sock 2>/dev/null"

info "Current user in docker group?"
id | grep -q docker && hit "User is in docker group — escalate via 'docker run -v /:/mnt ...'"

info "Docker images/containers"
run "docker ps -a 2>/dev/null"
run "docker images 2>/dev/null"

info "LXC / LXD"
id | grep -q lxd && hit "User is in lxd group — LXD privesc possible!"
run "lxc list 2>/dev/null"

info "Inside a container?"
[ -f /.dockerenv ] && warn "Running inside a Docker container"
run "cat /proc/1/cgroup 2>/dev/null | grep -iE 'docker|lxc'"

# ─────────────────────────────────────────────────────────────
title "12. SSH"
# ─────────────────────────────────────────────────────────────
info "SSH keys"
find /home /root 2>/dev/null -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' 2>/dev/null | while read -r k; do
    [ -r "$k" ] && hit "Readable private key: $k"
done

info "authorized_keys files"
run "find /home /root -name 'authorized_keys' 2>/dev/null -exec ls -la {} \;"

info "SSH config"
run "cat /etc/ssh/sshd_config 2>/dev/null | grep -vE '^#|^$'"

# ─────────────────────────────────────────────────────────────
title "13. INTERESTING FILES & CREDENTIALS"
# ─────────────────────────────────────────────────────────────
info "History files"
for f in ~/.bash_history ~/.zsh_history ~/.sh_history ~/.python_history ~/.mysql_history ~/.psql_history; do
    [ -r "$f" ] && { hit "Readable history: $f"; run "grep -iE 'pass|sudo|ssh|mysql|psql|secret|token|key' '$f' | tail -20"; }
done

info "Password-like strings in /tmp and /var/tmp"
run "grep -riE 'password|passwd|secret' /tmp /var/tmp 2>/dev/null | head -20"

info "Recently modified files (last 10 min)"
run "find / -newer /tmp -type f ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20"

info "Backup / config files with passwords"
find / -maxdepth 8 \( -name '*.bak' -o -name '*.backup' -o -name '*.old' -o -name '*.orig' \) 2>/dev/null | while read -r f; do
    [ -r "$f" ] && grep -qiE 'pass|secret|token' "$f" 2>/dev/null && hit "Credentials in backup: $f"
done

info "SSHD private keys"
run "ls -la /etc/ssh/ssh_host_*key 2>/dev/null"

# ─────────────────────────────────────────────────────────────
title "14. PATH HIJACKING & LD_PRELOAD"
# ─────────────────────────────────────────────────────────────
info "LD_PRELOAD in sudo env_keep?"
sudo -l 2>/dev/null | grep -q 'LD_PRELOAD' && hit "LD_PRELOAD preserved by sudo — code execution as root possible!"
sudo -l 2>/dev/null | grep -q 'LD_LIBRARY_PATH' && hit "LD_LIBRARY_PATH preserved by sudo!"

info "Current PATH"
out "  $PATH"

# ─────────────────────────────────────────────────────────────
title "15. WEAK FILE PERMISSIONS"
# ─────────────────────────────────────────────────────────────
info "Checking critical file permissions"
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/hosts /etc/crontab /root/.ssh/authorized_keys; do
    [ -e "$f" ] && ls -la "$f" 2>/dev/null
done

info "Files owned by current user in /etc"
run "find /etc -user $(whoami) 2>/dev/null | head -20"

# ─────────────────────────────────────────────────────────────
title "16. INSTALLED SOFTWARE"
# ─────────────────────────────────────────────────────────────
info "Useful binaries available"
for bin in gcc g++ make python python3 perl ruby php node wget curl socat nc netcat ncat nmap git strace ltrace gdb tmux screen vi vim nano; do
    command -v $bin &>/dev/null && info "  $bin → $(command -v $bin)"
done

if [ "$FULL" -eq 1 ]; then
    info "Full package list"
    run "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null"
fi

# ─────────────────────────────────────────────────────────────
title "17. KERNEL EXPLOITS (version check)"
# ─────────────────────────────────────────────────────────────
KVER=$(uname -r)
info "Kernel: $KVER"
warn "Run 'linux-exploit-suggester' or 'linux-smart-enumeration' for automated kernel CVE matching"

# ─────────────────────────────────────────────────────────────
title "18. INTERESTING VARS & SCRIPTS"
# ─────────────────────────────────────────────────────────────
info "Checking for readable /root"
run "ls -la /root/ 2>/dev/null"

info "Writable /etc/profile.d or /etc/bash*"
for f in /etc/profile /etc/profile.d /etc/bash.bashrc /etc/environment; do
    [ -w "$f" ] && hit "Writable init script: $f  →  persistence / privesc!"
done

# ─────────────────────────────────────────────────────────────
out "\n${BOLD}${GREEN}[*] Enumeration complete.${NC}"
[ -n "$OUTFILE" ] && out "${BOLD}[*] Results saved to: $OUTFILE${NC}"
out ""
