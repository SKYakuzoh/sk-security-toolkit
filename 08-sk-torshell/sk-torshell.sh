#!/usr/bin/env bash
# sk-torshell (transparent proxy, instance dediee) :
# route TOUT le trafic de la machine via Tor, au niveau noyau (iptables).
#
# Approche : on lance une instance Tor DEDIEE (processus separe, DataDirectory
# /tmp, ports 9150/9040/5353) en tant que debian-tor. On ne touche PAS au tor
# systeme ni a /etc/tor/torrc. Le nettoyage = tuer le process dedie + flusher
# iptables. Pas de residu.
#
# Le routage noyau (iptables REDIRECT vers TransPort 9040 / DNSPort 5353)
# intercepte TOUT, y compris les binaires Go (nuclei, ffuf, httpx) qui
# contournent torsocks. filter DROP empeche les fuites UDP/ICMP/IPv6.
#
# IMPORTANT : pendant la session, toute la machine est Tor-ifiee. apt/NTP/etc.
# = bloques ou Tor-ifies. Ne pas lancer en SSH distant vers la machine.
#
# Pour tests autorises uniquement.

set -euo pipefail

VERSION="1.0.0"

TOR_SOCKS_PORT=9150        # socks de l'instance dediee (transparent proxy = via TransPort)
TOR_TRANS_PORT=9040
TOR_DNS_PORT=5353
TOR_CTRL_PORT=9151
TOR_USER=""          # auto-detecte plus bas (debian-tor sur Debian/Kali, tor ailleurs). Override: SK_TOR_USER=<user>
DD=/tmp/sk-torshell-dd
LOG=/tmp/sk-torshell.log
CHAIN_N=SK_TOR_NAT
CHAIN_F=SK_TOR_FIL
CHAIN6=SK_TOR6
DED_PID=""

c_red(){ printf '\033[31m%s\033[0m' "$*"; }
c_ylw(){ printf '\033[33m%s\033[0m' "$*"; }
c_grn(){ printf '\033[32m%s\033[0m' "$*"; }
c_dim(){ printf '\033[2m%s\033[0m' "$*"; }
log(){  printf '%s %s\n' "$(c_dim '[sk-torshell]')" "$*"; }
warn(){ printf '%s %s\n' "$(c_dim '[sk-torshell]')" "$(c_ylw "$*")"; }
err(){  printf '%s %s\n' "$(c_dim '[sk-torshell]')" "$(c_red "$*")" >&2; exit 1; }

usage(){
cat <<EOF
$(c_grn 'sk-torshell') $VERSION - terminal full-Tor (transparent proxy noyau)

$(c_dim 'USAGE')
  sudo sk-torshell            demarre le terminal full-Tor
  sk-torshell -h|--help       cette aide (pas besoin de root)
  sk-torshell -V|--version    version

$(c_dim 'INSTALL')
  Installe dans /usr/local/bin (vu par root), pas ~/.local/bin :
    sudo install -m0755 sk-torshell.sh /usr/local/bin/sk-torshell
  Si "sudo sk-torshell" n'est pas trouve, c'est que ton secure_path n'inclut
  pas /usr/local/bin (durcissement). Utilise alors :
    sudo "$(command -v sk-torshell)"   # ou le chemin absolu

$(c_dim 'PRINCIPE')
  Lance une instance Tor DEDIEE (ne touche pas au tor systeme ni a
  /etc/tor/torrc). Redirige TOUT le trafic de la machine vers Tor au niveau
  noyau (iptables) : TCP -> TransPort 9040, DNS -> DNSPort 5353. Le reste
  (UDP non-DNS, ICMP, IPv6) est DROP, zero fuite. Ouvre un sous-shell user
  avec le prompt [tor:<ip>] et les helpers tor-check / tor-newcircuit /
  tor-exit. Au exit, nettoyage integral (iptables + process dedie).

$(c_dim 'POURQUOI PAS torsocks')
  torsocks (LD_PRELOAD) intercepte les binaires libc mais PAS les binaires
  Go (nuclei, ffuf, gobuster) qui contournent la preload et fuient en direct.
  Le routage noyau attrape TOUT, y compris le Go.

$(c_dim 'AVERTISSEMENT')
  Tor masque ton IP reseau, PAS ton identite applicative. Ne te connecte a
  aucun compte perso dans ce shell. Les sorties Tor sont des IP publiquement
  connues : la cible SAIT que c'est du Tor. Ne pas lancer en SSH distant
  (toute la machine est Tor-ifiee pendant la session : apt/NTP bloques).
  Pour tests autorises uniquement (pentests declares, CTF, labs).

$(c_dim 'VOIR AUSSI')
  sk-scan(1)  -  scanner TCP recon avec mode Tor fiable
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  -V|--version) echo "sk-torshell $VERSION"; exit 0 ;;
  "") : ;;   # usage normal : on continue
  *) err "option inconnue: '$1'. Essaie: sk-torshell --help" ;;
esac

# 0) privileges
[[ $EUID -eq 0 ]] || err "doit etre lance en root : sudo sk-torshell"
[[ -n "${SUDO_USER:-}" ]] || err "lance via 'sudo sk-torshell' (SUDO_USER absent)."
ORIG_USER="$SUDO_USER"
[[ "$ORIG_USER" != "root" ]] || err "utilise 'sudo sk-torshell' (pas 'sudo -i')."
command -v tor >/dev/null 2>&1 || err "tor absent."
command -v iptables >/dev/null 2>&1 || err "iptables absent."
# utilisateur tor : override via SK_TOR_USER, sinon auto-detect (debian-tor
# sur Debian/Kali/Ubuntu, tor sur Arch/Fedora/Gentoo...).
TOR_USER="${SK_TOR_USER:-}"
if [[ -z "$TOR_USER" ]]; then
    for cand in debian-tor tor; do
        getent passwd "$cand" >/dev/null 2>&1 && { TOR_USER="$cand"; break; }
    done
fi
[[ -n "$TOR_USER" ]] || err "utilisateur tor introuvable (essaie: sudo SK_TOR_USER=<user> sk-torshell)."
TOR_UID=$(id -u "$TOR_USER")

cleanup() {
    log "nettoyage..."
    iptables -t nat -D OUTPUT -j "$CHAIN_N" 2>/dev/null || true
    iptables -t nat -F "$CHAIN_N" 2>/dev/null || true
    iptables -t nat -X "$CHAIN_N" 2>/dev/null || true
    iptables -D OUTPUT -j "$CHAIN_F" 2>/dev/null || true
    iptables -F "$CHAIN_F" 2>/dev/null || true
    iptables -X "$CHAIN_F" 2>/dev/null || true
    ip6tables -D OUTPUT -j "$CHAIN6" 2>/dev/null || true
    ip6tables -F "$CHAIN6" 2>/dev/null || true
    ip6tables -X "$CHAIN6" 2>/dev/null || true
    # tuer l'instance dediee (uniquement, via son DataDirectory unique)
    pkill -u "$TOR_USER" -f "sk-torshell-dd" 2>/dev/null || true
    log "nettoyage termine. trafic normal restaure."
}
trap cleanup EXIT INT TERM

# 1) instance tor dediee
log "demarrage instance Tor dediee (datadir $DD)..."
mkdir -p "$DD"
chown "$TOR_USER":"$TOR_USER" "$DD"
rm -f "$LOG"
# le log est ouvert par le shell (root) -> tor herite du fd, pas de check de perms
sudo -u "$TOR_USER" tor \
    --Log "notice stdout" \
    --SocksPort "127.0.0.1:${TOR_SOCKS_PORT}" \
    --TransPort "127.0.0.1:${TOR_TRANS_PORT}" \
    --DNSPort "127.0.0.1:${TOR_DNS_PORT}" \
    --AutomapHostsOnResolve 1 \
    --VirtualAddrNetwork 10.192.0.0/10 \
    --ControlPort "127.0.0.1:${TOR_CTRL_PORT}" \
    --DataDirectory "$DD" \
    >"$LOG" 2>&1 &
disown 2>/dev/null || true

# 2) attendre bootstrap via le log (fiable, sans dependre d'un site externe)
log "attente bootstrap Tor (jusqu'a 150s)..."
ok=0
for i in $(seq 1 150); do
    if grep -q "Bootstrapped 100%" "$LOG" 2>/dev/null; then ok=1; break; fi
    if grep -qiE "\[err\]|\\bfatal\\b|Could not bind|Address already in use" "$LOG" 2>/dev/null; then
        err "tor dedie a echoue. Logs: $LOG (voir aussi: ports deja pris ?)"
    fi
    sleep 1
done
[[ $ok -eq 1 ]] || err "bootstrap Tor trop long (>150s). Logs: $LOG"

EXIT_IP="$(curl --socks5-hostname "127.0.0.1:${TOR_SOCKS_PORT}" -s --max-time 10 \
    https://check.torproject.org/api/ip 2>/dev/null | sed -n 's/.*"IP":"\([^"]*\)".*/\1/p')"
[[ -n "$EXIT_IP" ]] || EXIT_IP="inconnu"
log "Tor pret. sortie: $(c_grn "$EXIT_IP")"

# 3) iptables : redirection (nat) + drop des fuites (filter)
#
# NOTE importante (backend nftables) : on matche le loopback par DESTINATION
# (-d 127.0.0.0/8) et NON par interface (-o lo). Sur Kali recent, iptables
# utilise le backend nf_tables ; or apres un REDIRECT vers 127.0.0.1:9040, le
# paquet n'est PAS vu comme -o lo par le chain filter OUTPUT (le rerouting ne
# change pas l'interface de sortie vue par -o). Resultat : les paquets
# rediriges tombent dans le DROP et le TransPort ne route rien. Matcher -d
# 127.0.0.0/8 resout le probleme (teste : libc ET Go routent via Tor).
log "application iptables (uid tor=$TOR_UID)..."
# nat : tor sort direct ; DNS (y.c. 127.0.0.53 systemd-resolved) -> tor ;
# reste loopback tranquille ; TCP syn -> TransPort.
iptables -t nat -N "$CHAIN_N" 2>/dev/null || iptables -t nat -F "$CHAIN_N"
iptables -t nat -A "$CHAIN_N" -m owner --uid-owner "$TOR_UID" -j RETURN
iptables -t nat -A "$CHAIN_N" -p udp --dport 53 -j REDIRECT --to-ports "$TOR_DNS_PORT"
iptables -t nat -A "$CHAIN_N" -d 127.0.0.0/8 -j RETURN
iptables -t nat -A "$CHAIN_N" -p tcp --syn -j REDIRECT --to-ports "$TOR_TRANS_PORT"
iptables -t nat -A OUTPUT -j "$CHAIN_N"

# filter : established ; tor sort direct ; loopback (y.c. paquets rediriges) ;
# le reste DROP (anti-fuite UDP/ICMP/IPv4-direct).
iptables -N "$CHAIN_F" 2>/dev/null || iptables -F "$CHAIN_F"
iptables -A "$CHAIN_F" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A "$CHAIN_F" -m owner --uid-owner "$TOR_UID" -j ACCEPT
iptables -A "$CHAIN_F" -d 127.0.0.0/8 -j ACCEPT
iptables -A "$CHAIN_F" -j DROP
iptables -A OUTPUT -j "$CHAIN_F"

# ipv6 : on bloque TOUT sauf le loopback local (anti-fuite IPv6).
ip6tables -N "$CHAIN6" 2>/dev/null || ip6tables -F "$CHAIN6"
ip6tables -A "$CHAIN6" -d ::1/128 -j RETURN
ip6tables -A "$CHAIN6" -j DROP
ip6tables -A OUTPUT -j "$CHAIN6"
log "iptables actives."

# 4) verification que le routage noyau fonctionne (un curl root -> Tor).
# On garde le verdict pour l'afficher DANS le banner (sinon le clear l'efface).
log "verification routage..."
v_json="$(curl -s --max-time 15 https://check.torproject.org/api/ip 2>/dev/null)"
v_ip="$(printf '%s' "$v_json" | sed -n 's/.*"IP":"\([^"]*\)".*/\1/p')"
v_istor="$(printf '%s' "$v_json" | sed -n 's/.*"IsTor":\([^,}]*\).*/\1/p')"
if [[ "$v_istor" == "true" ]]; then
    ROUTAGE_VERDICT="$(c_grn 'OK') : le trafic sort par Tor ($v_ip)"
else
    ROUTAGE_VERDICT="$(c_ylw 'INCERTAIN') (IsTor='${v_istor:-?}' ip='${v_ip:-?}')"
    warn "verification incertaine - le routage peut etre partiel. Verifie: tor-check"
fi

# 5) sous-shell utilisateur
RC=$(mktemp)
chmod 644 "$RC"          # lisible par l'user (cree par root, lu par $ORIG_USER)
cat > "$RC" <<EOF
export SK_TORSHELL=1
export SK_TOR_EXIT_IP="$EXIT_IP"
export PS1='\[\033[36m\][tor:'"$EXIT_IP"']\[\033[0m\] \u@\h \w\$ '
tor-check(){ curl -s https://check.torproject.org/api/ip; echo; }
tor-newcircuit(){ (echo -e "AUTHENTICATE \"\"\nSIGNAL NEWNYM\nQUIT" | nc 127.0.0.1 $TOR_CTRL_PORT 2>/dev/null) && echo "nouveau circuit demande" || echo "echec control port"; }
tor-exit(){ exit; }
EOF

clear || true
cat <<BANNER
$(c_dim '================================================================')
 $(c_grn 'sk-torshell') $(c_dim '- transparent proxy : TOUT le trafic via Tor')
$(c_dim '================================================================')
 sortie Tor      : $(c_grn "$EXIT_IP")
 routage noyau   : $ROUTAGE_VERDICT
 utilisateur     : $ORIG_USER
 TransPort/DNSPort : 127.0.0.1:$TOR_TRANS_PORT / 127.0.0.1:$TOR_DNS_PORT
$(c_dim '----------------------------------------------------------------')
 $(c_ylw 'ROUTAGE NOYAU ACTIF')
  - iptables redirige TOUT (libc ET Go : nuclei, ffuf, httpx...) vers Tor.
  - tout le reste (UDP non-DNS, ICMP, IPv6) est DROP : zero fuite.
  - la machine entiere est Tor-ifiee pendant la session.
$(c_dim '----------------------------------------------------------------')
 $(c_ylw 'AVERTISSEMENT')
  - Tor masque ton IP reseau, PAS ton identite applicative.
  - Ne te connecte a aucun compte perso dans ce shell.
  - Les sorties Tor sont des IP connues : la cible SAIT que c'est du Tor.
$(c_dim '----------------------------------------------------------------')
 helpers : tor-check | tor-newcircuit | tor-exit
$(c_dim '================================================================')
BANNER

su -s /bin/bash "$ORIG_USER" -c "bash --rcfile '$RC' -i"
RC_RC=$?
rm -f "$RC"
exit $RC_RC