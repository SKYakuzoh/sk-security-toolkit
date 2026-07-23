# sk-torshell

Terminal **full-Tor** : un script bash qui met en place un shell ou TOUT le
trafic de la machine passe par Tor, au niveau noyau (iptables), sans fuite.

## En une ligne

```bash
sudo sk-torshell          # demarre le terminal full-Tor
tor-check                  # dans le shell : verifie qu'on sort par Tor
tor-exit                   # quitte et restore le reseau normal
```

## Principe

`sk-torshell` lance une instance Tor **dediee** (elle ne touche pas au tor
systeme ni a `/etc/tor/torrc`, DataDirectory dans `/tmp`, ports 9150/9040/5353).
Puis elle applique des regles iptables qui redirigent, au niveau noyau :

- le TCP sortant vers le TransPort Tor (9040),
- le DNS (UDP/53) vers le DNSPort Tor (5353),
- et DROP tout le reste (UDP non-DNS, ICMP) ainsi que TOUT l'IPv6.

Un sous-shell user est ouvert, avec le prompt `[tor:<ip>]` et trois helpers :
`tor-check`, `tor-newcircuit`, `tor-exit`. A la sortie, un trap nettoie tout
(suppression des chaines iptables + arret du process Tor dedie). Zero residu.

## Pourquoi pas torsocks

torsocks fonctionne par `LD_PRELOAD` : il intercepte les `connect()` de la
libc. Mais les binaires Go (`nuclei`, `ffuf`, `gobuster`, `katana`...) font
leur propre resolution DNS et leurs propres sockets, ils contournent la
preload et **fuient en direct**. Le routage noyau (iptables REDIRECT vers le
TransPort) attrape TOUT, Go y compris, parce qu'il agit avant l'application.

## Pre-requis

- Linux + `root`/`sudo` (iptables au niveau noyau).
- `tor` et `iptables` installes.
- Un utilisateur dedie pour tor : `debian-tor` (Debian/Kali/Ubuntu) ou `tor`
  (Arch/Fedora/Gentoo...). Auto-detecte. Override possible :
  `sudo SK_TOR_USER=<user> sk-torshell`.
- Backend nftables ou legacy (les regles matchent par destination, pas par
  interface — voir caveats).

## Avertissement

- Tor masque ton **IP reseau**, pas ton **identite applicative**. Ne te
  connecte a aucun compte perso dans ce shell.
- Les IP de sortie Tor sont publiquement connues : la cible SAIT que c'est du
  Tor. C'est de l'anonymat reseau, pas de la furtivite.
- Pendant la session, **toute la machine** est Tor-ifiee : apt, NTP, les
  mises a jour sont bloques ou passes par Tor. Ne pas lancer en SSH distant
  vers la machine (tu perdrais ta session au moment du DROP).
- Un exit Tor peut etre en France : `loc=FR` dans une reponse ne prouve pas
  une fuite. La vraie verif est `IsTor:true`.

## Caveats techniques

- **Backend nftables** : sur Kali recent, iptables utilise `nf_tables`. Le
  filter matche le loopback par destination (`-d 127.0.0.0/8`), pas par
  interface (`-o lo`) : apres un REDIRECT vers 127.0.0.1, le paquet n'est pas
  vu comme `-o lo`, et `-o lo -j ACCEPT` le laisserait tomber dans le DROP.
  C'est le piege qui rendait le TransPort inactif tant qu'il n'etait pas fixe.
- TCP et DNS uniquement. Pas d'UDP applicatif (pas de NTP, pas de certains
  jeux/voix), pas d'ICMP. C'est volontaire (anti-fuite).
- Tor ne fait pas de NAT : les connexions entrantes (serveur local expose)
  sont impossibles dans ce shell, par conception.
- Les ports 9150/9040/5353 doivent etre libres. Si l'un est pris, le script
  le detecte (`Address already in use`) et s'arrete proprement.

## Installation

```bash
chmod +x sk-torshell.sh
ln -sf "$PWD/sk-torshell.sh" ~/.local/bin/sk-torshell
```

`~/.local/bin` est sur le PATH par defaut sur Kali/Debian. Verifie :
`sk-torshell --help` (marche sans root).

## Aide

```bash
sk-torshell --help      # aide detaillee
sk-torshell --version    # version
```

## Licence

MIT. Pour tests autorises uniquement (pentests declares, CTF, labs, bug
bounty dans le scope).