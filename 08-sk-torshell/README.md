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
  interface - voir caveats).

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

## Cycle de vie (opsec)

Le point le plus important a retenir, parce que c'est contre-intuitif :

- **Demarrage** (`sudo sk-torshell`) : les regles iptables vont sur la chaine
  OUTPUT, au **niveau noyau**. C'est donc **toute la machine** qui est
  Tor-ifiee, pas seulement le shell ouvert. **Pendant la session, tu n'as
  aucun terminal "clair"** : un autre onglet/terminal fait aussi du Tor (TCP)
  ou se fait dropper (UDP/ICMP/IPv6). Ton IP reelle ne sort de nulle part.
- **Pendant** : tu es anonyme cote reseau (IP masquee). Tu ne l'es pas cote
  identite applicative (ne te connecte a aucun compte perso).
- **Sortie** (`tor-exit`, ou fermeture du sous-shell) : le trap cleanup retire
  les regles iptables et tue le tor dedie. Ta machine **revient au routage
  normal, a ton IP reelle**. Tu n'es **plus anonyme** a partir de la. Tout ce
  que tu veux faire anonyme doit se faire **avant** le `tor-exit`.
- **Piège du kill brutal** : le cleanup est un trap (EXIT/INT/TERM). Il
  s'execute dans tous les cas propres, **mais pas si le script est tue
  brutalement** (`sudo kill -9` du process, coupure electrique). Dans ce cas
  les regles iptables restent et la machine reste Tor-ifiee/cassee. Auto-guerison
  : un **reboot** (les regles iptables sont en RAM, elles disparaissent au
  reboot, le tor dedie meurt aussi), ou relancer `sudo sk-torshell` puis
  `tor-exit` proprement.

En une ligne : **lance = tout passe par Tor ; exit = retour a ton IP reelle,
plus anonyme.** L'anonymat est une session, pas un etat permanent.

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

sk-torshell a besoin de **root**, on l'installe donc dans `/usr/local/bin`
(vu par root), pas dans `~/.local/bin` (qui n'existe que pour ton user) :

```bash
sudo install -m0755 sk-torshell.sh /usr/local/bin/sk-torshell
# equivalent : sudo ln -sf "$PWD/sk-torshell.sh" /usr/local/bin/sk-torshell
```

Verifie : `sudo sk-torshell --help` (doit afficher l'aide).

**Si `sudo sk-torshell` renvoie "commande introuvable"**, c'est que ton
`secure_path` sudo n'inclut pas `/usr/local/bin` (certains durcissements
raccourcissent le secure_path a `/usr/sbin:/usr/bin:/sbin:/bin`). Deux options :

```bash
# option A (portable, marche partout) : command -v tourne dans ton shell
sudo "$(command -v sk-torshell)"

# option B : remettre /usr/local/bin dans le secure_path (drop-in reversible)
echo 'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' | sudo tee /etc/sudoers.d/00-secure-path
sudo visudo -c   # valide la syntaxe
```

## Aide

```bash
sk-torshell --help       # aide detaillee (marche sans root)
sk-torshell --version    # version
```

## Licence

MIT. Pour tests autorises uniquement (pentests declares, CTF, labs, bug
bounty dans le scope).