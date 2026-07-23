# sk-scan

Scanner TCP recon fait maison, oriente **opsec** et **CTF**, en pur TCP connect
(aucun privilege, aucune dependance externe, stdlib uniquement).

## En une ligne

```bash
sk-scan 10.10.10.10 --top 100 -b               # CTF, rapide
sk-scan 10.10.10.10 -p 22,80,443 --timing paranoid --tor   # opsec furtif
```

## Pourquoi un autre scanner

- **Aucun privilege** : TCP connect pur, marche la ou nmap (SYN, raw sockets)
  est bloque (sandbox, no-sudo, containers).
- **Mode Tor fiable** : SOCKS5 code main, **pas de repli silencieux en direct**
  (contrairement a `nmap --proxies` qui peut fuiter quand le proxy tombe).
- **Moins bruyant par defaut** : ordre des ports randomise, pas de banner
  grabbing par defaut, rate limiting, presets de timing.
- **Sans dependance** : un seul fichier Python, stdlib uniquement. Portable.

## Usage

```bash
sk-scan [options] cible [cible ...]
```

Voir le man complet :

```bash
man sk-scan
```

## Installation

```bash
chmod +x sk_scan.py
ln -sf "$PWD/sk_scan.py" ~/.local/bin/sk-scan
mkdir -p ~/.local/share/man/man1
cp sk-scan.1 ~/.local/share/man/man1/ && gzip -9 ~/.local/share/man/man1/sk-scan.1
```

`~/.local/bin` et `~/.local/share/man` sont sur le PATH/MANPATH par defaut sur
Kali/Debian.

## Cibles acceptees

IP, hostname, CIDR (`10.10.10.0/24`), range (`10.10.10.1-50`), fichier (`-iL`).

## Sorties

`human` (defaut), `json`, `csv` (avec en-tete), `grep` (tabule). Le resume
`[done]` va sur stderr pour permettre `sk-scan ... -o json | jq ...`.

## Limites (volontaires)

- TCP uniquement (pas d'UDP, pas d'ICMP, pas de host discovery reseau).
- Pas de detection de version/OS approfondie (banner grabbing leger seulement).
- Aucune fonctionnalite destructive.

## Licence

MIT. Pour tests autorises uniquement (pentests declares, CTF, labs, bug bounty
dans le scope).