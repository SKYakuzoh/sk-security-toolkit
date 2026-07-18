# sk_recon.py

**Assistant de recon post-Nmap : parse la sortie XML et suggère des
commandes d'énumération / d'attaque par service détecté.**

## Fonctionnalités

- Lecture d'un scan Nmap au format XML (`-oX`)
- Table de correspondance `service → suggestions` (`SERVICE_HINTS`) couvrant
  ssh, ftp, http(s), smb, ldap, mssql, rpc, rdp, etc.
- Commandes suggérées : `hydra`, `netexec`, `enum4linux-ng`, `ldapsearch`,
  `feroxbuster`, `sslscan`, `whatweb`, `nikto`, `ssh-audit`…
- Sortie colorée (colorama)

## Usage

```bash
nmap -sV -oX scan.xml <cible>
python3 sk_recon.py scan.xml
```

## Dépendances

- Python 3
- `colorama`  (`pip install -r requirements.txt`)

## Licence

MIT