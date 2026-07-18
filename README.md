# sk-security-toolkit

Collection d'outils sécurité faits maison : recon passive, énumération
privesc, reporting, cracking. Chaque outil est dans son propre sous-dossier
avec son `README.md`.

## Outils

| #  | Outil | Rôle | Langage |
|----|-------|------|---------|
| 01 | [sk-enumpassive](01-sk-enumpassive/) | Recon passive 100 %, bypass Cloudflare, reverse IP | Bash |
| 02 | [privesc-enum](02-privesc-enum/) | Énumérateur d'escalade de privilèges Linux | Bash |
| 03 | [sk-recon](03-sk-recon/) | Parser Nmap XML + suggestions d'attaque par service | Python |
| 04 | [sk-inject-sysreptor](04-sk-inject-sysreptor/) | Injecteur de rapport SysReptor depuis .txt formaté | Python |
| 05 | [migrate-kali](05-migrate-kali/) | Migration d'un setup Kali portable → PC | Bash |
| 06 | [crack-myth](06-crack-myth/) | Cracker PBKDF2-HMAC-SHA256 paramétrable | Python |

## Installation rapide (par outil)

Voir le `README.md` de chaque dossier pour les dépendances.
Pour les outils Python :

```bash
pip install -r 03-sk-recon/requirements.txt        # colorama
pip install -r 04-sk-inject-sysreptor/requirements.txt   # requests
```

## Sécurité

Aucun secret / clé API / token n'est versionné.
- Clés API (VirusTotal, Shodan, etc.) chargées depuis l'environnement
  ou un fichier dédié **hors git**.
- Le token SysReptor est lu depuis `SYSREPTOR_TOKEN`.

## Licence

MIT — voir `LICENSE` (à ajouter).