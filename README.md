# sk-security-toolkit

Collection d'outils sécurité faits maison, utilisés en pentest / CTF / audit
défensif : recon passive, énumération de privesc, reporting, cracking, et
migration d'environnement. Chaque outil est dans son propre sous-dossier
avec son `README.md` détaillé.

## Sommaire des outils

| #  | Outil | Rôle | Langage |
|----|-------|------|---------|
| 01 | [sk-enumpassive](01-sk-enumpassive/) | Recon passive 100 %, bypass Cloudflare, reverse IP | Bash |
| 02 | [privesc-enum](02-privesc-enum/) | Énumérateur d'escalade de privilèges Linux | Bash |
| 03 | [sk-recon](03-sk-recon/) | Parser Nmap XML + suggestions d'attaque par service | Python |
| 04 | [sk-inject-sysreptor](04-sk-inject-sysreptor/) | Injecteur de rapport SysReptor depuis .txt formaté | Python |
| 05 | [migrate-kali](05-migrate-kali/) | Migration d'un setup Kali portable → PC | Bash |
| 06 | [crack-myth](06-crack-myth/) | Cracker PBKDF2-HMAC-SHA256 paramétrable | Python |

## Description des outils

### 01 — sk-enumpassive
Recon passive **100 %** : ne contacte jamais la cible. Sous-domaines
(subfinder, crt.sh, DoH), résolution de l'origin derrière Cloudflare,
reverse IP (HackerTarget), étiquetage hébergeur/ASN (ipinfo). Sources à clé
(SecurityTrails, Censys, Shodan, VirusTotal) + sources gratuites.
Sortie : un rapport HTML autonome.
```bash
./sk-enumpassive example.com --save ./out --open
```

### 02 — privesc-enum
Énumérateur rapide de vecteurs d'escalade de privilèges Linux : SUID,
capabilities, cron, services, kernel, montages, historiques, configs
avec creds… Mode `--full` pour une énumération exhaustive.
```bash
bash privesc_enum.sh --full --output result.txt
```

### 03 — sk-recon
Lance Nmap (top-200, `-sV`), parse la sortie XML et, pour chaque service
détecté, propose les commandes d'énumération/attaque adaptées (hydra,
netexec, enum4linux-ng, ldapsearch, feroxbuster, sslscan, whatweb, nikto).
Ajoute aussi les domaines détectés à `/etc/hosts`. **Nécessite sudo.**
```bash
sudo python3 sk_recon.py -ip 10.10.10.10 -u example.htb
```

### 04 — sk-inject-sysreptor
Crée un rapport SysReptor directement à partir d'un `.txt` formaté
(blocs `=== ... ===`). La variante `sk_injectfinal.py` ajoute un nettoyage
déterministe des séparateurs LLM et la redaction des hashs/secrets à
motif reconnaissable. Token lu depuis l'environnement.
```bash
export SYSREPTOR_TOKEN=... && python3 sk_injectfinal.py rapport.txt
```

### 05 — migrate-kali
Migration d'un setup Kali « portable » vers un PC cible : vérification
de l'UID, copie du `/home` et de `/root` via `rsync`, restauration des
paquets apt et des volumes Docker. Tout est paramétrable via l'env
(`SOURCE_HOST` obligatoire).
```bash
SOURCE_HOST=192.168.1.42 ./migrate_kali.sh
```

### 06 — crack-myth
Cracker par dictionnaire pour hashs PBKDF2-HMAC-SHA256 (itérations et
dklen paramétrables, salt adaptable). Usage éducatif / CTF.
```bash
python3 crack_myth.py "<hash_b64>" /usr/share/wordlists/rockyou.txt
```

## Pré-requis par langage

| Langage | Pré-requis |
|---------|-----------|
| Bash | outils standards Linux ; `subfinder`, `curl` pour sk-enumpassive ; `nmap`+`sudo` pour sk-recon |
| Python 3 | voir les `requirements.txt` (`colorama`, `requests`) |

## Installation rapide (outils Python)

```bash
pip install -r 03-sk-recon/requirements.txt             # colorama
pip install -r 04-sk-inject-sysreptor/requirements.txt  # requests
```

## Sécurité

Aucun secret / clé API / token n'est versionné.
- Clés API (VirusTotal, Shodan, SecurityTrails, Censys) chargées depuis
  l'environnement ou un fichier dédié **hors git**
  (`~/.config/sk-enumpassive.env`).
- Le token SysReptor est lu depuis `SYSREPTOR_TOKEN`.

## Licence

MIT — voir [LICENSE](LICENSE).