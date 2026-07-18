# sk_recon.py

**Recon automatisée : lance Nmap, parse les résultats et suggère, par
service détecté, les commandes d'énumération / attaque à enchaîner.**

Le script ne consomme pas un XML existant : il **lance lui-même** un scan
Nmap (top-200 ports, `-sV`), en parse la sortie XML, affiche le résumé des
ports ouverts, puis propose les commandes adaptées à chaque service.
Il extrait aussi les domaines (certificats SSL, hostnames) et les ajoute
au besoin à `/etc/hosts`, et lance des checks web sur les ports HTTP(S).

## Usage

```bash
sudo python3 sk_recon.py -ip <IP_cible> [-u <domaine>]
```

- `-ip`  : IP cible (obligatoire)
- `-u`   : domaine/URL cible (optionnel, utilisé pour les checks web)

Exemple :

```bash
sudo python3 sk_recon.py -ip 10.10.10.10 -u example.htb
```

## ⚠️ Pré-requis et effets de bord

- Doit être lancé **en root / sudo** (check au démarrage, abort sinon).
- **Nmap** installé (le script l'invoque avec `-sV --top-ports 200`).
- Sortie Nmap écrite dans `/tmp/sk_nmap_<IP>.{xml,txt}`.
- **Modifie `/etc/hosts`** : ajoute les entrées `<IP> <domaine>` détectées
  si elles n'y sont pas déjà. C'est volontaire (résolution locale pour la
  suite de l'énum), mais à savoir.
- Coloration via `colorama`.

## Dépendances

- Python 3
- `colorama`  (`pip install -r requirements.txt`)
- `nmap`

## Licence

MIT