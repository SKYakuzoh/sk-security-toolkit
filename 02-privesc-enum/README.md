# privesc_enum.sh

**Énumérateur de vecteurs d'escalade de privilèges Linux.**

À **lancer sur la machine que tu veux auditer** (le host cible / une box
CTF / le shell que tu as obtenu), pas depuis ton poste. Collecte rapidement
les artefacts système pertinents pour identifier un chemin de privesc :
SUID, capabilities, cron, services, kernel, montages, historiques,
binaires intéressants, configs qui fuient des creds, etc.

## Usage

```bash
bash privesc_enum.sh
bash privesc_enum.sh --full            # énumération exhaustive (plus lent)
bash privesc_enum.sh --output result.txt   # sauvegarde aussi dans result.txt
```

## Dépendances

- Bash pur, outils standards Linux (aucune dépendance externe).

## Licence

MIT