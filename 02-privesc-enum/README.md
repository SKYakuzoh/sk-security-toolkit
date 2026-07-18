# privesc_enum.sh

**Énumérateur de vecteurs d'escalade de privilèges Linux.**

Collecte rapidement les artefacts système pertinents pour identifier un
chemin de privesc : SUID, capabilities, cron, services, kernel, montages,
binaires intéressants, etc.

## Usage

```bash
bash privesc_enum.sh
bash privesc_enum.sh --full            # énumération exhaustive (plus lent)
bash privesc_enum.sh --output result.txt
```

## Dépendances

- Bash pur, outils standards Linux (aucune dépendance externe).

## Licence

MIT