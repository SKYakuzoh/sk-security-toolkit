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

- Bash (aucune dépendance obligatoire). Le script tourne tout seul.
- Beaucoup de checks tentent des outils optionnels (`mysql`, `psql`,
  `docker`, `nmap`, `nc`, etc.). Si un outil n'est pas installé, le check
  correspondant est **ignoré silencieusement** (pas de crash), l'outil donne
  juste moins de résultats. Avoir ces outils installés = énumération plus
  complète.
- Lecture seule : le script ne modifie rien sur la cible. Pas besoin d'être
  root, mais sans root certains fichiers (shadow, configs root) ne seront
  pas lisibles et les checks correspondants sortiront vide.

## Licence

MIT