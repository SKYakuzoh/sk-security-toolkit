# migrate_kali.sh

**Migration d'un setup Kali « portable » vers un PC cible.**

À lancer depuis le **PC de destination**, avec SSH déjà actif sur le
portable source. Vérifie la concordance des UID puis copie le `/home`
via `rsync` en préservant permissions, xattrs et hardlinks.

## Pré-requis

- SSH actif sur la source
- `rsync`, `sudo` côté destination
- UID identique sur les deux machines (le script vérifie et aborte sinon)

## Usage

1. Éditer `SOURCE_HOST` en haut du script (IP du portable source)
2. Lancer depuis le PC destination :

```bash
./migrate_kali.sh
```

## Étapes

- 0/4 : vérification de l'UID (local vs source)
- 1/4 : copie de `/home/<user>` (`rsync -aAXHv`)
- 2/4+ : suite de la migration (voir script)

## Licence

MIT