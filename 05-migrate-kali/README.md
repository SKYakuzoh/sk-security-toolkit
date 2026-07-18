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

```bash
# SOURCE_HOST est obligatoire ; SOURCE_USER / LOCAL_USER ont ${USER} par défaut
SOURCE_HOST=192.168.1.42 ./migrate_kali.sh

# ou tout spécifier
SOURCE_USER=bob SOURCE_HOST=192.168.1.42 LOCAL_USER=bob ./migrate_kali.sh
```

## Étapes

- 0/4 : vérification de l'UID (local vs source)
- 1/4 : copie de `/home/<user>` (`rsync -aAXHv`)
- 2/4+ : suite de la migration (voir script)

## Licence

MIT