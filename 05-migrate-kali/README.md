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

- 0/4 : vérification de l'UID (local vs source), abort si différent
- 1/4 : copie de `/home/<user>` via `rsync -aAXHv` (exclut `.cache` et la
  corbeille). **Écrase** le `/home` local par la source
- 2/4 : copie de `/root` (msf4, wordlists perso, etc.)
- 3/4 : restauration des paquets apt (`dpkg --get-selections` puis
  `dpkg --set-selections` puis `apt-get dselect-upgrade`)
- 4/4 : dump des volumes Docker de la source (tar.gz via conteneur alpine
  éphémère) puis restauration dans des volumes locaux créés à l'identique

## Effets de bord

- `rsync` écrase la destination (`/home/<user>` et `/root`).
- L'étape 3/4 installe/réinstalle des paquets, à lancer sur une machine
  de destination propre ou identique.
- L'étape 4/4 suppose Docker installé côté destination.

## Licence

MIT