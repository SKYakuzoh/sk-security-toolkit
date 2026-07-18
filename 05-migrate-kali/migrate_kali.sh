#!/usr/bin/env bash
# Migration complète du setup Kali portable -> PC (Windows/Kali)
# A lancer depuis le PC (destination), avec SSH déjà actif sur le portable.
#
# Usage:
#   ./migrate_kali.sh                            # valeurs depuis l'env (voir ci-dessous)
#   SOURCE_USER=bob SOURCE_HOST=192.168.1.42 ./migrate_kali.sh
#
# Variables d'environnement (toutes optionnelles, valeurs par défaut entre crochets):
#   SOURCE_USER  utilisateur sur le portable source      [${USER:-yaku}]
#   SOURCE_HOST  IP/hostname du portable source          [OBLIGATOIRE]
#   LOCAL_USER   utilisateur local (PC destination)      [${USER:-yaku}]
set -euo pipefail

SOURCE_USER="${SOURCE_USER:-${USER:-yaku}}"
SOURCE_HOST="${SOURCE_HOST:?SOURCE_HOST est obligatoire (ex: SOURCE_HOST=192.168.1.42 ./migrate_kali.sh)}"
LOCAL_USER="${LOCAL_USER:-${USER:-yaku}}"
SOURCE="${SOURCE_USER}@${SOURCE_HOST}"

echo "=== 0/4 : Vérification UID ==="
LOCAL_UID=$(id -u "${LOCAL_USER}")
REMOTE_UID=$(ssh "${SOURCE}" "id -u ${SOURCE_USER}")
if [ "${LOCAL_UID}" != "${REMOTE_UID}" ]; then
  echo "ATTENTION : UID différent (local=${LOCAL_USER}=${LOCAL_UID}, portable=${SOURCE_USER}=${REMOTE_UID})."
  echo "Corrige avec 'sudo usermod -u ${REMOTE_UID} ${LOCAL_USER}' avant de continuer, sinon les permissions seront fausses."
  exit 1
fi

echo "=== 1/4 : Copie de /home/${LOCAL_USER} ==="
sudo rsync -aAXHv --info=progress2 \
  --exclude='.cache' \
  --exclude='.local/share/Trash' \
  "${SOURCE}:/home/${SOURCE_USER}/" "/home/${LOCAL_USER}/"

echo "=== 2/4 : Copie de /root (msf4, wordlists perso, etc.) ==="
sudo rsync -aAXHv --info=progress2 \
  "${SOURCE}:/root/" /root/

echo "=== 3/4 : Paquets apt installés ==="
ssh "${SOURCE}" "dpkg --get-selections" > /tmp/pkglist.txt
sudo dpkg --set-selections < /tmp/pkglist.txt
sudo apt-get update
sudo apt-get dselect-upgrade -y

echo "=== 4/4 : Volumes Docker (SysReptor et autres) ==="
for vol in $(ssh "${SOURCE}" "sudo docker volume ls -q"); do
  echo "  -> volume: ${vol}"
  ssh "${SOURCE}" "sudo docker run --rm -v ${vol}:/data -v /tmp:/backup alpine tar czf /backup/${vol}.tar.gz -C /data ."
  scp "${SOURCE}:/tmp/${vol}.tar.gz" /tmp/
  sudo docker volume create "${vol}" 2>/dev/null || true
  sudo docker run --rm -v "${vol}:/data" -v /tmp:/backup alpine tar xzf "/backup/${vol}.tar.gz" -C /data
done

echo "=== Terminé ==="
echo "Vérifie les permissions (chown -R ${LOCAL_USER}:${LOCAL_USER} /home/${LOCAL_USER} si besoin) et relance tes containers (docker compose up -d)."
