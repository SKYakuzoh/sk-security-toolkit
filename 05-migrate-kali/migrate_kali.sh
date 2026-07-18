#!/usr/bin/env bash
# Migration complète du setup Kali portable -> PC (Windows/Kali)
# A lancer depuis le PC (destination), avec SSH déjà actif sur le portable.
set -euo pipefail

SOURCE_USER="yaku"
SOURCE_HOST="192.168.1.XX"   # <-- mets l'IP du portable ici
SOURCE="${SOURCE_USER}@${SOURCE_HOST}"

echo "=== 0/4 : Vérification UID ==="
LOCAL_UID=$(id -u yaku)
REMOTE_UID=$(ssh "${SOURCE}" "id -u yaku")
if [ "${LOCAL_UID}" != "${REMOTE_UID}" ]; then
  echo "ATTENTION : UID différent (local=${LOCAL_UID}, portable=${REMOTE_UID})."
  echo "Corrige avec 'sudo usermod -u ${REMOTE_UID} yaku' avant de continuer, sinon les permissions seront fausses."
  exit 1
fi

echo "=== 1/4 : Copie de /home/yaku ==="
sudo rsync -aAXHv --info=progress2 \
  --exclude='.cache' \
  --exclude='.local/share/Trash' \
  "${SOURCE}:/home/yaku/" /home/yaku/

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
echo "Vérifie les permissions (chown -R yaku:yaku /home/yaku si besoin) et relance tes containers (docker compose up -d)."
