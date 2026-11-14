#!/bin/bash
# Exécuté dans le système installé (image mkosi ou ISO) après installation des paquets.
set -euo pipefail
install -m 644 /usr/share/barbacane/usbsas-config.toml /etc/usbsas/config.toml
install -m 644 /usr/share/barbacane/nftables.conf /etc/nftables.conf
systemctl enable nftables.service
systemctl disable clamav-freshclam.service 2>/dev/null || true
for s in networking NetworkManager systemd-networkd systemd-resolved wpa_supplicant ssh; do
    systemctl mask "$s.service" 2>/dev/null || true
done
# Jamais d'Internet : ni synchro NTP ni tâches apt périodiques
systemctl mask systemd-timesyncd.service apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
if [ -n "${BARBACANE_PIN:-}" ]; then
    echo "$BARBACANE_PIN" | barbacane-admind --set-pin
fi
passwd -l root >/dev/null
chown -R clamav:clamav /var/lib/clamav 2>/dev/null || true
if command -v update-grub >/dev/null; then
    # GRUB verrouillé : sans mot de passe, Échap au démarrage permet d'éditer la ligne du noyau
    # (init=/bin/sh…) avec un simple clavier, donc un shell root sans PIN. Mot de passe
    # aléatoire jamais conservé : personne ne peut éditer ; l'entrée par défaut démarre seule.
    if [ ! -f /etc/grub.d/01_barbacane ] && command -v grub-mkpasswd-pbkdf2 >/dev/null; then
        mdp=$(head -c 32 /dev/urandom | base64)
        hache=$(printf '%s\n%s\n' "$mdp" "$mdp" | grub-mkpasswd-pbkdf2 | awk '/grub\.pbkdf2/ { print $NF }')
        unset mdp
        [ -n "$hache" ] || { echo "ÉCHEC : hachage du mot de passe GRUB" >&2; exit 1; }
        printf '#!/bin/sh\ncat <<FIN\nset superusers="barbacane"\npassword_pbkdf2 barbacane %s\nFIN\n' "$hache" \
            > /etc/grub.d/01_barbacane
        chmod 700 /etc/grub.d/01_barbacane
        # Entrées Debian démarrables sans mot de passe (pas éditables) ; résiste aux mises à jour de grub
        if [ ! -e /etc/grub.d/10_linux.debian ]; then
            dpkg-divert --quiet --local --rename --divert /etc/grub.d/10_linux.debian --add /etc/grub.d/10_linux
            chmod -x /etc/grub.d/10_linux.debian
        fi
        printf '#!/bin/sh\n# Barbacane : entrées Debian « --unrestricted » (démarrage sans mot de passe, édition protégée)\n/bin/sh /etc/grub.d/10_linux.debian "$@" | sed "s/^\\([[:space:]]*\\)menuentry /\\1menuentry --unrestricted /"\n' \
            > /etc/grub.d/10_linux
        chmod 755 /etc/grub.d/10_linux
    fi
    update-grub
fi
[ -f /etc/barbacane/maj.pub ] || echo "ATTENTION : /etc/barbacane/maj.pub absent : mises à jour impossibles" >&2
