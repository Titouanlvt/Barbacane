#!/bin/sh
# Fin d'installation de la borne EN LIGNE (profil en-ligne seulement ; jamais dans l'ISO hors
# ligne). Lancé par le preseed APRÈS fin-installation.sh, qui a installé tous les paquets (dont
# barbacane-agent) et appliqué la configuration commune de la v1 (pare-feu fermé, services
# réseau masqués). Pose ce qui distingue la borne en ligne, préparé par build-iso.sh :
#   - configuration de l'agent et CA serveur épinglée ;
#   - pare-feu : sortie vers adresse:ports du serveur pour le seul compte barbacane-agent,
#     rien en entrée hors réponses du serveur ;
#   - réseau : systemd-networkd (déjà dans le paquet systemd), IPv4 statique ou DHCP ;
#   - restriction d'adresse du service (IPAddressAllow = serveur seul).
# L'installation elle-même reste sans réseau.
set -e
X=/cdrom/barbacane/en-ligne
T=/target
install -d -m 0755 $T/etc/barbacane/agent $T/etc/systemd/network \
    $T/etc/systemd/system/barbacane-agent.service.d
install -m 0644 $X/ca-serveur.pem $T/etc/barbacane/agent/ca-serveur.pem
install -m 0644 $X/agent.toml $T/etc/barbacane/agent.toml
install -m 0644 $X/nftables.conf $T/etc/nftables.conf
install -m 0644 $X/10-barbacane.network $T/etc/systemd/network/10-barbacane.network
install -m 0644 $X/serveur.conf $T/etc/systemd/system/barbacane-agent.service.d/serveur.conf
# Seul service réseau de la borne en ligne (masqué par la configuration commune) ; pas de
# résolveur DNS, pas de synchronisation NTP (l'heure vient du serveur, canal authentifié).
in-target systemctl unmask systemd-networkd.service systemd-networkd.socket
in-target systemctl enable systemd-networkd.service barbacane-agent.service nftables.service
