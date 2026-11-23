#!/usr/bin/env python3
"""Collecteur Syslog de TEST pour les bancs (v2.3.0) : RFC 5425 (TLS 1.3) ou RFC 6587 (TCP en
clair), cadrage par longueur. Chaque message reçu est ajouté, sur une ligne, au fichier de
sortie. Comme rsyslog et syslog-ng, il ferme la connexion dès que le client a fermé la sienne :
c'est ce qui permet au serveur Barbacane de confirmer la remise d'un lot.

  collecteur-syslog.py --port P --sortie FICHIER [--cert C --cle K [--ac-client AC]]
"""
import argparse
import socket
import ssl
import threading


def trames(tampon, sortie, verrou):
    while True:
        e = tampon.find(b" ")
        if e <= 0:
            return tampon
        try:
            n = int(tampon[:e])
        except ValueError:
            raise SystemExit("trame invalide")
        if len(tampon) < e + 1 + n:
            return tampon
        m = tampon[e + 1:e + 1 + n]
        with verrou, open(sortie, "ab") as f:
            f.write(m.replace(b"\n", b" ") + b"\n")
        tampon = tampon[e + 1 + n:]


def servir(conn, contexte, sortie, verrou):
    try:
        conn.settimeout(60)
        if contexte is not None:
            conn = contexte.wrap_socket(conn, server_side=True)
        tampon = b""
        while True:
            o = conn.recv(65536)
            if not o:
                break
            tampon = trames(tampon + o, sortie, verrou)
    except (OSError, ssl.SSLError) as e:
        with verrou, open(sortie + ".erreurs", "a") as f:
            f.write(f"{e}\n")
    finally:
        conn.close()


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--port", type=int, required=True)
    a.add_argument("--sortie", required=True)
    a.add_argument("--cert")
    a.add_argument("--cle")
    a.add_argument("--ac-client")
    o = a.parse_args()
    contexte = None
    if o.cert:
        contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contexte.minimum_version = ssl.TLSVersion.TLSv1_3
        contexte.load_cert_chain(o.cert, o.cle)
        if o.ac_client:
            contexte.verify_mode = ssl.CERT_REQUIRED
            contexte.load_verify_locations(o.ac_client)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", o.port))
    s.listen(16)
    verrou = threading.Lock()
    while True:
        c, _ = s.accept()
        threading.Thread(target=servir, args=(c, contexte, o.sortie, verrou), daemon=True).start()


if __name__ == "__main__":
    main()
