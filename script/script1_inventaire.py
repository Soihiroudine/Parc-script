#!/usr/bin/env python3

import csv
import ipaddress
import logging
import os
import platform
import socket
import subprocess
from datetime import datetime
from pathlib import Path
import argparse

# ============================================================
# EXEMPLES D'UTILISATION
# ============================================================
#
# Analyse globale du réseau :
#
#   python ./script/script.py
#
#
# Analyse d'une plage précise :
#
#   python ./script/script.py --debut 192.168.1.10 --fin 192.168.1.50
#
#
# Afficher l'aide :
#
#   python ./script/script.py --help
#
#
# Si --debut et --fin ne sont pas renseignés :
#   -> le programme analyse le réseau RESEAU
#
#
# Si --debut et --fin sont renseignés :
#   -> le programme analyse uniquement la plage indiquée
#
#
# --debut et --fin doivent être utilisés ensemble.
#
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    finally:
        sock.close()


def get_network_cidr(ip, netmask):
    return str(
        ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    )


ip = get_local_ip()

# Le masque doit être obtenu autrement
netmask = "255.255.255.0"

# Obtenir le CIDR du réseau local
RESEAU = get_network_cidr(ip, netmask)

# Définition des chemins pour les rapports et les logs
PROJET = Path(__file__).resolve().parent.parent
DOSSIER_RAPPORTS = PROJET / "rapports" / "inventaire"
DOSSIER_LOGS = PROJET / "logs"

# Date actuelle pour nommer les fichiers
DATE = datetime.now().strftime("%Y-%m-%d")

FICHIER_CSV = os.path.join(
    DOSSIER_RAPPORTS,
    f"rapport_inventaire_{DATE}.csv"
)

FICHIER_LOG = os.path.join(
    DOSSIER_LOGS,
    "log_scan.txt"
)


# ============================================================
# ARGUMENTS
# ============================================================

def recuperer_arguments():
    """
    Récupère les arguments --debut et --fin.

    Les deux arguments sont optionnels.

    Aucun argument :
        -> analyse globale du réseau RESEAU

    --debut + --fin :
        -> analyse de la plage indiquée
    """

    parser = argparse.ArgumentParser(
        description="Analyse du réseau"
    )

    parser.add_argument(
        "--debut",
        help="Adresse IP de début"
    )

    parser.add_argument(
        "--fin",
        help="Adresse IP de fin"
    )

    args = parser.parse_args()

    # Aucun argument :
    # on utilisera RESEAU
    if args.debut is None and args.fin is None:
        return None, None

    # Un seul des deux arguments
    if args.debut is None or args.fin is None:
        parser.error(
            "--debut et --fin doivent être utilisés ensemble."
        )

    # Vérification des adresses IP
    try:
        ip_debut = ipaddress.IPv4Address(args.debut)
        ip_fin = ipaddress.IPv4Address(args.fin)

    except ipaddress.AddressValueError as erreur:
        parser.error(
            f"Adresse IP invalide : {erreur}"
        )

    # Vérification de l'ordre
    if ip_debut > ip_fin:
        parser.error(
            "L'adresse IP de début doit être "
            "inférieure ou égale à l'adresse IP de fin."
        )

    return ip_debut, ip_fin


# ============================================================
# INITIALISATION
# ============================================================

def initialiser_dossiers():
    """Créé les dossiers nécessaires."""

    os.makedirs(DOSSIER_RAPPORTS, exist_ok=True)
    os.makedirs(DOSSIER_LOGS, exist_ok=True)


def initialiser_logging():
    """Configure le fichier de journalisation."""

    logging.basicConfig(
        filename=FICHIER_LOG,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        encoding="utf-8"
    )


# ============================================================
# SCAN D'UNE ADRESSE IP
# ============================================================

def scanner_ip(ip):
    """
    Vérifie si une adresse IP répond au ping.

    Retourne :
        True  -> machine active
        False -> machine inactive
    """

    systeme = platform.system().lower()

    if systeme == "windows":
        commande = [
            "ping",
            "-n", "1",
            "-w", "1000",
            str(ip)
        ]
    else:
        commande = [
            "ping",
            "-c", "1",
            "-W", "1",
            str(ip)
        ]

    try:
        resultat = subprocess.run(
            commande,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )

        return resultat.returncode == 0

    except subprocess.TimeoutExpired:
        return False

    except Exception as erreur:
        logging.error(f"Erreur lors du scan de {ip} : {erreur}")
        return False


# ============================================================
# RECUPERATION DU HOSTNAME
# ============================================================

def recuperer_hostname(ip):
    """Essaie de récupérer le nom de la machine."""

    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname

    except socket.herror:
        return "Inconnu"

    except socket.gaierror:
        return "Inconnu"

    except Exception as erreur:
        logging.warning(
            f"Impossible de récupérer le hostname de {ip} : {erreur}"
        )
        return "Inconnu"


# ============================================================
# DETECTION APPROXIMATIVE DU SYSTEME
# ============================================================

def recuperer_os(ip):
    """
    Essaie d'identifier le système d'exploitation
    grâce au TTL retourné par le ping.

    Cette méthode est indicative et non garantie.
    """

    systeme = platform.system().lower()

    if systeme == "windows":
        commande = [
            "ping",
            "-n", "1",
            str(ip)
        ]
    else:
        commande = [
            "ping",
            "-c", "1",
            str(ip)
        ]

    try:
        resultat = subprocess.run(
            commande,
            capture_output=True,
            text=True,
            timeout=3
        )

        sortie = resultat.stdout.lower()

        # Recherche du TTL
        if "ttl=" in sortie:
            partie = sortie.split("ttl=")[1]
            ttl = ""

            for caractere in partie:
                if caractere.isdigit():
                    ttl += caractere
                else:
                    break

            if ttl:
                ttl = int(ttl)

                if ttl <= 64:
                    return "Linux / Unix probable"

                elif ttl <= 128:
                    return "Windows probable"

                elif ttl <= 255:
                    return "Équipement réseau / autre"

        return "Inconnu"

    except Exception as erreur:
        logging.warning(
            f"Impossible de déterminer l'OS de {ip} : {erreur}"
        )
        return "Inconnu"


# ============================================================
# CREATION DU RAPPORT
# ============================================================

def generer_csv(resultats):
    """Génère le fichier CSV d'inventaire."""

    champs = [
        "IP",
        "Hostname",
        "OS",
        "Statut"
    ]

    try:
        with open(
            FICHIER_CSV,
            "w",
            newline="",
            encoding="utf-8"
        ) as fichier:

            writer = csv.DictWriter(
                fichier,
                fieldnames=champs
            )

            writer.writeheader()

            for machine in resultats:
                writer.writerow(machine)

        logging.info(
            f"Rapport généré : {FICHIER_CSV}"
        )

    except Exception as erreur:
        logging.error(
            f"Erreur lors de la création du CSV : {erreur}"
        )


# ============================================================
# SCAN DU RESEAU
# ============================================================

def scanner_reseau(reseau):
    """Parcourt toutes les adresses IP du réseau."""

    resultats = []

    try:
        network = ipaddress.ip_network(
            reseau,
            strict=False
        )

    except ValueError:
        logging.error(
            f"Réseau invalide : {reseau}"
        )
        print(f"[ERREUR] Réseau invalide : {reseau}")
        return []

    print()
    print("=" * 60)
    print("       INVENTAIRE AUTOMATIQUE DU PARC")
    print("=" * 60)
    print()
    print(f"Réseau analysé : {network}")
    print()

    logging.info(
        f"Début du scan du réseau {network}"
    )

    for ip in network.hosts():

        print(
            f"[SCAN] {ip}",
            end="",
            flush=True
        )

        actif = scanner_ip(ip)

        if actif:

            print(" -> ACTIF")

            hostname = recuperer_hostname(ip)
            os_detecte = recuperer_os(ip)

            machine = {
                "IP": str(ip),
                "Hostname": hostname,
                "OS": os_detecte,
                "Statut": "Actif"
            }

            resultats.append(machine)

            logging.info(
                f"Machine active : {ip} | "
                f"Hostname : {hostname} | "
                f"OS : {os_detecte}"
            )

        else:

            print(" -> INACTIF")

            machine = {
                "IP": str(ip),
                "Hostname": "N/A",
                "OS": "N/A",
                "Statut": "Inactif"
            }

            resultats.append(machine)

    logging.info(
        f"Fin du scan. {len(resultats)} adresses analysées."
    )

    return resultats


# ============================================================
# SCAN D'UNE PLAGE D'IP
# ============================================================

def scanner_plage(ip_debut, ip_fin):
    """Parcourt une plage d'adresses IP."""

    resultats = []

    print()
    print("=" * 60)
    print("       INVENTAIRE AUTOMATIQUE DU PARC")
    print("=" * 60)
    print()
    print(
        f"Plage analysée : {ip_debut} -> {ip_fin}"
    )
    print()

    logging.info(
        f"Début du scan de la plage "
        f"{ip_debut} -> {ip_fin}"
    )

    ip = ip_debut

    while ip <= ip_fin:

        print(
            f"[SCAN] {ip}",
            end="",
            flush=True
        )

        actif = scanner_ip(ip)

        if actif:

            print(" -> ACTIF")

            hostname = recuperer_hostname(ip)
            os_detecte = recuperer_os(ip)

            machine = {
                "IP": str(ip),
                "Hostname": hostname,
                "OS": os_detecte,
                "Statut": "Actif"
            }

            resultats.append(machine)

            logging.info(
                f"Machine active : {ip} | "
                f"Hostname : {hostname} | "
                f"OS : {os_detecte}"
            )

        else:

            print(" -> INACTIF")

            machine = {
                "IP": str(ip),
                "Hostname": "N/A",
                "OS": "N/A",
                "Statut": "Inactif"
            }

            resultats.append(machine)

        ip += 1

    logging.info(
        f"Fin du scan. {len(resultats)} adresses analysées."
    )

    return resultats


# ============================================================
# RESUME
# ============================================================

def afficher_resume(resultats):
    """Affiche un résumé du scan."""

    total = len(resultats)

    actifs = sum(
        1
        for machine in resultats
        if machine["Statut"] == "Actif"
    )

    inactifs = total - actifs

    print()
    print("=" * 60)
    print("RÉSUMÉ")
    print("=" * 60)
    print(f"Adresses analysées : {total}")
    print(f"Machines actives   : {actifs}")
    print(f"Machines inactives : {inactifs}")
    print()
    print(f"Rapport CSV : {FICHIER_CSV}")
    print(f"Fichier log : {FICHIER_LOG}")
    print("=" * 60)


# ============================================================
# PROGRAMME PRINCIPAL
# ============================================================

def main():

    initialiser_dossiers()
    initialiser_logging()

    print()
    print("Démarrage de l'inventaire...")

    logging.info("==========================================")
    logging.info("Démarrage du script d'inventaire")
    logging.info("==========================================")

    # Récupération des arguments
    ip_debut, ip_fin = recuperer_arguments()

    # --------------------------------------------------------
    # Aucun argument :
    # analyse globale de RESEAU
    # --------------------------------------------------------

    if ip_debut is None and ip_fin is None:

        resultats = scanner_reseau(
            RESEAU
        )

    # --------------------------------------------------------
    # --debut et --fin :
    # analyse de la plage demandée
    # --------------------------------------------------------

    else:

        resultats = scanner_plage(
            ip_debut,
            ip_fin
        )

    if resultats:

        generer_csv(
            resultats
        )

        afficher_resume(
            resultats
        )

    else:

        print()
        print("[ERREUR] Aucun résultat.")

        logging.error(
            "Aucun résultat obtenu."
        )

    logging.info(
        "Fin du script."
    )


# ============================================================
# EXECUTION
# ============================================================

if __name__ == "__main__":
    main()
