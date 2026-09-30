#!/usr/bin/env python3

import csv
import ipaddress
import logging
import os
import platform
import socket
import subprocess
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

RESEAU = "192.168.10.0/24" # À modifier selon votre réseau

DOSSIER_RAPPORTS = "../rapports/inventaire"
DOSSIER_LOGS = "../logs"

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

    resultats = scanner_reseau(RESEAU)

    if resultats:
        generer_csv(resultats)
        afficher_resume(resultats)

    else:
        print()
        print("[ERREUR] Aucun résultat.")
        logging.error("Aucun résultat obtenu.")

    logging.info("Fin du script.")


# ============================================================
# EXECUTION
# ============================================================

if __name__ == "__main__":
    main()