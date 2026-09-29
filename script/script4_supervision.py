#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
============================================================
S4 - SUPERVISION ET ALERTE DE DISPONIBILITÉ DES SERVICES
============================================================

Fichier :
    script4_supervision.py

Objectif :
    Détecter automatiquement les services TCP en écoute
    sur la machine et surveiller leur disponibilité.

Fonctionnalités :
    - Découverte automatique des ports TCP en écoute
    - Identification automatique de certains services
    - Test automatique IP + port
    - Surveillance périodique
    - Logs horodatés
    - Détection d'une panne après 3 échecs consécutifs
    - Journalisation des incidents
    - Détection du retour à la normale
    - Calcul du taux de disponibilité
    - Génération d'un rapport SLA
    - Partie e-mail préparée mais désactivée

Aucune liste de services n'est nécessaire.

Arborescence :

    PROJET/
    │
    ├── script/
    │   └── script4_supervision.py
    │
    ├── logs/
    │   ├── supervision.log
    │   └── incidents.log
    │
    └── rapports/
        └── supervision/
            └── rapport_sla.txt
============================================================
"""


# ============================================================
#                         IMPORTS
# ============================================================

import socket
import time
import logging
import signal
import sys
import subprocess
import platform

from pathlib import Path
from datetime import datetime


# ============================================================
#                    CONFIGURATION
# ============================================================

# Temps entre deux cycles de supervision.
#
# Pour tester rapidement :
# INTERVALLE_TEST = 10
#
# Pour le projet :
# INTERVALLE_TEST = 30
INTERVALLE_TEST = 30


# Nombre d'échecs consécutifs avant de confirmer
# une panne.
SEUIL_ECHECS = 3


# Temps maximum pour tester un port.
TIMEOUT = 5


# Objectif SLA.
SLA_CIBLE = 99.9


# Adresse locale à surveiller.
ADRESSE_LOCALE = "127.0.0.1"


# ============================================================
#              SERVICES TCP CONNUS
# ============================================================

"""
Cette liste ne sert PAS à définir les services à surveiller.

Elle sert uniquement à donner un nom compréhensible
aux ports automatiquement découverts.

Exemples :

    22   -> SSH
    53   -> DNS
    80   -> HTTP
    443  -> HTTPS
    3306 -> MySQL
    5432 -> PostgreSQL
    8080 -> HTTP-ALT

Si un port n'est pas dans cette liste, le programme
l'appellera automatiquement :

    Service TCP - port XXXX
"""

SERVICES_CONNUS = {

    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker TLS",
    3000: "Application Web",
    3306: "MySQL",
    3389: "RDP",
    5000: "Application Web",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "Application Web",
    8080: "HTTP-ALT",
    8081: "Application Web",
    8443: "HTTPS-ALT",
    9000: "Application",
    9090: "Prometheus",
    9200: "Elasticsearch",
    27017: "MongoDB"

}


# ============================================================
#                  CONFIGURATION E-MAIL
# ============================================================

"""
============================================================
PARTIE E-MAIL DÉSACTIVÉE
============================================================

La partie e-mail est conservée en commentaire.

Elle pourra être activée plus tard.

Exemple Gmail :

    SMTP_SERVEUR = "smtp.gmail.com"
    SMTP_PORT = 587

    SMTP_UTILISATEUR = "monadresse@gmail.com"
    SMTP_MOT_DE_PASSE = "mot_de_passe_application"

    EMAIL_DESTINATAIRE = "administrateur@example.com"
"""


# SMTP_SERVEUR = "smtp.gmail.com"
# SMTP_PORT = 587

# SMTP_UTILISATEUR = "monadresse@gmail.com"
# SMTP_MOT_DE_PASSE = "mot_de_passe_application"

# EMAIL_DESTINATAIRE = "administrateur@example.com"


# ============================================================
#                  STRUCTURE DU PROJET
# ============================================================

# Dossier contenant ce script.
DOSSIER_SCRIPT = Path(__file__).resolve().parent


# Dossier principal du projet.
DOSSIER_PROJET = DOSSIER_SCRIPT.parent


# Dossier des logs.
DOSSIER_LOGS = DOSSIER_PROJET / "logs"


# Dossier des rapports.
DOSSIER_RAPPORTS = (
    DOSSIER_PROJET
    / "rapports"
    / "supervision"
)


# ============================================================
#                    CRÉATION DES DOSSIERS
# ============================================================

DOSSIER_LOGS.mkdir(
    parents=True,
    exist_ok=True
)


DOSSIER_RAPPORTS.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
#                       FICHIERS
# ============================================================

FICHIER_LOG = (
    DOSSIER_LOGS
    / "supervision.log"
)


FICHIER_INCIDENTS = (
    DOSSIER_LOGS
    / "incidents.log"
)


FICHIER_RAPPORT = (
    DOSSIER_RAPPORTS
    / "rapport_sla.txt"
)


# ============================================================
#                   VARIABLE GLOBALE
# ============================================================

PROGRAMME_ACTIF = True


# ============================================================
#                       LOGGING
# ============================================================

logging.basicConfig(

    filename=str(FICHIER_LOG),

    level=logging.INFO,

    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    ),

    datefmt="%Y-%m-%d %H:%M:%S"
)


logger = logging.getLogger(
    "supervision"
)


# ============================================================
#                    CTRL + C
# ============================================================

def arreter_programme(signal_num, frame):
    """
    Arrête proprement le programme avec Ctrl+C.
    """

    global PROGRAMME_ACTIF

    PROGRAMME_ACTIF = False

    print()
    print("Arrêt de la supervision demandé...")

    logger.info(
        "Arrêt demandé par l'utilisateur."
    )


signal.signal(
    signal.SIGINT,
    arreter_programme
)


# ============================================================
#              IDENTIFICATION D'UN SERVICE
# ============================================================

def obtenir_nom_service(port):
    """
    Retourne un nom lisible pour un port.

    Si le port est connu, on utilise son nom.

    Sinon :
        Service TCP - port XXXX
    """

    if port in SERVICES_CONNUS:

        return SERVICES_CONNUS[port]

    return f"Service TCP - port {port}"


# ============================================================
#            DÉTECTION DES PORTS SOUS LINUX
# ============================================================

def decouvrir_ports_linux():
    """
    Détecte les ports TCP en écoute sous Linux.

    Utilise /proc/net/tcp et /proc/net/tcp6.

    Retourne une liste de ports.
    """

    ports = set()


    fichiers = [
        "/proc/net/tcp",
        "/proc/net/tcp6"
    ]


    for chemin in fichiers:

        try:

            with open(
                chemin,
                "r",
                encoding="utf-8"
            ) as fichier:

                lignes = fichier.readlines()


            # La première ligne contient les noms des colonnes.
            for ligne in lignes[1:]:

                elements = ligne.split()


                # Vérification de la longueur.
                if len(elements) < 4:
                    continue


                adresse_locale = elements[1]

                etat = elements[3]


                # État 0A = LISTEN
                if etat != "0A":
                    continue


                # Format :
                #
                # adresse_hex:port_hex
                #
                # Exemple :
                #
                # 0100007F:0016
                #

                try:

                    port_hex = (
                        adresse_locale
                        .split(":")[1]
                    )

                    port = int(
                        port_hex,
                        16
                    )

                    ports.add(port)

                except (
                    ValueError,
                    IndexError
                ):

                    continue


        except FileNotFoundError:

            continue


        except PermissionError:

            logger.warning(
                "Permission refusée pour %s",
                chemin
            )


        except Exception as erreur:

            logger.error(
                "Erreur lecture %s : %s",
                chemin,
                erreur
            )


    return sorted(ports)


# ============================================================
#             DÉTECTION DES PORTS SOUS WINDOWS
# ============================================================

def decouvrir_ports_windows():
    """
    Détecte les ports TCP en écoute sous Windows
    à l'aide de netstat.
    """

    ports = set()


    try:

        resultat = subprocess.run(

            [
                "netstat",
                "-ano"
            ],

            capture_output=True,

            text=True,

            timeout=10,

            encoding="cp850",

            errors="replace"

        )


        for ligne in resultat.stdout.splitlines():

            ligne = ligne.strip()


            if not ligne:
                continue


            # On s'intéresse uniquement aux lignes TCP.
            if not ligne.upper().startswith("TCP"):
                continue


            elements = ligne.split()


            # Une ligne netstat classique :
            #
            # TCP
            # Adresse locale
            # Adresse distante
            # Etat
            # PID
            #

            if len(elements) < 4:
                continue


            etat = elements[3].upper()


            if etat != "LISTENING":
                continue


            adresse_locale = elements[1]


            try:

                port = int(
                    adresse_locale.rsplit(
                        ":",
                        1
                    )[1]
                )

                ports.add(port)

            except (
                ValueError,
                IndexError
            ):

                continue


    except FileNotFoundError:

        logger.error(
            "La commande netstat "
            "n'est pas disponible."
        )


    except subprocess.TimeoutExpired:

        logger.error(
            "Timeout lors de l'exécution de netstat."
        )


    except Exception as erreur:

        logger.error(
            "Erreur lors de la découverte "
            "des ports Windows : %s",
            erreur
        )


    return sorted(ports)


# ============================================================
#             DÉTECTION DES PORTS SOUS MACOS
# ============================================================

def decouvrir_ports_macos():
    """
    Détecte les ports TCP en écoute sous macOS.

    Utilise la commande lsof si disponible.
    """

    ports = set()


    try:

        resultat = subprocess.run(

            [
                "lsof",
                "-nP",
                "-iTCP",
                "-sTCP:LISTEN"
            ],

            capture_output=True,

            text=True,

            timeout=10,

            encoding="utf-8",

            errors="replace"

        )


        for ligne in resultat.stdout.splitlines():

            ligne = ligne.strip()


            if not ligne:
                continue


            # Les informations de réseau se trouvent
            # généralement dans la colonne finale.
            elements = ligne.split()


            if len(elements) < 9:
                continue


            derniere_colonne = elements[-1]


            # Exemple :
            #
            # 127.0.0.1:8080
            # *:80
            #

            if ":" not in derniere_colonne:
                continue


            try:

                port = int(
                    derniere_colonne
                    .rsplit(":", 1)[1]
                )

                ports.add(port)

            except (
                ValueError,
                IndexError
            ):

                continue


    except FileNotFoundError:

        logger.error(
            "La commande lsof "
            "n'est pas disponible."
        )


    except Exception as erreur:

        logger.error(
            "Erreur lors de la découverte "
            "des ports macOS : %s",
            erreur
        )


    return sorted(ports)


# ============================================================
#             DÉCOUVERTE AUTOMATIQUE
# ============================================================

def decouvrir_services():
    """
    Détecte automatiquement les services TCP locaux.

    Le programme choisit la méthode adaptée au système
    d'exploitation.

    Retourne une liste de dictionnaires :

        {
            "nom": "...",
            "ip": "127.0.0.1",
            "port": 80
        }
    """

    systeme = platform.system()


    logger.info(
        "Système détecté : %s",
        systeme
    )


    # --------------------------------------------------------
    # Linux
    # --------------------------------------------------------

    if systeme == "Linux":

        ports = decouvrir_ports_linux()


    # --------------------------------------------------------
    # Windows
    # --------------------------------------------------------

    elif systeme == "Windows":

        ports = decouvrir_ports_windows()


    # --------------------------------------------------------
    # macOS
    # --------------------------------------------------------

    elif systeme == "Darwin":

        ports = decouvrir_ports_macos()


    # --------------------------------------------------------
    # Système inconnu
    # --------------------------------------------------------

    else:

        logger.error(
            "Système d'exploitation non supporté : %s",
            systeme
        )

        ports = []


    # ========================================================
    # Création des services
    # ========================================================

    services = []


    for port in ports:

        nom = obtenir_nom_service(
            port
        )


        service = {

            "nom": nom,

            "ip": ADRESSE_LOCALE,

            "port": port

        }


        services.append(
            service
        )


    # Log de la découverte.
    logger.info(
        "%s service(s) découvert(s).",
        len(services)
    )


    return services


# ============================================================
#                    TEST D'UN SERVICE
# ============================================================

def tester_service(
    ip,
    port,
    timeout=TIMEOUT
):
    """
    Teste la disponibilité d'un service TCP.
    """

    socket_test = None


    try:

        socket_test = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )


        socket_test.settimeout(
            timeout
        )


        resultat = socket_test.connect_ex(
            (ip, port)
        )


        if resultat == 0:

            return True


        return False


    except socket.error:

        return False


    except Exception as erreur:

        logger.error(
            "Erreur test %s:%s : %s",
            ip,
            port,
            erreur
        )

        return False


    finally:

        if socket_test is not None:

            try:

                socket_test.close()

            except Exception:

                pass


# ============================================================
#                PARTIE E-MAIL DÉSACTIVÉE
# ============================================================

"""
La fonction d'envoi d'e-mail est volontairement
commentée.

Elle pourra être activée ultérieurement.

"""


# def envoyer_email(sujet, message):
#
#     from email.message import EmailMessage
#     import smtplib
#
#     try:
#
#         email = EmailMessage()
#
#         email["Subject"] = sujet
#         email["From"] = SMTP_UTILISATEUR
#         email["To"] = EMAIL_DESTINATAIRE
#
#         email.set_content(message)
#
#
#         with smtplib.SMTP(
#             SMTP_SERVEUR,
#             SMTP_PORT,
#             timeout=15
#         ) as serveur:
#
#             serveur.starttls()
#
#             serveur.login(
#                 SMTP_UTILISATEUR,
#                 SMTP_MOT_DE_PASSE
#             )
#
#             serveur.send_message(email)
#
#
#         logger.info(
#             "E-mail envoyé : %s",
#             sujet
#         )
#
#
#     except Exception as erreur:
#
#         logger.error(
#             "Erreur e-mail : %s",
#             erreur
#         )


# ============================================================
#                  ENREGISTREMENT INCIDENT
# ============================================================

def enregistrer_incident(message):
    """
    Enregistre un incident dans incidents.log.
    """

    date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    ligne = (
        f"{date} | {message}\n"
    )


    try:

        with open(
            FICHIER_INCIDENTS,
            "a",
            encoding="utf-8"
        ) as fichier:

            fichier.write(
                ligne
            )


    except Exception as erreur:

        logger.error(
            "Erreur écriture incident : %s",
            erreur
        )


# ============================================================
#                     CALCUL DU SLA
# ============================================================

def calculer_sla(statistiques):
    """
    Calcule le SLA de chaque service.
    """

    resultats = {}


    for nom, stats in statistiques.items():

        total = stats["total"]

        succes = stats["succes"]


        if total == 0:

            sla = 0.0

        else:

            sla = (
                succes / total
            ) * 100


        resultats[nom] = sla


    return resultats


# ============================================================
#                  GÉNÉRATION DU RAPPORT
# ============================================================

def generer_rapport(
    statistiques,
    date_debut,
    date_fin
):
    """
    Génère le rapport SLA.
    """

    slas = calculer_sla(
        statistiques
    )


    try:

        with open(
            FICHIER_RAPPORT,
            "w",
            encoding="utf-8"
        ) as fichier:

            # ------------------------------------------------
            # En-tête
            # ------------------------------------------------

            fichier.write(
                "=" * 80 + "\n"
            )

            fichier.write(
                "             RAPPORT DE SUPERVISION SLA\n"
            )

            fichier.write(
                "=" * 80 + "\n\n"
            )


            # ------------------------------------------------
            # Informations
            # ------------------------------------------------

            fichier.write(
                "INFORMATIONS GÉNÉRALES\n"
            )

            fichier.write(
                "-" * 80 + "\n"
            )


            fichier.write(
                "Début : "
                + date_debut.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                + "\n"
            )


            fichier.write(
                "Fin   : "
                + date_fin.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                + "\n"
            )


            fichier.write(
                f"Intervalle : "
                f"{INTERVALLE_TEST} secondes\n"
            )


            fichier.write(
                f"Seuil panne : "
                f"{SEUIL_ECHECS} échecs consécutifs\n"
            )


            fichier.write(
                f"Objectif SLA : "
                f"{SLA_CIBLE:.3f} %\n"
            )


            fichier.write("\n")


            # ------------------------------------------------
            # Tableau
            # ------------------------------------------------

            fichier.write(
                "SERVICES SURVEILLÉS\n"
            )

            fichier.write(
                "-" * 80 + "\n"
            )


            fichier.write(
                f"{'Service':30}"
                f"{'Port':>10}"
                f"{'Tests':>10}"
                f"{'OK':>10}"
                f"{'Échecs':>10}"
                f"{'SLA':>10}\n"
            )


            fichier.write(
                "-" * 80 + "\n"
            )


            for nom, stats in statistiques.items():

                sla = slas[nom]

                port = stats["port"]


                fichier.write(
                    f"{nom[:30]:30}"
                    f"{port:>10}"
                    f"{stats['total']:>10}"
                    f"{stats['succes']:>10}"
                    f"{stats['echecs']:>10}"
                    f"{sla:>9.3f}%\n"
                )


            fichier.write(
                "-" * 80 + "\n\n"
            )


            # ------------------------------------------------
            # Statistiques globales
            # ------------------------------------------------

            total_global = sum(
                stats["total"]
                for stats in statistiques.values()
            )


            succes_global = sum(
                stats["succes"]
                for stats in statistiques.values()
            )


            echecs_global = sum(
                stats["echecs"]
                for stats in statistiques.values()
            )


            if total_global > 0:

                sla_global = (
                    succes_global
                    / total_global
                ) * 100

            else:

                sla_global = 0.0


            fichier.write(
                "RÉSUMÉ GLOBAL\n"
            )

            fichier.write(
                "-" * 80 + "\n"
            )


            fichier.write(
                f"Nombre total de tests : "
                f"{total_global}\n"
            )


            fichier.write(
                f"Tests réussis         : "
                f"{succes_global}\n"
            )


            fichier.write(
                f"Tests échoués         : "
                f"{echecs_global}\n"
            )


            fichier.write(
                f"SLA global            : "
                f"{sla_global:.3f} %\n"
            )


            fichier.write("\n")


            # ------------------------------------------------
            # Objectif
            # ------------------------------------------------

            fichier.write(
                "OBJECTIF SLA\n"
            )

            fichier.write(
                "-" * 80 + "\n"
            )


            if sla_global >= SLA_CIBLE:

                fichier.write(
                    "Objectif SLA atteint.\n"
                )

            else:

                fichier.write(
                    "Objectif SLA non atteint.\n"
                )


            fichier.write("\n")


            fichier.write(
                "=" * 80 + "\n"
            )


        logger.info(
            "Rapport SLA généré : %s",
            FICHIER_RAPPORT
        )


    except Exception as erreur:

        logger.error(
            "Erreur génération rapport : %s",
            erreur
        )


# ============================================================
#                 AFFICHAGE D'UN RÉSULTAT
# ============================================================

def afficher_resultat(
    service,
    disponible,
    echecs_consecutifs
):
    """
    Affiche le résultat d'un test.
    """

    date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    nom = service["nom"]

    ip = service["ip"]

    port = service["port"]


    if disponible:

        print(
            f"[{date}] "
            f"[OK] "
            f"{nom} "
            f"({ip}:{port})"
        )


    else:

        print(
            f"[{date}] "
            f"[ERREUR] "
            f"{nom} "
            f"({ip}:{port}) "
            f"- échecs consécutifs : "
            f"{echecs_consecutifs}"
        )


# ============================================================
#              AFFICHAGE DES SERVICES DÉTECTÉS
# ============================================================

def afficher_services(services):
    """
    Affiche les services automatiquement détectés.
    """

    print()

    print(
        f"{len(services)} service(s) "
        "TCP détecté(s) automatiquement."
    )

    print()


    if not services:

        print(
            "Aucun service TCP en écoute détecté."
        )

        print()

        return


    print(
        "Services détectés :"
    )


    for service in services:

        print(
            f"  - {service['nom']} "
            f"-> "
            f"{service['ip']}:{service['port']}"
        )


    print()


# ============================================================
#                 INITIALISATION STATISTIQUES
# ============================================================

def initialiser_statistiques(services):
    """
    Crée les statistiques pour les services détectés.
    """

    statistiques = {}


    for service in services:

        nom = service["nom"]


        # Si deux services ont le même nom,
        # on ajoute le port pour les différencier.

        if nom in statistiques:

            nom = (
                f"{service['nom']} "
                f"({service['port']})"
            )

            service["nom"] = nom


        statistiques[nom] = {

            "port": service["port"],

            "total": 0,

            "succes": 0,

            "echecs": 0

        }


    return statistiques


# ============================================================
#                AJOUT DES NOUVEAUX SERVICES
# ============================================================

def ajouter_nouveaux_services(
    services,
    statistiques,
    echecs_consecutifs,
    panne_confirmee
):
    """
    Recherche de nouveaux services.

    Si un nouveau port apparaît pendant que le programme
    fonctionne, il est automatiquement ajouté à la
    supervision.
    """

    nouveaux_services = decouvrir_services()


    ports_existants = {
        service["port"]
        for service in services
    }


    nombre_nouveaux = 0


    for service in nouveaux_services:

        port = service["port"]


        # Le port est déjà surveillé.
        if port in ports_existants:

            continue


        # ----------------------------------------------------
        # Nouveau service
        # ----------------------------------------------------

        nom = service["nom"]


        # Évite les conflits de noms.
        if nom in statistiques:

            nom = (
                f"{nom} "
                f"({port})"
            )

            service["nom"] = nom


        services.append(
            service
        )


        statistiques[nom] = {

            "port": port,

            "total": 0,

            "succes": 0,

            "echecs": 0

        }


        echecs_consecutifs[nom] = 0

        panne_confirmee[nom] = False


        ports_existants.add(
            port
        )


        nombre_nouveaux += 1


        logger.info(
            "Nouveau service détecté : "
            "%s:%s",
            ADRESSE_LOCALE,
            port
        )


    if nombre_nouveaux > 0:

        print()

        print(
            f"{nombre_nouveaux} nouveau(x) "
            "service(s) détecté(s)."
        )


    return services


# ============================================================
#                         MAIN
# ============================================================

def main():

    global PROGRAMME_ACTIF


    # ========================================================
    # CONFIGURATION
    # ========================================================

    print()

    print(
        "=" * 80
    )

    print(
        "     S4 - SUPERVISION AUTOMATIQUE DES SERVICES"
    )

    print(
        "=" * 80
    )

    print()


    print(
        f"Système : "
        f"{platform.system()}"
    )


    print(
        f"Adresse surveillée : "
        f"{ADRESSE_LOCALE}"
    )


    print(
        f"Intervalle : "
        f"{INTERVALLE_TEST} secondes"
    )


    print(
        f"Seuil de panne : "
        f"{SEUIL_ECHECS} échecs consécutifs"
    )


    print(
        f"Timeout : "
        f"{TIMEOUT} secondes"
    )


    print(
        f"SLA cible : "
        f"{SLA_CIBLE:.1f} %"
    )


    print()


    # ========================================================
    # DÉCOUVERTE INITIALE
    # ========================================================

    print(
        "Recherche automatique des services..."
    )


    services = decouvrir_services()


    afficher_services(
        services
    )


    # ========================================================
    # SI AUCUN SERVICE N'EST DÉTECTÉ
    # ========================================================

    if not services:

        print(
            "Aucun service TCP en écoute n'a été détecté."
        )


        print(
            "La supervision reste active et "
            "recherchera régulièrement de nouveaux services."
        )


        logger.warning(
            "Aucun service détecté au démarrage."
        )


    # ========================================================
    # STATISTIQUES
    # ========================================================

    statistiques = (
        initialiser_statistiques(
            services
        )
    )


    # ========================================================
    # COMPTEURS
    # ========================================================

    echecs_consecutifs = {}

    panne_confirmee = {}


    for service in services:

        nom = service["nom"]


        echecs_consecutifs[nom] = 0

        panne_confirmee[nom] = False


    # ========================================================
    # DATE DE DÉBUT
    # ========================================================

    date_debut = datetime.now()


    logger.info(
        "Démarrage de la supervision."
    )


    # ========================================================
    # BOUCLE PRINCIPALE
    # ========================================================

    while PROGRAMME_ACTIF:

        print()

        print(
            "=" * 80
        )


        print(
            "Cycle de supervision - "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )


        print(
            "=" * 80
        )


        # ====================================================
        # RECHERCHE DES NOUVEAUX SERVICES
        # ====================================================

        services = ajouter_nouveaux_services(

            services,

            statistiques,

            echecs_consecutifs,

            panne_confirmee

        )


        # ====================================================
        # TEST DE CHAQUE SERVICE
        # ====================================================

        for service in services:

            nom = service["nom"]

            ip = service["ip"]

            port = service["port"]


            # ------------------------------------------------
            # Test TCP
            # ------------------------------------------------

            disponible = tester_service(

                ip,

                port,

                TIMEOUT

            )


            # =================================================
            # SERVICE DISPONIBLE
            # =================================================

            if disponible:

                statistiques[nom]["total"] += 1

                statistiques[nom]["succes"] += 1


                # Sauvegarde du nombre d'échecs.
                ancien_nombre_echecs = (
                    echecs_consecutifs[nom]
                )


                # Remise à zéro.
                echecs_consecutifs[nom] = 0


                # ------------------------------------------------
                # RETOUR À LA NORMALE
                # ------------------------------------------------

                if panne_confirmee[nom]:

                    date_retour = datetime.now()


                    message_incident = (

                        "RETOUR A LA NORMALE | "

                        f"{nom} | "

                        f"{ip}:{port} | "

                        "Service de nouveau disponible | "

                        "Retour : "

                        + date_retour.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )

                    )


                    logger.info(
                        message_incident
                    )


                    enregistrer_incident(
                        message_incident
                    )


                    # ------------------------------------------------
                    # E-MAIL DÉSACTIVÉ
                    # ------------------------------------------------

                    # sujet = (
                    #     f"[RECOVERY] {nom}"
                    # )
                    #
                    # message = (
                    #     "RETOUR À LA NORMALE\n\n"
                    #     f"Service : {nom}\n"
                    #     f"Adresse : {ip}\n"
                    #     f"Port : {port}\n"
                    # )
                    #
                    # envoyer_email(
                    #     sujet,
                    #     message
                    # )


                    panne_confirmee[nom] = False


                else:

                    logger.info(
                        "OK | %s | %s:%s",
                        nom,
                        ip,
                        port
                    )


            # =================================================
            # SERVICE INDISPONIBLE
            # =================================================

            else:

                statistiques[nom]["total"] += 1

                statistiques[nom]["echecs"] += 1


                # Incrémentation du compteur.
                echecs_consecutifs[nom] += 1


                nombre_echecs = (
                    echecs_consecutifs[nom]
                )


                logger.warning(

                    "ÉCHEC | %s | %s:%s | "
                    "échecs consécutifs = %s",

                    nom,

                    ip,

                    port,

                    nombre_echecs

                )


                # =================================================
                # PANNE CONFIRMÉE
                # =================================================

                if (

                    nombre_echecs >= SEUIL_ECHECS

                    and not panne_confirmee[nom]

                ):

                    panne_confirmee[nom] = True


                    date_panne = datetime.now()


                    message_incident = (

                        "PANNE CONFIRMEE | "

                        f"{nom} | "

                        f"{ip}:{port} | "

                        f"{nombre_echecs} "
                        "échecs consécutifs | "

                        "Détection : "

                        + date_panne.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )

                    )


                    # Log principal.
                    logger.error(
                        message_incident
                    )


                    # Log des incidents.
                    enregistrer_incident(
                        message_incident
                    )


                    # ------------------------------------------------
                    # E-MAIL DÉSACTIVÉ
                    # ------------------------------------------------

                    # sujet = (
                    #     f"[ALERTE PANNE] {nom}"
                    # )
                    #
                    # message = (
                    #     "ALERTE DE SUPERVISION\n\n"
                    #     "Une panne a été détectée.\n\n"
                    #     f"Service : {nom}\n"
                    #     f"Adresse IP : {ip}\n"
                    #     f"Port : {port}\n"
                    #     f"Échecs : {nombre_echecs}\n"
                    # )
                    #
                    # envoyer_email(
                    #     sujet,
                    #     message
                    # )


            # ------------------------------------------------
            # Affichage du résultat.
            # ------------------------------------------------

            afficher_resultat(

                service,

                disponible,

                echecs_consecutifs[nom]

            )


        # ====================================================
        # ATTENTE AVANT LE PROCHAIN CYCLE
        # ====================================================

        if PROGRAMME_ACTIF:

            print()

            print(

                f"Prochain test dans "
                f"{INTERVALLE_TEST} secondes..."

            )


            temps_ecoule = 0


            while (

                temps_ecoule < INTERVALLE_TEST

                and PROGRAMME_ACTIF

            ):

                time.sleep(1)

                temps_ecoule += 1


    # ========================================================
    # FIN DE LA SUPERVISION
    # ========================================================

    date_fin = datetime.now()


    print()

    print(
        "=" * 80
    )


    print(
        "Fin de la supervision."
    )


    print(
        "Génération du rapport SLA..."
    )


    print(
        "=" * 80
    )


    logger.info(
        "Fin de la supervision."
    )


    # ========================================================
    # GÉNÉRATION DU RAPPORT
    # ========================================================

    generer_rapport(

        statistiques,

        date_debut,

        date_fin

    )


    # ========================================================
    # FICHIERS GÉNÉRÉS
    # ========================================================

    print()

    print(
        "Fichiers générés :"
    )


    print()

    print(
        f"  supervision.log"
    )

    print(
        f"  {FICHIER_LOG}"
    )


    print()

    print(
        f"  incidents.log"
    )

    print(
        f"  {FICHIER_INCIDENTS}"
    )


    print()

    print(
        f"  rapport_sla.txt"
    )

    print(
        f"  {FICHIER_RAPPORT}"
    )


    print()

    print(
        "Supervision terminée."
    )


# ============================================================
#                     LANCEMENT
# ============================================================

if __name__ == "__main__":

    try:

        main()


    except KeyboardInterrupt:

        PROGRAMME_ACTIF = False

        print()

        print(
            "Arrêt demandé par l'utilisateur."
        )


    except Exception as erreur:

        logger.exception(
            "Erreur critique : %s",
            erreur
        )


        print()

        print(
            "ERREUR CRITIQUE :"
        )


        print(
            erreur
        )


        sys.exit(1)
