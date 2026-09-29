#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
============================================================
S4 - SUPERVISION ET ALERTE DE DISPONIBILITÉ DES SERVICES
============================================================

Fichier :
    script4_supervision.py

Objectif :
    Surveiller en temps réel la disponibilité des services
    critiques et envoyer une alerte en cas de panne.

Fonctionnalités :
    - Surveillance de plusieurs services TCP
    - Test IP + port
    - Vérification toutes les X secondes
    - Journalisation avec horodatage
    - Détection d'une panne après 3 échecs consécutifs
    - Journal des incidents
    - Alerte e-mail
    - Détection du retour à la normale
    - Calcul du taux de disponibilité
    - Génération automatique d'un rapport SLA

Arborescence attendue :

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

import socket
import time
import logging
import smtplib
import signal
import sys

from pathlib import Path
from datetime import datetime
from email.message import EmailMessage


# ============================================================
#                    CONFIGURATION GÉNÉRALE
# ============================================================

# Temps entre deux cycles de surveillance.
#
# Pour un test rapide, tu peux mettre :
# INTERVALLE_TEST = 10
#
# Pour le projet réel :
# INTERVALLE_TEST = 30
INTERVALLE_TEST = 30

# Nombre d'échecs consécutifs nécessaires
# pour confirmer une panne.
SEUIL_ECHECS = 3

# Temps maximum pour tenter une connexion.
TIMEOUT = 5

# Objectif SLA.
SLA_CIBLE = 99.9


# ============================================================
#                       SERVICES
# ============================================================

"""
Liste des services à surveiller.

Chaque service possède :
    - nom
    - ip
    - port

IMPORTANT :
    Remplace les adresses IP et les ports par ceux
    correspondant à ton environnement.
"""

SERVICES = [
    {
        "nom": "Serveur Web",
        "ip": "192.168.1.10",
        "port": 80
    },
    {
        "nom": "Serveur SSH",
        "ip": "192.168.1.20",
        "port": 22
    },
    {
        "nom": "Serveur Application",
        "ip": "192.168.1.30",
        "port": 8080
    }
]


# ============================================================
#                    CONFIGURATION EMAIL
# ============================================================

"""
Configuration de l'envoi d'e-mails.

Par défaut, les e-mails sont désactivés.

Pour activer :

    EMAIL_ACTIF = True

Puis renseigne les paramètres SMTP.

Exemple Gmail :

    SMTP_SERVEUR = "smtp.gmail.com"
    SMTP_PORT = 587

Il est recommandé d'utiliser un mot de passe
d'application avec Gmail.
"""

EMAIL_ACTIF = False

SMTP_SERVEUR = "smtp.gmail.com"
SMTP_PORT = 587

SMTP_UTILISATEUR = "monadresse@gmail.com"
SMTP_MOT_DE_PASSE = "MOT_DE_PASSE_APPLICATION"

EMAIL_DESTINATAIRE = "administrateur@example.com"


# ============================================================
#                     STRUCTURE DU PROJET
# ============================================================

"""
Le script se trouve dans :

    PROJET/script/script4_supervision.py

Donc :

    DOSSIER_SCRIPT = PROJET/script
    DOSSIER_PROJET = PROJET

Les fichiers seront automatiquement placés dans :

    PROJET/logs/
    PROJET/rapports/supervision/
"""


# Dossier dans lequel se trouve ce script.
DOSSIER_SCRIPT = Path(__file__).resolve().parent

# Dossier principal du projet.
DOSSIER_PROJET = DOSSIER_SCRIPT.parent

# Dossier contenant les fichiers de logs.
DOSSIER_LOGS = DOSSIER_PROJET / "logs"

# Dossier contenant les rapports.
DOSSIER_RAPPORTS = DOSSIER_PROJET / "rapports" / "supervision"


# Création automatique des dossiers.
DOSSIER_LOGS.mkdir(
    parents=True,
    exist_ok=True
)

DOSSIER_RAPPORTS.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
#                         FICHIERS
# ============================================================

FICHIER_LOG = DOSSIER_LOGS / "supervision.log"

FICHIER_INCIDENTS = DOSSIER_LOGS / "incidents.log"

FICHIER_RAPPORT = DOSSIER_RAPPORTS / "rapport_sla.txt"


# ============================================================
#                       VARIABLE GLOBALE
# ============================================================

# Permet d'arrêter proprement le programme.
PROGRAMME_ACTIF = True


# ============================================================
#                         LOGGING
# ============================================================

logging.basicConfig(
    filename=str(FICHIER_LOG),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("supervision")


# ============================================================
#                     GESTION DE CTRL+C
# ============================================================

def arreter_programme(signal_num, frame):
    """
    Arrête proprement le programme lorsque l'utilisateur
    appuie sur Ctrl+C.
    """

    global PROGRAMME_ACTIF

    PROGRAMME_ACTIF = False

    print()
    print("Arrêt de la supervision demandé...")

    logger.info(
        "Arrêt de la supervision demandé par l'utilisateur."
    )


# Capture Ctrl+C.
signal.signal(
    signal.SIGINT,
    arreter_programme
)


# ============================================================
#                     TEST DU SERVICE
# ============================================================

def tester_service(ip, port, timeout=TIMEOUT):
    """
    Teste la disponibilité d'un service TCP.

    Paramètres :
        ip      : adresse IP du service
        port    : port TCP
        timeout : délai maximum de connexion

    Retour :
        True  -> service disponible
        False -> service indisponible
    """

    socket_test = None

    try:

        # Création d'un socket TCP.
        socket_test = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        # Définition du timeout.
        socket_test.settimeout(timeout)

        # Tentative de connexion.
        resultat = socket_test.connect_ex(
            (ip, port)
        )

        # Si le résultat est 0 :
        # la connexion a réussi.
        if resultat == 0:
            return True

        return False

    except socket.error:

        return False

    except Exception as erreur:

        logger.error(
            "Erreur lors du test de %s:%s : %s",
            ip,
            port,
            erreur
        )

        return False

    finally:

        # Fermeture du socket.
        if socket_test is not None:

            try:
                socket_test.close()

            except Exception:
                pass


# ============================================================
#                    ENVOI D'UN EMAIL
# ============================================================

def envoyer_email(sujet, message):
    """
    Envoie une alerte par e-mail.

    Si EMAIL_ACTIF vaut False, aucun e-mail
    ne sera envoyé.
    """

    # Si les e-mails sont désactivés.
    if not EMAIL_ACTIF:

        logger.info(
            "Alerte e-mail désactivée : %s",
            sujet
        )

        return


    try:

        # Création du message.
        email = EmailMessage()

        email["Subject"] = sujet
        email["From"] = SMTP_UTILISATEUR
        email["To"] = EMAIL_DESTINATAIRE

        email.set_content(message)


        # Connexion au serveur SMTP.
        with smtplib.SMTP(
            SMTP_SERVEUR,
            SMTP_PORT,
            timeout=15
        ) as serveur:

            # Activation de STARTTLS.
            serveur.starttls()

            # Connexion au compte SMTP.
            serveur.login(
                SMTP_UTILISATEUR,
                SMTP_MOT_DE_PASSE
            )

            # Envoi du message.
            serveur.send_message(email)


        logger.info(
            "Alerte e-mail envoyée : %s",
            sujet
        )


    except Exception as erreur:

        logger.error(
            "Erreur lors de l'envoi de l'e-mail : %s",
            erreur
        )


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

            fichier.write(ligne)


    except Exception as erreur:

        logger.error(
            "Impossible d'écrire dans incidents.log : %s",
            erreur
        )


# ============================================================
#                     CALCUL DU SLA
# ============================================================

def calculer_sla(statistiques):
    """
    Calcule le taux de disponibilité de chaque service.

    Formule :

        SLA = (tests réussis / tests totaux) * 100
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
#                   RAPPORT SLA
# ============================================================

def generer_rapport(
    statistiques,
    date_debut,
    date_fin
):
    """
    Génère le fichier :

        rapports/supervision/rapport_sla.txt
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
                "=" * 75 + "\n"
            )

            fichier.write(
                "                 RAPPORT DE SLA\n"
            )

            fichier.write(
                "=" * 75 + "\n\n"
            )


            # ------------------------------------------------
            # Informations générales
            # ------------------------------------------------

            fichier.write(
                "Informations générales\n"
            )

            fichier.write(
                "-" * 75 + "\n"
            )

            fichier.write(
                "Début de surveillance : "
                f"{date_debut.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

            fichier.write(
                "Fin de surveillance   : "
                f"{date_fin.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

            fichier.write(
                f"Intervalle de test    : "
                f"{INTERVALLE_TEST} secondes\n"
            )

            fichier.write(
                f"Seuil de panne        : "
                f"{SEUIL_ECHECS} échecs consécutifs\n"
            )

            fichier.write(
                f"Objectif SLA          : "
                f"{SLA_CIBLE:.3f} %\n"
            )

            fichier.write("\n")


            # ------------------------------------------------
            # Tableau des services
            # ------------------------------------------------

            fichier.write(
                "Disponibilité des services\n"
            )

            fichier.write(
                "-" * 75 + "\n"
            )


            fichier.write(
                f"{'Service':25}"
                f"{'Tests':>10}"
                f"{'OK':>10}"
                f"{'Échecs':>10}"
                f"{'SLA':>15}\n"
            )


            fichier.write(
                "-" * 75 + "\n"
            )


            for nom, stats in statistiques.items():

                sla = slas[nom]

                fichier.write(
                    f"{nom[:25]:25}"
                    f"{stats['total']:>10}"
                    f"{stats['succes']:>10}"
                    f"{stats['echecs']:>10}"
                    f"{sla:>14.3f} %\n"
                )


            fichier.write(
                "-" * 75 + "\n\n"
            )


            # ------------------------------------------------
            # Calcul global
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
                    succes_global /
                    total_global
                ) * 100

            else:

                sla_global = 0.0


            # ------------------------------------------------
            # Résumé global
            # ------------------------------------------------

            fichier.write(
                "Résumé global\n"
            )

            fichier.write(
                "-" * 75 + "\n"
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
            # Comparaison avec l'objectif
            # ------------------------------------------------

            fichier.write(
                "Résultat par rapport à l'objectif\n"
            )

            fichier.write(
                "-" * 75 + "\n"
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
                "=" * 75 + "\n"
            )


        logger.info(
            "Rapport SLA généré : %s",
            FICHIER_RAPPORT
        )


    except Exception as erreur:

        logger.error(
            "Erreur lors de la génération du rapport : %s",
            erreur
        )


# ============================================================
#                    AFFICHAGE CONSOLE
# ============================================================

def afficher_resultat(
    service,
    disponible,
    echecs_consecutifs
):
    """
    Affiche le résultat d'un test dans le terminal.
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
#                  AFFICHAGE CONFIGURATION
# ============================================================

def afficher_configuration():
    """
    Affiche la configuration actuelle.
    """

    print()
    print("=" * 75)
    print(
        "       S4 - SUPERVISION ET ALERTE DES SERVICES"
    )
    print("=" * 75)

    print()

    print(
        f"Dossier du projet : "
        f"{DOSSIER_PROJET}"
    )

    print(
        f"Dossier des logs  : "
        f"{DOSSIER_LOGS}"
    )

    print(
        f"Dossier rapports  : "
        f"{DOSSIER_RAPPORTS}"
    )

    print()

    print(
        f"Intervalle        : "
        f"{INTERVALLE_TEST} secondes"
    )

    print(
        f"Seuil de panne    : "
        f"{SEUIL_ECHECS} échecs"
    )

    print(
        f"Timeout           : "
        f"{TIMEOUT} secondes"
    )

    print(
        f"SLA cible         : "
        f"{SLA_CIBLE:.1f} %"
    )

    print(
        f"Nombre de services: "
        f"{len(SERVICES)}"
    )

    print()

    print("Services surveillés :")

    for service in SERVICES:

        print(
            f"  - {service['nom']} "
            f"({service['ip']}:{service['port']})"
        )

    print()

    if EMAIL_ACTIF:

        print(
            "Alerte e-mail     : ACTIVÉE"
        )

    else:

        print(
            "Alerte e-mail     : DÉSACTIVÉE"
        )

    print()


# ============================================================
#                         MAIN
# ============================================================

def main():

    global PROGRAMME_ACTIF


    # --------------------------------------------------------
    # Affichage configuration
    # --------------------------------------------------------

    afficher_configuration()


    # --------------------------------------------------------
    # Vérification du nombre de services
    # --------------------------------------------------------

    if len(SERVICES) < 3:

        print(
            "ATTENTION : le cahier des charges demande "
            "au moins 3 services."
        )

        logger.warning(
            "Moins de 3 services configurés."
        )


    # --------------------------------------------------------
    # Initialisation statistiques
    # --------------------------------------------------------

    statistiques = {}


    for service in SERVICES:

        nom = service["nom"]

        statistiques[nom] = {
            "total": 0,
            "succes": 0,
            "echecs": 0
        }


    # --------------------------------------------------------
    # Compteur d'échecs consécutifs
    # --------------------------------------------------------

    echecs_consecutifs = {}


    # --------------------------------------------------------
    # État de panne
    # --------------------------------------------------------

    panne_confirmee = {}


    for service in SERVICES:

        nom = service["nom"]

        echecs_consecutifs[nom] = 0

        panne_confirmee[nom] = False


    # --------------------------------------------------------
    # Date de début
    # --------------------------------------------------------

    date_debut = datetime.now()


    logger.info(
        "=" * 60
    )

    logger.info(
        "Démarrage de la supervision."
    )

    logger.info(
        "Intervalle : %s secondes",
        INTERVALLE_TEST
    )

    logger.info(
        "Seuil panne : %s échecs",
        SEUIL_ECHECS
    )


    # --------------------------------------------------------
    # Boucle principale
    # --------------------------------------------------------

    while PROGRAMME_ACTIF:

        print()
        print("-" * 75)

        print(
            "Cycle de supervision - "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        print("-" * 75)


        # ----------------------------------------------------
        # Test de chaque service
        # ----------------------------------------------------

        for service in SERVICES:

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
            #                  SERVICE OK
            # =================================================

            if disponible:

                # Statistiques.
                statistiques[nom]["total"] += 1

                statistiques[nom]["succes"] += 1


                # Sauvegarde de l'ancien compteur.
                ancien_nombre_echecs = (
                    echecs_consecutifs[nom]
                )


                # Remise à zéro.
                echecs_consecutifs[nom] = 0


                # ------------------------------------------------
                # Retour à la normale
                # ------------------------------------------------

                if panne_confirmee[nom]:

                    date_retour = datetime.now()


                    message_incident = (
                        "RETOUR A LA NORMALE | "
                        f"{nom} | "
                        f"{ip}:{port} | "
                        "Service de nouveau disponible | "
                        f"Retour : "
                        f"{date_retour.strftime('%Y-%m-%d %H:%M:%S')}"
                    )


                    logger.info(
                        message_incident
                    )


                    enregistrer_incident(
                        message_incident
                    )


                    # --------------------------------------------
                    # E-mail de récupération
                    # --------------------------------------------

                    sujet = (
                        f"[RECOVERY] {nom} "
                        "est de nouveau disponible"
                    )


                    message = (
                        "RETOUR À LA NORMALE\n\n"

                        f"Service : {nom}\n"
                        f"Adresse : {ip}\n"
                        f"Port : {port}\n\n"

                        "Le service est de nouveau "
                        "disponible.\n\n"

                        f"Heure du retour : "
                        f"{date_retour.strftime('%Y-%m-%d %H:%M:%S')}\n"

                        f"Nombre d'échecs précédents : "
                        f"{ancien_nombre_echecs}\n"
                    )


                    envoyer_email(
                        sujet,
                        message
                    )


                    # Le service n'est plus en panne.
                    panne_confirmee[nom] = False


                else:

                    logger.info(
                        "OK | %s | %s:%s",
                        nom,
                        ip,
                        port
                    )


            # =================================================
            #                SERVICE EN ERREUR
            # =================================================

            else:

                # Statistiques.
                statistiques[nom]["total"] += 1

                statistiques[nom]["echecs"] += 1


                # Incrémentation des échecs consécutifs.
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


                # ------------------------------------------------
                # Détection de la panne
                # ------------------------------------------------

                if (
                    nombre_echecs >= SEUIL_ECHECS
                    and not panne_confirmee[nom]
                ):

                    # La panne est maintenant confirmée.
                    panne_confirmee[nom] = True


                    date_panne = datetime.now()


                    # --------------------------------------------
                    # Message incident
                    # --------------------------------------------

                    message_incident = (
                        "PANNE CONFIRMEE | "
                        f"{nom} | "
                        f"{ip}:{port} | "
                        f"{nombre_echecs} échecs consécutifs | "
                        "Détection : "
                        f"{date_panne.strftime('%Y-%m-%d %H:%M:%S')}"
                    )


                    # Log principal.
                    logger.error(
                        message_incident
                    )


                    # Log des incidents.
                    enregistrer_incident(
                        message_incident
                    )


                    # --------------------------------------------
                    # Alerte e-mail
                    # --------------------------------------------

                    sujet = (
                        f"[ALERTE PANNE] {nom}"
                    )


                    message = (
                        "ALERTE DE SUPERVISION\n\n"

                        "Une panne a été détectée.\n\n"

                        f"Service : {nom}\n"
                        f"Adresse IP : {ip}\n"
                        f"Port : {port}\n\n"

                        f"Échecs consécutifs : "
                        f"{nombre_echecs}\n"

                        f"Heure de détection : "
                        f"{date_panne.strftime('%Y-%m-%d %H:%M:%S')}\n\n"

                        f"Le service est considéré "
                        f"en panne après "
                        f"{SEUIL_ECHECS} échecs consécutifs."
                    )


                    envoyer_email(
                        sujet,
                        message
                    )


            # ------------------------------------------------
            # Affichage console
            # ------------------------------------------------

            afficher_resultat(
                service,
                disponible,
                echecs_consecutifs[nom]
            )


        # ----------------------------------------------------
        # Attente avant le prochain cycle
        # ----------------------------------------------------

        if PROGRAMME_ACTIF:

            print()

            print(
                f"Prochain test dans "
                f"{INTERVALLE_TEST} secondes..."
            )


            # Attente seconde par seconde.
            #
            # Cela permet d'arrêter rapidement
            # le programme avec Ctrl+C.

            temps_ecoule = 0


            while (
                temps_ecoule < INTERVALLE_TEST
                and PROGRAMME_ACTIF
            ):

                time.sleep(1)

                temps_ecoule += 1


    # ========================================================
    #                      FIN DU PROGRAMME
    # ========================================================

    date_fin = datetime.now()


    print()
    print("=" * 75)

    print(
        "Fin de la supervision."
    )

    print(
        "Génération du rapport SLA..."
    )

    print("=" * 75)


    logger.info(
        "Fin de la supervision."
    )


    # --------------------------------------------------------
    # Génération du rapport
    # --------------------------------------------------------

    generer_rapport(
        statistiques,
        date_debut,
        date_fin
    )


    # --------------------------------------------------------
    # Affichage des fichiers
    # --------------------------------------------------------

    print()

    print(
        "Fichiers générés :"
    )

    print()

    print(
        f"  supervision.log :\n"
        f"  {FICHIER_LOG}"
    )

    print()

    print(
        f"  incidents.log :\n"
        f"  {FICHIER_INCIDENTS}"
    )

    print()

    print(
        f"  rapport_sla.txt :\n"
        f"  {FICHIER_RAPPORT}"
    )

    print()

    print(
        "Supervision terminée."
    )


# ============================================================
#                     LANCEMENT DU SCRIPT
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
