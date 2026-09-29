#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
============================================================
AUDIT DE CONFORMITÉ SÉCURITÉ
============================================================

Arborescence attendue :

mon_projet/
│
├── script/
│   └── script2_audit_securite.py
│
├── base/
│   └── rapport_conformite.html
│
├── logs/
│
└── rapports/
    └── audi_securite/

Le script utilise automatiquement la racine du projet :

    mon_projet/

Les fichiers sont générés dans :

    Logs :
        mon_projet/logs/

    Rapports :
        mon_projet/rapports/audi_securite/

Le template HTML est chargé depuis :

    mon_projet/base/rapport_conformite.html

============================================================
"""

# ============================================================
# IMPORTS
# ============================================================

import sys
import html
import socket
import logging
import subprocess

from datetime import datetime
from pathlib import Path


# ============================================================
# CHEMINS DU PROJET
# ============================================================

"""
Le script se trouve ici :

    mon_projet/script/script2_audit_securite.py

Donc :

    __file__
        ↓
    mon_projet/script/script2_audit_securite.py

    .parent
        ↓
    mon_projet/script/

    .parent.parent
        ↓
    mon_projet/

PROJECT_DIR correspond donc toujours à la racine du projet.
"""

SCRIPT_FILE = (
    Path(__file__)
    .resolve()
)

SCRIPT_DIR = (
    SCRIPT_FILE.parent
)

PROJECT_DIR = (
    SCRIPT_DIR.parent
)


# ============================================================
# DOSSIER BASE
# ============================================================

BASE_DIR = (
    PROJECT_DIR /
    "base"
)


# ============================================================
# TEMPLATE HTML
# ============================================================

BASE_HTML = (
    BASE_DIR /
    "rapport_conformite.html"
)


# ============================================================
# DOSSIER LOGS
# ============================================================

LOG_DIR = (
    PROJECT_DIR /
    "logs"
)


# ============================================================
# DOSSIER RAPPORTS
# ============================================================

REPORT_DIR = (
    PROJECT_DIR /
    "rapports" /
    "audi_securite"
)


# ============================================================
# CONFIGURATION SSH
# ============================================================

SSH_CONFIG = Path(
    "/etc/ssh/sshd_config"
)


# ============================================================
# FICHIERS DE LOGS LINUX
# ============================================================

LOG_FILES = [

    "/var/log/auth.log",

    "/var/log/secure",

    "/var/log/syslog",

    "/var/log/messages",

]


# ============================================================
# PORTS SSH STANDARDS
# ============================================================

STANDARD_SSH_PORTS = {

    22

}


# ============================================================
# INITIALISATION DU LOGGING
# ============================================================

def setup_logging():
    """
    Initialise le système de logs.

    Un nouveau fichier est créé à chaque exécution :

        mon_projet/logs/
            audit_securite_YYYY-MM-DD_HH-MM-SS.log
    """

    # --------------------------------------------------------
    # Création du dossier logs
    # --------------------------------------------------------

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Date / heure
    # --------------------------------------------------------

    timestamp = (
        datetime.now()
        .strftime(
            "%Y-%m-%d_%H-%M-%S"
        )
    )

    # --------------------------------------------------------
    # Fichier log
    # --------------------------------------------------------

    log_file = (
        LOG_DIR /
        f"audit_securite_{timestamp}.log"
    )

    # --------------------------------------------------------
    # Configuration logging
    # --------------------------------------------------------

    logging.basicConfig(

        level=logging.INFO,

        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(message)s"
        ),

        handlers=[

            logging.FileHandler(
                log_file,
                encoding="utf-8"
            ),

            logging.StreamHandler(
                sys.stdout
            )

        ]

    )

    logging.info(
        "=" * 70
    )

    logging.info(
        "DÉMARRAGE DE L'AUDIT DE SÉCURITÉ"
    )

    logging.info(
        "=" * 70
    )

    logging.info(
        "Fichier Python : %s",
        SCRIPT_FILE
    )

    logging.info(
        "Répertoire script : %s",
        SCRIPT_DIR
    )

    logging.info(
        "Racine projet : %s",
        PROJECT_DIR
    )

    logging.info(
        "Template HTML : %s",
        BASE_HTML
    )

    logging.info(
        "Répertoire logs : %s",
        LOG_DIR
    )

    logging.info(
        "Répertoire rapports : %s",
        REPORT_DIR
    )

    logging.info(
        "Fichier log : %s",
        log_file
    )

    return log_file


# ============================================================
# EXÉCUTION D'UNE COMMANDE
# ============================================================

def run_command(
    command,
    timeout=15
):
    """
    Exécute une commande système.

    Retourne :

        code retour
        stdout
        stderr
    """

    logging.debug(
        "Commande : %s",
        command
    )

    try:

        result = subprocess.run(

            command,

            shell=True,

            capture_output=True,

            text=True,

            timeout=timeout

        )

        return (
            result.returncode,
            result.stdout.strip(),
            result.stderr.strip()
        )

    except subprocess.TimeoutExpired:

        logging.warning(
            "Commande expirée : %s",
            command
        )

        return (
            -1,
            "",
            "Commande expirée"
        )

    except Exception as exc:

        logging.exception(
            "Erreur lors de l'exécution : %s",
            command
        )

        return (
            -1,
            "",
            str(exc)
        )


# ============================================================
# VÉRIFICATION D'UNE COMMANDE
# ============================================================

def command_exists(
    command
):
    """
    Vérifie si une commande existe.
    """

    code, _, _ = run_command(
        f"command -v {command}"
    )

    return code == 0


# ============================================================
# COULEUR DU STATUT
# ============================================================

def status_color(
    status
):
    """
    Retourne la couleur associée au statut.
    """

    colors = {

        "OK":
            "#198754",

        "WARNING":
            "#f0ad00",

        "KO":
            "#dc3545"

    }

    return colors.get(
        status,
        "#6c757d"
    )


# ============================================================
# TEXTE DU STATUT
# ============================================================

def status_text(
    status
):
    """
    Convertit un statut interne en texte.
    """

    statuses = {

        "OK":
            "OK",

        "WARNING":
            "AVERTISSEMENT",

        "KO":
            "NON CONFORME"

    }

    return statuses.get(
        status,
        status
    )


# ============================================================
# INFORMATIONS SYSTÈME
# ============================================================

def get_system_info():
    """
    Récupère les informations du serveur.
    """

    logging.info(
        "Collecte des informations système"
    )

    # --------------------------------------------------------
    # Hostname
    # --------------------------------------------------------

    hostname = (
        socket.gethostname()
    )

    # --------------------------------------------------------
    # OS
    # --------------------------------------------------------

    code, os_info, _ = run_command(

        "grep '^PRETTY_NAME=' "
        "/etc/os-release "
        "| cut -d= -f2-"

    )

    if (
        code == 0
        and os_info
    ):

        os_info = (
            os_info
            .strip('"')
        )

    else:

        os_info = (
            "Linux"
        )

    # --------------------------------------------------------
    # Kernel
    # --------------------------------------------------------

    code, kernel, _ = run_command(
        "uname -r"
    )

    if not kernel:

        kernel = (
            "Inconnu"
        )

    return {

        "hostname":
            hostname,

        "os":
            os_info,

        "kernel":
            kernel

    }


# ============================================================
# CONFIGURATION SSH EFFECTIVE
# ============================================================

def get_sshd_effective_config():
    """
    Récupère la configuration SSH effective.

    Utilise :

        sshd -T

    afin de tenir compte notamment
    des fichiers Include.
    """

    logging.info(
        "Lecture de la configuration SSH effective"
    )

    if not command_exists(
        "sshd"
    ):

        logging.warning(
            "La commande sshd est introuvable"
        )

        return None

    code, stdout, stderr = run_command(
        "sshd -T 2>/dev/null"
    )

    if code != 0:

        logging.warning(
            "Impossible de récupérer "
            "la configuration SSH effective"
        )

        return None

    config = {}

    for line in stdout.splitlines():

        parts = line.split(
            None,
            1
        )

        if len(parts) != 2:

            continue

        key, value = parts

        config[
            key.lower()
        ] = value.strip()

    return config


# ============================================================
# CONTRÔLE SSH - PORT
# ============================================================

def check_ssh_port():
    """
    Vérifie que SSH utilise un port
    différent du port standard 22.
    """

    logging.info(
        "Contrôle : port SSH"
    )

    config = (
        get_sshd_effective_config()
    )

    if config:

        port_value = config.get(
            "port"
        )

        if port_value:

            try:

                port = int(
                    port_value
                )

                logging.info(
                    "Port SSH : %d",
                    port
                )

                if port not in (
                    STANDARD_SSH_PORTS
                ):

                    return {

                        "name":
                            "SSH - Port non standard",

                        "status":
                            "OK",

                        "details":
                            f"Port SSH configuré : {port}"

                    }

                return {

                    "name":
                        "SSH - Port non standard",

                    "status":
                        "KO",

                    "details":
                        f"SSH utilise le port standard {port}"

                }

            except ValueError:

                logging.warning(
                    "Port SSH invalide : %s",
                    port_value
                )

    # --------------------------------------------------------
    # Fallback sshd_config
    # --------------------------------------------------------

    try:

        content = (
            SSH_CONFIG.read_text(
                encoding="utf-8"
            )
        )

        ports = []

        for line in content.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            parts = line.split()

            if (
                len(parts) >= 2
                and
                parts[0].lower()
                == "port"
            ):

                try:

                    ports.append(
                        int(parts[1])
                    )

                except ValueError:

                    continue

        if ports:

            port = ports[0]

            if port not in (
                STANDARD_SSH_PORTS
            ):

                return {

                    "name":
                        "SSH - Port non standard",

                    "status":
                        "OK",

                    "details":
                        f"Port SSH configuré : {port}"

                }

            return {

                "name":
                    "SSH - Port non standard",

                "status":
                    "KO",

                "details":
                    f"SSH utilise le port standard {port}"

            }

    except FileNotFoundError:

        logging.warning(
            "Fichier SSH introuvable : %s",
            SSH_CONFIG
        )

    except PermissionError:

        logging.warning(
            "Permission refusée : %s",
            SSH_CONFIG
        )

    return {

        "name":
            "SSH - Port non standard",

        "status":
            "WARNING",

        "details":
            "Impossible de déterminer le port SSH"

    }


# ============================================================
# CONTRÔLE SSH - ROOT
# ============================================================

def check_ssh_root_login():
    """
    Vérifie PermitRootLogin.
    """

    logging.info(
        "Contrôle : PermitRootLogin"
    )

    config = (
        get_sshd_effective_config()
    )

    if config:

        value = (
            config.get(
                "permitrootlogin",
                ""
            )
            .lower()
        )

        logging.info(
            "PermitRootLogin = %s",
            value or "non défini"
        )

        if value == "no":

            return {

                "name":
                    "SSH - PermitRootLogin",

                "status":
                    "OK",

                "details":
                    "Connexion SSH directe de root désactivée"

            }

        return {

            "name":
                "SSH - PermitRootLogin",

            "status":
                "KO",

            "details":
                "PermitRootLogin = "
                + (
                    value
                    if value
                    else "non défini"
                )

        }

    return {

        "name":
            "SSH - PermitRootLogin",

        "status":
            "WARNING",

        "details":
            "Configuration SSH effective indisponible"

    }


# ============================================================
# CONTRÔLE SSH - CLÉ PUBLIQUE
# ============================================================

def check_ssh_public_key():
    """
    Vérifie PubkeyAuthentication.
    """

    logging.info(
        "Contrôle : authentification "
        "par clé publique"
    )

    config = (
        get_sshd_effective_config()
    )

    if config:

        value = (
            config.get(
                "pubkeyauthentication",
                ""
            )
            .lower()
        )

        logging.info(
            "PubkeyAuthentication = %s",
            value or "non défini"
        )

        if value == "yes":

            return {

                "name":
                    "SSH - Authentification par clé publique",

                "status":
                    "OK",

                "details":
                    "PubkeyAuthentication activé"

            }

        return {

            "name":
                "SSH - Authentification par clé publique",

            "status":
                "KO",

            "details":
                "PubkeyAuthentication = "
                + (
                    value
                    if value
                    else "non défini"
                )

        }

    return {

        "name":
            "SSH - Authentification par clé publique",

        "status":
            "WARNING",

        "details":
            "Configuration SSH effective indisponible"

    }


# ============================================================
# CONTRÔLE FIREWALL
# ============================================================

def check_firewall():
    """
    Vérifie si un firewall actif est détecté.

    Vérification :

        1. UFW
        2. nftables
        3. iptables
    """

    logging.info(
        "Contrôle : firewall"
    )

    # --------------------------------------------------------
    # UFW
    # --------------------------------------------------------

    if command_exists(
        "ufw"
    ):

        logging.info(
            "UFW détecté"
        )

        code, stdout, stderr = run_command(
            "ufw status"
        )

        if "Status: active" in stdout:

            return {

                "name":
                    "Firewall",

                "status":
                    "OK",

                "details":
                    "UFW est actif"

            }

    # --------------------------------------------------------
    # NFTABLES
    # --------------------------------------------------------

    if command_exists(
        "nft"
    ):

        logging.info(
            "nftables détecté"
        )

        code, stdout, stderr = run_command(
            "nft list ruleset"
        )

        if (
            code == 0
            and stdout.strip()
        ):

            return {

                "name":
                    "Firewall",

                "status":
                    "OK",

                "details":
                    "nftables contient des règles"

            }

    # --------------------------------------------------------
    # IPTABLES
    # --------------------------------------------------------

    if command_exists(
        "iptables"
    ):

        logging.info(
            "iptables détecté"
        )

        code, stdout, stderr = run_command(
            "iptables -L -n"
        )

        if code == 0:

            lines = (
                stdout.splitlines()
            )

            rules = []

            for line in lines:

                if not line.strip():
                    continue

                if line.startswith(
                    "Chain"
                ):
                    continue

                if line.startswith(
                    "target"
                ):
                    continue

                rules.append(
                    line
                )

            if rules:

                return {

                    "name":
                        "Firewall",

                    "status":
                        "OK",

                    "details":
                        "iptables contient des règles"

                }

    return {

        "name":
            "Firewall",

        "status":
            "KO",

        "details":
            "Aucun firewall actif détecté"

    }


# ============================================================
# CONTRÔLE MISES À JOUR
# ============================================================

def check_security_updates():
    """
    Vérifie les mises à jour disponibles.

    Supporte :

        APT
        DNF
    """

    logging.info(
        "Contrôle : mises à jour"
    )

    # --------------------------------------------------------
    # APT
    # --------------------------------------------------------

    if command_exists(
        "apt"
    ):

        logging.info(
            "APT détecté"
        )

        code, stdout, stderr = run_command(

            "apt list --upgradable 2>/dev/null",

            timeout=30

        )

        if code == 0:

            updates = []

            for line in stdout.splitlines():

                if not line:
                    continue

                if line.startswith(
                    "Listing..."
                ):
                    continue

                updates.append(
                    line
                )

            if updates:

                logging.warning(
                    "%d paquet(s) pouvant être mis à jour",
                    len(updates)
                )

                return {

                    "name":
                        "Mises à jour de sécurité",

                    "status":
                        "WARNING",

                    "details":
                        f"{len(updates)} paquet(s) "
                        "pouvant être mis à jour"

                }

            return {

                "name":
                    "Mises à jour de sécurité",

                "status":
                    "OK",

                "details":
                    "Aucune mise à jour disponible détectée"

            }

        return {

            "name":
                "Mises à jour de sécurité",

            "status":
                "WARNING",

            "details":
                "Impossible d'interroger APT"

        }

    # --------------------------------------------------------
    # DNF
    # --------------------------------------------------------

    if command_exists(
        "dnf"
    ):

        logging.info(
            "DNF détecté"
        )

        code, stdout, stderr = run_command(

            "dnf check-update",

            timeout=30

        )

        if code == 100:

            return {

                "name":
                    "Mises à jour de sécurité",

                "status":
                    "WARNING",

                "details":
                    "Des mises à jour sont disponibles"

            }

        if code == 0:

            return {

                "name":
                    "Mises à jour de sécurité",

                "status":
                    "OK",

                "details":
                    "Aucune mise à jour disponible détectée"

            }

        return {

            "name":
                "Mises à jour de sécurité",

            "status":
                "WARNING",

            "details":
                "Impossible d'interroger DNF"

        }

    return {

        "name":
            "Mises à jour de sécurité",

        "status":
            "WARNING",

        "details":
            "Gestionnaire de paquets non reconnu"

    }


# ============================================================
# CONTRÔLE JOURNAUX
# ============================================================

def check_logs():
    """
    Vérifie les journaux système.
    """

    logging.info(
        "Contrôle : journaux système"
    )

    existing_logs = []

    # --------------------------------------------------------
    # Fichiers de logs
    # --------------------------------------------------------

    for log_file in LOG_FILES:

        path = Path(
            log_file
        )

        try:

            if (
                path.exists()
                and
                path.stat().st_size > 0
            ):

                existing_logs.append(
                    log_file
                )

        except PermissionError:

            logging.warning(
                "Permission refusée : %s",
                log_file
            )

    # --------------------------------------------------------
    # Journald
    # --------------------------------------------------------

    journald_active = False

    if command_exists(
        "journalctl"
    ):

        code, stdout, stderr = run_command(

            "journalctl "
            "--no-pager "
            "-n 5 "
            "2>/dev/null"

        )

        if (
            code == 0
            and
            stdout.strip()
        ):

            journald_active = True

    # --------------------------------------------------------
    # Résultat
    # --------------------------------------------------------

    if (
        existing_logs
        or journald_active
    ):

        details = []

        if existing_logs:

            details.append(
                "logs actifs : "
                + ", ".join(
                    existing_logs
                )
            )

        if journald_active:

            details.append(
                "journald actif"
            )

        return {

            "name":
                "Journaux système",

            "status":
                "OK",

            "details":
                " ; ".join(
                    details
                )

        }

    return {

        "name":
            "Journaux système",

        "status":
            "KO",

        "details":
            "Aucun journal système exploitable détecté"

    }


# ============================================================
# EXÉCUTION DE L'AUDIT
# ============================================================

def run_audit():
    """
    Exécute tous les contrôles.
    """

    logging.info(
        "=" * 70
    )

    logging.info(
        "DÉBUT DES CONTRÔLES"
    )

    logging.info(
        "=" * 70
    )

    results = []

    checks = [

        check_ssh_port,

        check_ssh_root_login,

        check_ssh_public_key,

        check_firewall,

        check_security_updates,

        check_logs,

    ]

    for check in checks:

        logging.info(
            "Contrôle : %s",
            check.__name__
        )

        try:

            result = check()

            results.append(
                result
            )

            logging.info(
                "Résultat : %s",
                result["status"]
            )

            logging.info(
                "Détail : %s",
                result["details"]
            )

        except Exception as exc:

            logging.exception(
                "Erreur pendant %s",
                check.__name__
            )

            results.append({

                "name":
                    check.__name__,

                "status":
                    "WARNING",

                "details":
                    f"Erreur : {exc}"

            })

    logging.info(
        "=" * 70
    )

    logging.info(
        "FIN DES CONTRÔLES"
    )

    logging.info(
        "=" * 70
    )

    return results


# ============================================================
# CALCUL DU SCORE
# ============================================================

def calculate_score(
    results
):
    """
    Calcule un score indicatif :

        OK          = 100
        WARNING     = 50
        KO          = 0
    """

    if not results:

        return 0

    total = 0

    for result in results:

        status = (
            result["status"]
        )

        if status == "OK":

            total += 100

        elif status == "WARNING":

            total += 50

        elif status == "KO":

            total += 0

    return round(
        total /
        len(results)
    )


# ============================================================
# GÉNÉRATION DU RAPPORT TXT
# ============================================================

def generate_text_report(
    results,
    system_info,
    score,
    output_file
):
    """
    Génère le rapport texte.
    """

    logging.info(
        "Génération du rapport TXT"
    )

    # --------------------------------------------------------
    # Statistiques
    # --------------------------------------------------------

    ok_count = sum(

        1

        for result in results

        if result["status"] == "OK"

    )

    warning_count = sum(

        1

        for result in results

        if result["status"] == "WARNING"

    )

    ko_count = sum(

        1

        for result in results

        if result["status"] == "KO"

    )

    # --------------------------------------------------------
    # État global
    # --------------------------------------------------------

    if ko_count > 0:

        global_status = (
            "NON CONFORME"
        )

    elif warning_count > 0:

        global_status = (
            "AVERTISSEMENT"
        )

    else:

        global_status = "OK"

    # --------------------------------------------------------
    # Rapport
    # --------------------------------------------------------

    lines = []

    lines.append(
        "=" * 70
    )

    lines.append(
        "AUDIT DE CONFORMITÉ SÉCURITÉ"
    )

    lines.append(
        "=" * 70
    )

    lines.append("")

    lines.append(
        "Date       : "
        + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    lines.append(
        "Serveur    : "
        + system_info["hostname"]
    )

    lines.append(
        "OS         : "
        + system_info["os"]
    )

    lines.append(
        "Noyau      : "
        + system_info["kernel"]
    )

    lines.append("")

    lines.append(
        "-" * 70
    )

    lines.append(
        "RÉSULTATS DES CONTRÔLES"
    )

    lines.append(
        "-" * 70
    )

    for index, result in enumerate(
        results,
        start=1
    ):

        lines.append("")

        lines.append(
            f"[{index}] {result['name']}"
        )

        lines.append(
            "    Résultat : "
            + status_text(
                result["status"]
            )
        )

        lines.append(
            "    Détail   : "
            + result["details"]
        )

    lines.append("")

    lines.append(
        "-" * 70
    )

    lines.append(
        "SYNTHÈSE"
    )

    lines.append(
        "-" * 70
    )

    lines.append("")

    lines.append(
        f"Contrôles réalisés : {len(results)}"
    )

    lines.append(
        f"OK                 : {ok_count}"
    )

    lines.append(
        f"Avertissements     : {warning_count}"
    )

    lines.append(
        f"Non conformes      : {ko_count}"
    )

    lines.append(
        f"Score indicatif    : {score}%"
    )

    lines.append(
        f"État global        : {global_status}"
    )

    lines.append("")

    lines.append(
        "=" * 70
    )

    lines.append(
        "Rapport généré automatiquement"
    )

    lines.append(
        "=" * 70
    )

    # --------------------------------------------------------
    # Écriture
    # --------------------------------------------------------

    output_file.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    logging.info(
        "Rapport TXT créé : %s",
        output_file
    )


# ============================================================
# GÉNÉRATION DU RAPPORT HTML
# ============================================================

def generate_html_report(
    results,
    system_info,
    score,
    output_file
):
    """
    Génère le rapport HTML à partir du template :

        mon_projet/base/rapport_conformite.html

    Le fichier HTML de base n'est PAS recréé par Python.

    Le script lit le fichier existant, remplace les
    variables et crée le rapport final dans :

        mon_projet/rapports/audi_securite/
    """

    logging.info(
        "Génération du rapport HTML"
    )

    logging.info(
        "Recherche du template : %s",
        BASE_HTML
    )

    # ========================================================
    # VÉRIFICATION DU TEMPLATE
    # ========================================================

    if not BASE_DIR.exists():

        raise FileNotFoundError(

            "Le dossier base est introuvable : "
            f"{BASE_DIR}"

        )

    if not BASE_HTML.exists():

        raise FileNotFoundError(

            "Le fichier rapport_conformite.html "
            "est introuvable : "
            f"{BASE_HTML}"

        )

    if not BASE_HTML.is_file():

        raise FileNotFoundError(

            "rapport_conformite.html n'est pas "
            f"un fichier : {BASE_HTML}"

        )

    logging.info(
        "Template HTML trouvé : %s",
        BASE_HTML
    )

    # ========================================================
    # LECTURE DU TEMPLATE
    # ========================================================

    try:

        template = (
            BASE_HTML.read_text(
                encoding="utf-8"
            )
        )

    except Exception as exc:

        logging.exception(
            "Impossible de lire le template HTML"
        )

        raise RuntimeError(

            "Impossible de lire "
            f"{BASE_HTML} : {exc}"

        ) from exc

    # ========================================================
    # STATISTIQUES
    # ========================================================

    ok_count = sum(

        1

        for result in results

        if result["status"] == "OK"

    )

    warning_count = sum(

        1

        for result in results

        if result["status"] == "WARNING"

    )

    ko_count = sum(

        1

        for result in results

        if result["status"] == "KO"

    )

    # ========================================================
    # ÉTAT GLOBAL
    # ========================================================

    if ko_count > 0:

        global_status = (
            "NON CONFORME"
        )

        global_color = (
            "#dc3545"
        )

    elif warning_count > 0:

        global_status = (
            "AVERTISSEMENT"
        )

        global_color = (
            "#f0ad00"
        )

    else:

        global_status = (
            "OK"
        )

        global_color = (
            "#198754"
        )

    # ========================================================
    # LIGNES DU TABLEAU
    # ========================================================

    rows = []

    for index, result in enumerate(
        results,
        start=1
    ):

        color = status_color(
            result["status"]
        )

        status = status_text(
            result["status"]
        )

        row = f"""
<tr>

    <td>
        {index}
    </td>

    <td>
        {html.escape(
            str(result["name"])
        )}
    </td>

    <td>

        <span
            class="badge"
            style="background-color:{color}"
        >
            {html.escape(
                str(status)
            )}
        </span>

    </td>

    <td>
        {html.escape(
            str(result["details"])
        )}
    </td>

</tr>
"""

        rows.append(
            row
        )

    results_rows = (
        "\n".join(rows)
    )

    # ========================================================
    # VARIABLES DU TEMPLATE
    # ========================================================

    variables = {

        "{{TITLE}}":
            "Rapport de conformité sécurité",

        "{{SUBTITLE}}":
            "Serveur Linux - "
            "Checklist simplifiée sécurité",

        "{{HOSTNAME}}":
            html.escape(
                str(
                    system_info["hostname"]
                )
            ),

        "{{OS}}":
            html.escape(
                str(
                    system_info["os"]
                )
            ),

        "{{KERNEL}}":
            html.escape(
                str(
                    system_info["kernel"]
                )
            ),

        "{{DATE}}":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "{{GLOBAL_COLOR}}":
            global_color,

        "{{GLOBAL_STATUS}}":
            html.escape(
                global_status
            ),

        "{{SCORE}}":
            str(score),

        "{{OK_COUNT}}":
            str(ok_count),

        "{{WARNING_COUNT}}":
            str(warning_count),

        "{{KO_COUNT}}":
            str(ko_count),

        "{{RESULTS_ROWS}}":
            results_rows

    }

    # ========================================================
    # REMPLACEMENT DES VARIABLES
    # ========================================================

    report = template

    for variable, value in (
        variables.items()
    ):

        if variable not in report:

            logging.warning(
                "Variable absente du template : %s",
                variable
            )

        report = report.replace(
            variable,
            value
        )

    # ========================================================
    # ÉCRITURE DU RAPPORT FINAL
    # ========================================================

    try:

        output_file.write_text(

            report,

            encoding="utf-8"

        )

    except Exception as exc:

        logging.exception(
            "Impossible d'écrire le rapport HTML"
        )

        raise RuntimeError(

            "Impossible d'écrire "
            f"{output_file} : {exc}"

        ) from exc

    logging.info(
        "Rapport HTML créé : %s",
        output_file
    )


# ============================================================
# PRÉPARATION DES DOSSIERS
# ============================================================

def prepare_directories():
    """
    Vérifie et crée les dossiers nécessaires.
    """

    logging.info(
        "Préparation des répertoires"
    )

    # --------------------------------------------------------
    # Logs
    # --------------------------------------------------------

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Rapports
    # --------------------------------------------------------

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Base
    # --------------------------------------------------------

    if not BASE_DIR.exists():

        raise FileNotFoundError(

            "Le dossier base est introuvable : "
            f"{BASE_DIR}"

        )

    if not BASE_HTML.exists():

        raise FileNotFoundError(

            "Le template HTML est introuvable : "
            f"{BASE_HTML}"

        )

    logging.info(
        "Dossier base : %s",
        BASE_DIR
    )

    logging.info(
        "Template HTML : %s",
        BASE_HTML
    )

    logging.info(
        "Dossier logs : %s",
        LOG_DIR
    )

    logging.info(
        "Dossier rapports : %s",
        REPORT_DIR
    )


# ============================================================
# AFFICHAGE DU RÉSUMÉ
# ============================================================

def display_summary(
    results,
    score,
    text_file,
    html_file,
    log_file
):
    """
    Affiche le résumé dans le terminal.
    """

    ok_count = sum(

        1

        for result in results

        if result["status"] == "OK"

    )

    warning_count = sum(

        1

        for result in results

        if result["status"] == "WARNING"

    )

    ko_count = sum(

        1

        for result in results

        if result["status"] == "KO"

    )

    print()

    print(
        "=" * 70
    )

    print(
        "RÉSULTAT DE L'AUDIT"
    )

    print(
        "=" * 70
    )

    print()

    for result in results:

        print(

            f"{result['status']:8} | "
            f"{result['name']} | "
            f"{result['details']}"

        )

    print()

    print(
        "-" * 70
    )

    print(
        f"Contrôles réalisés : {len(results)}"
    )

    print(
        f"OK                 : {ok_count}"
    )

    print(
        f"Avertissements     : {warning_count}"
    )

    print(
        f"Non conformes      : {ko_count}"
    )

    print(
        f"Score indicatif    : {score}%"
    )

    print(
        "-" * 70
    )

    print()

    print(
        "Fichiers générés :"
    )

    print(
        f"  TXT  : {text_file}"
    )

    print(
        f"  HTML : {html_file}"
    )

    print(
        f"  LOG  : {log_file}"
    )

    print()

    print(
        "=" * 70
    )


# ============================================================
# FONCTION PRINCIPALE
# ============================================================

def main():
    """
    Fonction principale du programme.
    """

    # --------------------------------------------------------
    # Initialisation logging
    # --------------------------------------------------------

    log_file = setup_logging()

    try:

        # ----------------------------------------------------
        # Préparation
        # ----------------------------------------------------

        prepare_directories()

        # ----------------------------------------------------
        # Informations système
        # ----------------------------------------------------

        system_info = (
            get_system_info()
        )

        logging.info(
            "Serveur : %s",
            system_info["hostname"]
        )

        logging.info(
            "OS : %s",
            system_info["os"]
        )

        logging.info(
            "Kernel : %s",
            system_info["kernel"]
        )

        # ----------------------------------------------------
        # Nom des fichiers
        # ----------------------------------------------------

        date_string = (
            datetime.now()
            .strftime(
                "%Y-%m-%d"
            )
        )

        # ----------------------------------------------------
        # Rapport TXT
        # ----------------------------------------------------

        text_file = (

            REPORT_DIR /

            f"audit_securite_{date_string}.txt"

        )

        # ----------------------------------------------------
        # Rapport HTML
        # ----------------------------------------------------

        html_file = (

            REPORT_DIR /

            "rapport_conformite.html"

        )

        logging.info(
            "Fichier rapport TXT : %s",
            text_file
        )

        logging.info(
            "Fichier rapport HTML : %s",
            html_file
        )

        # ----------------------------------------------------
        # Audit
        # ----------------------------------------------------

        results = (
            run_audit()
        )

        # ----------------------------------------------------
        # Score
        # ----------------------------------------------------

        score = (
            calculate_score(
                results
            )
        )

        logging.info(
            "Score indicatif : %d%%",
            score
        )

        # ----------------------------------------------------
        # Rapport TXT
        # ----------------------------------------------------

        generate_text_report(

            results,

            system_info,

            score,

            text_file

        )

        # ----------------------------------------------------
        # Rapport HTML
        # ----------------------------------------------------

        generate_html_report(

            results,

            system_info,

            score,

            html_file

        )

        # ----------------------------------------------------
        # Résumé
        # ----------------------------------------------------

        display_summary(

            results,

            score,

            text_file,

            html_file,

            log_file

        )

        # ----------------------------------------------------
        # Fin
        # ----------------------------------------------------

        logging.info(
            "=" * 70
        )

        logging.info(
            "AUDIT TERMINÉ AVEC SUCCÈS"
        )

        logging.info(
            "=" * 70
        )

        return 0

    except KeyboardInterrupt:

        logging.warning(
            "Audit interrompu par l'utilisateur"
        )

        print()
        print(
            "[!] Audit interrompu."
        )

        print(
            f"[!] Log : {log_file}"
        )

        return 130

    except Exception as exc:

        logging.exception(
            "ERREUR FATALE"
        )

        print()
        print(
            "[ERREUR] L'audit n'a pas pu "
            "être terminé."
        )

        print(
            f"Détail : {exc}"
        )

        print(
            f"Log : {log_file}"
        )

        return 1


# ============================================================
# POINT D'ENTRÉE
# ============================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )
