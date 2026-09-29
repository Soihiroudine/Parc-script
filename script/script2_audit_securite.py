#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
============================================================
S2 - AUDIT DE CONFORMITÉ SÉCURITÉ DES SERVEURS
============================================================

Fichier :
    script2_audit_securite.py

Structure attendue :

    projet/
    ├── script2_audit_securite.py
    │
    ├── base/
    │   └── rapport_conformite.html
    │
    ├── logs/
    │
    └── rapports/
        └── audi_securite/

Contrôles réalisés :

    1. SSH sur un port non standard
    2. PermitRootLogin désactivé
    3. Authentification SSH par clé publique
    4. Firewall actif
       - UFW
       - nftables
       - iptables
    5. Mises à jour disponibles
       - APT
       - DNF
    6. Journaux système présents

Fichiers générés :

    logs/
        audit_securite_AAAA-MM-JJ_HH-MM-SS.log

    rapports/audi_securite/
        audit_securite_AAAA-MM-JJ.txt
        rapport_conformite.html

Usage :

    python3 script2_audit_securite.py

ou :

    sudo python3 script2_audit_securite.py

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
# CHEMINS
# ============================================================

# Répertoire contenant le script
SCRIPT_DIR = Path(
    __file__
).resolve().parent

# Template HTML
BASE_DIR = SCRIPT_DIR / "base"

BASE_HTML = (
    BASE_DIR /
    "rapport_conformite.html"
)

# Répertoire des logs
LOG_DIR = SCRIPT_DIR / "logs"

# Répertoire des rapports
REPORT_DIR = (
    SCRIPT_DIR /
    "rapports" /
    "audi_securite"
)

# Configuration SSH
SSH_CONFIG = Path(
    "/etc/ssh/sshd_config"
)


# ============================================================
# CONFIGURATION
# ============================================================

# Ports SSH considérés comme standards
STANDARD_SSH_PORTS = {
    22
}

# Fichiers de logs Linux possibles
LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
]


# ============================================================
# LOGGING
# ============================================================

def setup_logging():
    """
    Configure le système de logs.

    Un fichier différent est créé à chaque exécution :

        logs/audit_securite_AAAA-MM-JJ_HH-MM-SS.log

    Les messages sont :
        - écrits dans le fichier
        - affichés dans le terminal
    """

    # Création du dossier logs
    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # Timestamp de l'exécution
    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    # Nom du fichier
    log_file = (
        LOG_DIR /
        f"audit_securite_{timestamp}.log"
    )

    # Configuration du logging
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
        "DÉMARRAGE DE L'AUDIT DE CONFORMITÉ SÉCURITÉ"
    )

    logging.info(
        "=" * 70
    )

    logging.info(
        "Fichier log : %s",
        log_file
    )

    return log_file


# ============================================================
# EXÉCUTION DES COMMANDES
# ============================================================

def run_command(command, timeout=15):
    """
    Exécute une commande système.

    Retour :
        code retour
        stdout
        stderr
    """

    logging.debug(
        "Exécution commande : %s",
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
            "Erreur commande : %s",
            command
        )

        return (
            -1,
            "",
            str(exc)
        )


def command_exists(command):
    """
    Vérifie qu'une commande existe.
    """

    code, _, _ = run_command(
        f"command -v {command}"
    )

    return code == 0


# ============================================================
# STATUTS
# ============================================================

def status_text(status):
    """
    Convertit un statut interne en texte lisible.
    """

    statuses = {
        "OK": "OK",
        "WARNING": "AVERTISSEMENT",
        "KO": "NON CONFORME"
    }

    return statuses.get(
        status,
        status
    )


def status_color(status):
    """
    Retourne la couleur associée au statut.
    """

    colors = {
        "OK": "#198754",
        "WARNING": "#f0ad00",
        "KO": "#dc3545"
    }

    return colors.get(
        status,
        "#6c757d"
    )


# ============================================================
# INFORMATIONS SYSTÈME
# ============================================================

def get_system_info():
    """
    Récupère les informations générales
    du serveur.
    """

    logging.info(
        "Collecte des informations système"
    )

    # --------------------------------------------------------
    # Hostname
    # --------------------------------------------------------

    hostname = socket.gethostname()

    # --------------------------------------------------------
    # OS
    # --------------------------------------------------------

    code, os_info, _ = run_command(
        "grep '^PRETTY_NAME=' /etc/os-release "
        "| cut -d= -f2-"
    )

    if code == 0 and os_info:

        os_info = os_info.strip(
            '"'
        )

    else:

        os_info = "Linux"

    # --------------------------------------------------------
    # Kernel
    # --------------------------------------------------------

    code, kernel, _ = run_command(
        "uname -r"
    )

    if not kernel:

        kernel = "Inconnu"

    return {
        "hostname": hostname,
        "os": os_info,
        "kernel": kernel
    }


# ============================================================
# CONFIGURATION SSH EFFECTIVE
# ============================================================

def get_sshd_effective_config():
    """
    Récupère la configuration SSH effective
    avec sshd -T.

    Cela permet de tenir compte de certaines
    directives Include.
    """

    logging.info(
        "Lecture de la configuration SSH effective"
    )

    if not command_exists("sshd"):

        logging.warning(
            "Commande sshd introuvable"
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
# CONTRÔLE 1 - PORT SSH
# ============================================================

def check_ssh_port():
    """
    Vérifie que SSH utilise un port différent
    du port standard 22.
    """

    logging.info(
        "Contrôle 1 : port SSH non standard"
    )

    # --------------------------------------------------------
    # Configuration effective
    # --------------------------------------------------------

    config = get_sshd_effective_config()

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
                    "Port SSH détecté : %d",
                    port
                )

                if port not in STANDARD_SSH_PORTS:

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
                    "Valeur du port SSH invalide : %s",
                    port_value
                )

    # --------------------------------------------------------
    # Fallback sshd_config
    # --------------------------------------------------------

    try:

        content = SSH_CONFIG.read_text(
            encoding="utf-8"
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
                and parts[0].lower() == "port"
            ):

                try:

                    ports.append(
                        int(parts[1])
                    )

                except ValueError:

                    continue

        if ports:

            port = ports[0]

            logging.info(
                "Port SSH détecté dans sshd_config : %d",
                port
            )

            if port not in STANDARD_SSH_PORTS:

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
# CONTRÔLE 2 - ROOT LOGIN
# ============================================================

def check_ssh_root_login():
    """
    Vérifie que PermitRootLogin est configuré
    sur 'no'.
    """

    logging.info(
        "Contrôle 2 : PermitRootLogin"
    )

    config = get_sshd_effective_config()

    if config:

        value = config.get(
            "permitrootlogin",
            ""
        ).lower()

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

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    try:

        content = SSH_CONFIG.read_text(
            encoding="utf-8"
        )

        for line in content.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            parts = line.split(
                None,
                1
            )

            if (
                len(parts) == 2
                and parts[0].lower()
                == "permitrootlogin"
            ):

                value = (
                    parts[1]
                    .strip()
                    .lower()
                )

                if value == "no":

                    return {
                        "name":
                            "SSH - PermitRootLogin",

                        "status":
                            "OK",

                        "details":
                            "Connexion SSH directe "
                            "de root désactivée"
                    }

                return {
                    "name":
                        "SSH - PermitRootLogin",

                    "status":
                        "KO",

                    "details":
                        f"PermitRootLogin = {value}"
                }

    except FileNotFoundError:

        pass

    except PermissionError:

        logging.warning(
            "Permission refusée pour sshd_config"
        )

    return {
        "name":
            "SSH - PermitRootLogin",

        "status":
            "WARNING",

        "details":
            "Configuration SSH introuvable"
    }


# ============================================================
# CONTRÔLE 3 - CLÉ PUBLIQUE
# ============================================================

def check_ssh_public_key():
    """
    Vérifie que l'authentification SSH
    par clé publique est activée.
    """

    logging.info(
        "Contrôle 3 : authentification par clé publique"
    )

    config = get_sshd_effective_config()

    if config:

        value = config.get(
            "pubkeyauthentication",
            ""
        ).lower()

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

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    try:

        content = SSH_CONFIG.read_text(
            encoding="utf-8"
        )

        for line in content.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            parts = line.split(
                None,
                1
            )

            if (
                len(parts) == 2
                and parts[0].lower()
                == "pubkeyauthentication"
            ):

                value = (
                    parts[1]
                    .strip()
                    .lower()
                )

                if value == "yes":

                    return {
                        "name":
                            "SSH - Authentification "
                            "par clé publique",

                        "status":
                            "OK",

                        "details":
                            "PubkeyAuthentication activé"
                    }

                return {
                    "name":
                        "SSH - Authentification "
                        "par clé publique",

                    "status":
                        "KO",

                    "details":
                        f"PubkeyAuthentication = {value}"
                }

    except FileNotFoundError:

        pass

    except PermissionError:

        logging.warning(
            "Permission refusée pour sshd_config"
        )

    return {
        "name":
            "SSH - Authentification par clé publique",

        "status":
            "WARNING",

        "details":
            "Configuration SSH introuvable"
    }


# ============================================================
# CONTRÔLE 4 - FIREWALL
# ============================================================

def check_firewall():
    """
    Vérifie si un firewall actif est présent.

    Ordre de vérification :

        UFW
        nftables
        iptables
    """

    logging.info(
        "Contrôle 4 : firewall"
    )

    # --------------------------------------------------------
    # UFW
    # --------------------------------------------------------

    if command_exists("ufw"):

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

        logging.info(
            "UFW n'est pas actif"
        )

    # --------------------------------------------------------
    # nftables
    # --------------------------------------------------------

    if command_exists("nft"):

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
                    "nftables contient des règles actives"
            }

        logging.info(
            "Aucune règle nftables détectée"
        )

    # --------------------------------------------------------
    # iptables
    # --------------------------------------------------------

    if command_exists("iptables"):

        logging.info(
            "iptables détecté"
        )

        code, stdout, stderr = run_command(
            "iptables -L -n"
        )

        if code == 0:

            lines = stdout.splitlines()

            rules = []

            for line in lines:

                if not line.strip():
                    continue

                if line.startswith("Chain"):
                    continue

                if line.startswith("target"):
                    continue

                rules.append(line)

            if rules:

                return {
                    "name":
                        "Firewall",

                    "status":
                        "OK",

                    "details":
                        "iptables contient des règles"
                }

        logging.info(
            "Aucune règle iptables exploitable détectée"
        )

    return {
        "name":
            "Firewall",

        "status":
            "KO",

        "details":
            "Aucun firewall actif détecté"
    }


# ============================================================
# CONTRÔLE 5 - MISES À JOUR
# ============================================================

def check_security_updates():
    """
    Vérifie si des mises à jour sont disponibles.

    Support :

        Debian / Ubuntu
            apt

        RHEL / Fedora / CentOS
            dnf
    """

    logging.info(
        "Contrôle 5 : mises à jour"
    )

    # --------------------------------------------------------
    # APT
    # --------------------------------------------------------

    if command_exists("apt"):

        logging.info(
            "Gestionnaire APT détecté"
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

            logging.info(
                "Aucune mise à jour détectée"
            )

            return {
                "name":
                    "Mises à jour de sécurité",

                "status":
                    "OK",

                "details":
                    "Aucune mise à jour disponible détectée"
            }

        logging.warning(
            "Impossible d'interroger APT"
        )

        return {
            "name":
                "Mises à jour de sécurité",

            "status":
                "WARNING",

            "details":
                "Impossible de déterminer "
                "les mises à jour APT"
        }

    # --------------------------------------------------------
    # DNF
    # --------------------------------------------------------

    if command_exists("dnf"):

        logging.info(
            "Gestionnaire DNF détecté"
        )

        code, stdout, stderr = run_command(
            "dnf check-update",
            timeout=30
        )

        # DNF retourne 100 lorsqu'il existe
        # des mises à jour disponibles
        if code == 100:

            logging.warning(
                "Des mises à jour sont disponibles"
            )

            return {
                "name":
                    "Mises à jour de sécurité",

                "status":
                    "WARNING",

                "details":
                    "Des mises à jour sont disponibles"
            }

        if code == 0:

            logging.info(
                "Aucune mise à jour détectée"
            )

            return {
                "name":
                    "Mises à jour de sécurité",

                "status":
                    "OK",

                "details":
                    "Aucune mise à jour disponible détectée"
            }

        logging.warning(
            "Impossible d'interroger DNF"
        )

        return {
            "name":
                "Mises à jour de sécurité",

            "status":
                "WARNING",

            "details":
                "Impossible de déterminer "
                "les mises à jour DNF"
        }

    # --------------------------------------------------------
    # Gestionnaire inconnu
    # --------------------------------------------------------

    logging.warning(
        "Aucun gestionnaire de paquets reconnu"
    )

    return {
        "name":
            "Mises à jour de sécurité",

        "status":
            "WARNING",

        "details":
            "Gestionnaire de paquets non reconnu"
    }


# ============================================================
# CONTRÔLE 6 - JOURNAUX
# ============================================================

def check_logs():
    """
    Vérifie la présence de journaux système.

    Vérifie :

        /var/log/auth.log
        /var/log/secure
        /var/log/syslog
        /var/log/messages

    ainsi que journald.
    """

    logging.info(
        "Contrôle 6 : journaux système"
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
                and path.stat().st_size > 0
            ):

                existing_logs.append(
                    log_file
                )

                logging.info(
                    "Journal détecté : %s",
                    log_file
                )

        except PermissionError:

            logging.warning(
                "Permission refusée : %s",
                log_file
            )

    # --------------------------------------------------------
    # journald
    # --------------------------------------------------------

    journald_active = False

    if command_exists(
        "journalctl"
    ):

        code, stdout, stderr = run_command(
            "journalctl --no-pager -n 5 2>/dev/null"
        )

        if (
            code == 0
            and stdout.strip()
        ):

            journald_active = True

            logging.info(
                "journald actif"
            )

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
                + ", ".join(existing_logs)
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
                " ; ".join(details)
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
# AUDIT COMPLET
# ============================================================

def run_audit():
    """
    Exécute tous les contrôles de sécurité.
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
            "--------------------------------------------------"
        )

        logging.info(
            "Exécution : %s",
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
                "Critère : %s",
                result["name"]
            )

            logging.info(
                "Détail : %s",
                result["details"]
            )

        except Exception as exc:

            logging.exception(
                "Erreur pendant le contrôle : %s",
                check.__name__
            )

            result = {
                "name":
                    check.__name__,

                "status":
                    "WARNING",

                "details":
                    f"Erreur pendant le contrôle : {exc}"
            }

            results.append(
                result
            )

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

def calculate_score(results):
    """
    Calcule un score indicatif.

    OK :
        100 points

    AVERTISSEMENT :
        50 points

    KO :
        0 point
    """

    if not results:

        return 0

    total = 0

    for result in results:

        status = result[
            "status"
        ]

        if status == "OK":

            total += 100

        elif status == "WARNING":

            total += 50

        elif status == "KO":

            total += 0

    return round(
        total / len(results)
    )


# ============================================================
# RAPPORT TEXTE
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
        "Génération du rapport texte"
    )

    now = datetime.now()

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
    # Construction du rapport
    # --------------------------------------------------------

    lines = []

    lines.append(
        "=" * 70
    )

    lines.append(
        "AUDIT DE CONFORMITÉ SÉCURITÉ - SERVEUR LINUX"
    )

    lines.append(
        "=" * 70
    )

    lines.append("")

    lines.append(
        "Date       : "
        + now.strftime(
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
        "Rapport généré automatiquement par "
        "script2_audit_securite.py"
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
        "Rapport texte créé : %s",
        output_file
    )


# ============================================================
# RAPPORT HTML À PARTIR DU TEMPLATE
# ============================================================

def generate_html_report(
    results,
    system_info,
    score,
    output_file
):
    """
    Génère le rapport HTML à partir du template :

        base/rapport_conformite.html

    Le template contient des variables :

        {{TITLE}}
        {{SUBTITLE}}
        {{HOSTNAME}}
        {{OS}}
        {{KERNEL}}
        {{DATE}}
        {{GLOBAL_COLOR}}
        {{GLOBAL_STATUS}}
        {{SCORE}}
        {{OK_COUNT}}
        {{WARNING_COUNT}}
        {{KO_COUNT}}
        {{RESULTS_ROWS}}
    """

    logging.info(
        "Chargement du template HTML : %s",
        BASE_HTML
    )

    # --------------------------------------------------------
    # Vérification du template
    # --------------------------------------------------------

    if not BASE_HTML.exists():

        raise FileNotFoundError(
            "Template HTML introuvable : "
            f"{BASE_HTML}"
        )

    if not BASE_HTML.is_file():

        raise FileNotFoundError(
            "Le template HTML n'est pas un fichier : "
            f"{BASE_HTML}"
        )

    # --------------------------------------------------------
    # Lecture du template
    # --------------------------------------------------------

    template = BASE_HTML.read_text(
        encoding="utf-8"
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

        global_status = "OK"

        global_color = (
            "#198754"
        )

    # --------------------------------------------------------
    # Lignes du tableau HTML
    # --------------------------------------------------------

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
                    result["name"]
                )}
            </td>

            <td>

                <span
                    class="badge"
                    style="background-color:{color}"
                >
                    {html.escape(
                        status
                    )}
                </span>

            </td>

            <td>
                {html.escape(
                    result["details"]
                )}
            </td>

        </tr>
        """

        rows.append(
            row
        )

    results_rows = "\n".join(
        rows
    )

    # --------------------------------------------------------
    # Variables du template
    # --------------------------------------------------------

    variables = {

        "{{TITLE}}":
            "Rapport de conformité sécurité",

        "{{SUBTITLE}}":
            "Serveur Linux - "
            "Checklist simplifiée sécurité",

        "{{HOSTNAME}}":
            html.escape(
                system_info["hostname"]
            ),

        "{{OS}}":
            html.escape(
                system_info["os"]
            ),

        "{{KERNEL}}":
            html.escape(
                system_info["kernel"]
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

    # --------------------------------------------------------
    # Remplacement des variables
    # --------------------------------------------------------

    report = template

    for variable, value in variables.items():

        if variable not in report:

            logging.warning(
                "Variable absente du template : %s",
                variable
            )

        report = report.replace(
            variable,
            value
        )

    # --------------------------------------------------------
    # Écriture du rapport
    # --------------------------------------------------------

    output_file.write_text(
        report,
        encoding="utf-8"
    )

    logging.info(
        "Rapport HTML créé : %s",
        output_file
    )


# ============================================================
# VALIDATION DES DOSSIERS
# ============================================================

def prepare_directories():
    """
    Crée les répertoires nécessaires.
    """

    logging.info(
        "Préparation des répertoires"
    )

    # Logs
    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # Rapports
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # Base
    if not BASE_DIR.exists():

        raise FileNotFoundError(
            "Le dossier base est introuvable : "
            f"{BASE_DIR}"
        )

    logging.info(
        "Dossier logs    : %s",
        LOG_DIR
    )

    logging.info(
        "Dossier rapports : %s",
        REPORT_DIR
    )

    logging.info(
        "Dossier base    : %s",
        BASE_DIR
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
    Affiche le résumé de l'audit dans le terminal.
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
# MAIN
# ============================================================

def main():
    """
    Fonction principale.
    """

    # --------------------------------------------------------
    # Initialisation du logging
    # --------------------------------------------------------

    log_file = setup_logging()

    try:

        logging.info(
            "Initialisation du script"
        )

        logging.info(
            "Répertoire du script : %s",
            SCRIPT_DIR
        )

        # ----------------------------------------------------
        # Préparation des dossiers
        # ----------------------------------------------------

        prepare_directories()

        # ----------------------------------------------------
        # Informations système
        # ----------------------------------------------------

        system_info = get_system_info()

        logging.info(
            "Serveur : %s",
            system_info["hostname"]
        )

        logging.info(
            "Système : %s",
            system_info["os"]
        )

        logging.info(
            "Kernel : %s",
            system_info["kernel"]
        )

        # ----------------------------------------------------
        # Noms des rapports
        # ----------------------------------------------------

        today = datetime.now().strftime(
            "%Y-%m-%d"
        )

        text_file = (
            REPORT_DIR /
            f"audit_securite_{today}.txt"
        )

        html_file = (
            REPORT_DIR /
            "rapport_conformite.html"
        )

        logging.info(
            "Rapport TXT : %s",
            text_file
        )

        logging.info(
            "Rapport HTML : %s",
            html_file
        )

        # ----------------------------------------------------
        # Exécution audit
        # ----------------------------------------------------

        results = run_audit()

        # ----------------------------------------------------
        # Calcul score
        # ----------------------------------------------------

        score = calculate_score(
            results
        )

        logging.info(
            "Score indicatif calculé : %d%%",
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

        logging.info(
            "Audit terminé avec succès"
        )

        logging.info(
            "Rapport TXT : %s",
            text_file
        )

        logging.info(
            "Rapport HTML : %s",
            html_file
        )

        logging.info(
            "Fichier LOG : %s",
            log_file
        )

        return 0

    except KeyboardInterrupt:

        logging.warning(
            "Audit interrompu par l'utilisateur"
        )

        print(
            "\n[!] Audit interrompu."
        )

        return 130

    except Exception as exc:

        logging.exception(
            "ERREUR FATALE PENDANT L'AUDIT"
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
            f"Consultez le log : {log_file}"
        )

        return 1


# ============================================================
# POINT D'ENTRÉE
# ============================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )
