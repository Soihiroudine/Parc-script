#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
============================================================
AUDIT DE SÉCURITÉ - WINDOWS / LINUX
============================================================

Arborescence :

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

Le script détecte automatiquement le système :

    Windows
    Linux

Le template HTML est TOUJOURS recherché ici :

    mon_projet/base/rapport_conformite.html

Les logs sont créés ici :

    mon_projet/logs/

Les rapports sont créés ici :

    mon_projet/rapports/audi_securite/

Aucune bibliothèque Python externe n'est nécessaire.
"""

# ============================================================
# IMPORTS
# ============================================================

import sys
import os
import html
import socket
import logging
import platform
import subprocess
import shutil
import re

from pathlib import Path
from datetime import datetime


# ============================================================
# DÉTERMINATION DES CHEMINS
# ============================================================

SCRIPT_FILE = Path(__file__).resolve()

SCRIPT_DIR = SCRIPT_FILE.parent

PROJECT_DIR = SCRIPT_DIR.parent

BASE_DIR = PROJECT_DIR / "base"

BASE_HTML = BASE_DIR / "rapport_conformite.html"

LOG_DIR = PROJECT_DIR / "logs"

REPORT_DIR = PROJECT_DIR / "rapport" / "audi_securite"


# ============================================================
# VARIABLES GLOBALES
# ============================================================

OPERATING_SYSTEM = platform.system().lower()

IS_WINDOWS = OPERATING_SYSTEM == "windows"

IS_LINUX = OPERATING_SYSTEM == "linux"


# ============================================================
# LOGGING
# ============================================================

def setup_logging():
    """
    Création du fichier de log.
    """

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    log_file = (
        LOG_DIR /
        f"audit_securite_{timestamp}.log"
    )

    logger = logging.getLogger()

    logger.setLevel(
        logging.INFO
    )

    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler = logging.FileHandler(
        log_file,
        encoding="utf-8"
    )

    file_handler.setFormatter(
        formatter
    )

    console_handler = logging.StreamHandler(
        sys.stdout
    )

    console_handler.setFormatter(
        formatter
    )

    logger.addHandler(
        file_handler
    )

    logger.addHandler(
        console_handler
    )

    logging.info("=" * 70)
    logging.info("DÉMARRAGE DE L'AUDIT DE SÉCURITÉ")
    logging.info("=" * 70)

    logging.info(
        "Script : %s",
        SCRIPT_FILE
    )

    logging.info(
        "Racine projet : %s",
        PROJECT_DIR
    )

    logging.info(
        "Système détecté : %s",
        platform.system()
    )

    logging.info(
        "Version système : %s",
        platform.version()
    )

    logging.info(
        "Architecture : %s",
        platform.machine()
    )

    logging.info(
        "Template HTML : %s",
        BASE_HTML
    )

    logging.info(
        "Logs : %s",
        LOG_DIR
    )

    logging.info(
        "Rapports : %s",
        REPORT_DIR
    )

    return log_file


# ============================================================
# UTILITAIRE - EXÉCUTION COMMANDE
# ============================================================

def run_command(
    command,
    timeout=30,
    powershell=False
):
    """
    Exécute une commande.

    Retourne :

        return_code
        stdout
        stderr
    """

    try:

        if powershell:

            executable = shutil.which(
                "powershell"
            )

            if executable is None:

                executable = shutil.which(
                    "pwsh"
                )

            if executable is None:

                return (
                    -1,
                    "",
                    "PowerShell introuvable"
                )

            final_command = [
                executable,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command
            ]

        elif isinstance(
            command,
            list
        ):

            final_command = command

        else:

            final_command = command

        result = subprocess.run(
            final_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            shell=False
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
            "Timeout"
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


# ============================================================
# UTILITAIRE - COMMANDE DISPONIBLE
# ============================================================

def command_exists(command):
    """
    Vérifie si une commande existe.
    """

    return shutil.which(
        command
    ) is not None


# ============================================================
# INFORMATIONS SYSTÈME
# ============================================================

def get_system_info():
    """
    Retourne les informations système.
    """

    hostname = socket.gethostname()

    system = platform.system()

    release = platform.release()

    version = platform.version()

    machine = platform.machine()

    processor = platform.processor()

    if IS_WINDOWS:

        code, edition, _ = run_command(
            "(Get-CimInstance Win32_OperatingSystem).Caption",
            powershell=True
        )

        if code == 0 and edition:

            operating_system = edition

        else:

            operating_system = (
                f"{system} {release}"
            )

        code, build, _ = run_command(
            "(Get-CimInstance Win32_OperatingSystem).BuildNumber",
            powershell=True
        )

        if code != 0:

            build = ""

    elif IS_LINUX:

        operating_system = ""

        os_release = Path(
            "/etc/os-release"
        )

        if os_release.exists():

            try:

                content = os_release.read_text(
                    encoding="utf-8"
                )

                for line in content.splitlines():

                    if line.startswith(
                        "PRETTY_NAME="
                    ):

                        operating_system = (
                            line.split(
                                "=",
                                1
                            )[1]
                            .strip()
                            .strip('"')
                        )

                        break

            except Exception:

                pass

        if not operating_system:

            operating_system = (
                f"{system} {release}"
            )

        build = release

    else:

        operating_system = (
            f"{system} {release}"
        )

        build = version

    return {

        "hostname": hostname,

        "os": operating_system,

        "release": release,

        "version": version,

        "build": build,

        "architecture": machine,

        "processor": processor

    }


# ============================================================
# STATUT
# ============================================================

def status_color(status):

    colors = {

        "OK": "#198754",

        "WARNING": "#f0ad00",

        "KO": "#dc3545",

        "N/A": "#6c757d"

    }

    return colors.get(
        status,
        "#6c757d"
    )


def status_text(status):

    values = {

        "OK": "OK",

        "WARNING": "AVERTISSEMENT",

        "KO": "NON CONFORME",

        "N/A": "NON APPLICABLE"

    }

    return values.get(
        status,
        status
    )


# ============================================================
# CRÉATION D'UN RÉSULTAT
# ============================================================

def result(
    name,
    status,
    details,
    category
):
    return {

        "name": name,

        "status": status,

        "details": details,

        "category": category

    }


# ============================================================
# WINDOWS - FIREWALL
# ============================================================

def windows_firewall():

    logging.info(
        "Windows : contrôle du pare-feu"
    )

    command = """
Get-NetFirewallProfile |
Select-Object Name, Enabled |
ConvertTo-Json -Compress
"""

    code, stdout, stderr = run_command(
        command,
        powershell=True
    )

    if code != 0:

        return result(
            "Pare-feu Windows",
            "WARNING",
            "Impossible d'interroger le pare-feu Windows",
            "Windows"
        )

    enabled = []

    disabled = []

    for profile in (
        "Domain",
        "Private",
        "Public"
    ):

        pattern = (
            rf'"Name"\s*:\s*"{profile}".*?'
            rf'"Enabled"\s*:\s*(true|false)'
        )

        match = re.search(
            pattern,
            stdout,
            re.IGNORECASE
        )

        if match:

            value = (
                match.group(1).lower()
                == "true"
            )

            if value:

                enabled.append(
                    profile
                )

            else:

                disabled.append(
                    profile
                )

    if disabled:

        return result(
            "Pare-feu Windows",
            "KO",
            "Profil(s) désactivé(s) : "
            + ", ".join(disabled),
            "Windows"
        )

    if enabled:

        return result(
            "Pare-feu Windows",
            "OK",
            "Profils actifs : "
            + ", ".join(enabled),
            "Windows"
        )

    return result(
        "Pare-feu Windows",
        "WARNING",
        "État des profils impossible à déterminer",
        "Windows"
    )


# ============================================================
# WINDOWS - DEFENDER
# ============================================================

def windows_defender():

    logging.info(
        "Windows : contrôle Microsoft Defender"
    )

    command = """
Get-MpComputerStatus |
Select-Object AntivirusEnabled,
              RealTimeProtectionEnabled,
              AntispywareEnabled,
              AntivirusSignatureAge |
ConvertTo-Json -Compress
"""

    code, stdout, stderr = run_command(
        command,
        powershell=True
    )

    if code != 0:

        return result(
            "Microsoft Defender",
            "WARNING",
            "Impossible d'interroger Microsoft Defender",
            "Windows"
        )

    values = {}

    for key in [
        "AntivirusEnabled",
        "RealTimeProtectionEnabled",
        "AntispywareEnabled",
        "AntivirusSignatureAge"
    ]:

        pattern = (
            rf'"{key}"\s*:\s*'
            rf'(".*?"|true|false|\d+|null)'
        )

        match = re.search(
            pattern,
            stdout,
            re.IGNORECASE
        )

        if match:

            values[key] = (
                match.group(1)
                .strip('"')
            )

    problems = []

    for key in [
        "AntivirusEnabled",
        "RealTimeProtectionEnabled",
        "AntispywareEnabled"
    ]:

        value = values.get(
            key
        )

        if value is not None:

            if value.lower() != "true":

                problems.append(
                    key
                )

    signature_age = values.get(
        "AntivirusSignatureAge"
    )

    if signature_age:

        try:

            if int(
                signature_age
            ) > 7:

                problems.append(
                    "signatures anciennes"
                )

        except ValueError:

            pass

    if problems:

        return result(
            "Microsoft Defender",
            "WARNING",
            "Point(s) à vérifier : "
            + ", ".join(problems),
            "Windows"
        )

    return result(
        "Microsoft Defender",
        "OK",
        "Antivirus, protection temps réel et antispyware actifs",
        "Windows"
    )


# ============================================================
# WINDOWS - RDP
# ============================================================

def windows_rdp():

    logging.info(
        "Windows : contrôle RDP"
    )

    command = """
$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'
(Get-ItemProperty -Path $path -Name fDenyTSConnections).fDenyTSConnections
"""

    code, stdout, stderr = run_command(
        command,
        powershell=True
    )

    if code != 0:

        return result(
            "RDP",
            "WARNING",
            "Impossible de déterminer l'état de RDP",
            "Windows"
        )

    value = stdout.strip()

    if value == "1":

        return result(
            "RDP",
            "OK",
            "RDP est désactivé",
            "Windows"
        )

    if value == "0":

        return result(
            "RDP",
            "WARNING",
            "RDP est activé ; vérifier que son exposition est nécessaire",
            "Windows"
        )

    return result(
        "RDP",
        "WARNING",
        "État RDP inconnu",
        "Windows"
    )


# ============================================================
# WINDOWS - SMBv1
# ============================================================

def windows_smb1():

    logging.info(
        "Windows : contrôle SMBv1"
    )

    command = """
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol |
Select-Object State |
ConvertTo-Json -Compress
"""

    code, stdout, stderr = run_command(
        command,
        powershell=True
    )

    if code != 0:

        return result(
            "SMBv1",
            "WARNING",
            "Impossible de déterminer l'état de SMBv1",
            "Windows"
        )

    if (
        "Disabled" in stdout
        or
        "disabled" in stdout
    ):

        return result(
            "SMBv1",
            "OK",
            "SMBv1 est désactivé",
            "Windows"
        )

    if (
        "Enabled" in stdout
        or
        "enabled" in stdout
    ):

        return result(
            "SMBv1",
            "KO",
            "SMBv1 est activé",
            "Windows"
        )

    return result(
        "SMBv1",
        "WARNING",
        "État de SMBv1 indéterminé",
        "Windows"
    )


# ============================================================
# WINDOWS - UAC
# ============================================================

def windows_uac():

    logging.info(
        "Windows : contrôle UAC"
    )

    command = """
$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
Get-ItemProperty -Path $path |
Select-Object EnableLUA, ConsentPromptBehaviorAdmin |
ConvertTo-Json -Compress
"""

    code, stdout, stderr = run_command(
        command,
        powershell=True
    )

    if code != 0:

        return result(
            "UAC",
            "WARNING",
            "Impossible de contrôler UAC",
            "Windows"
        )

    if '"EnableLUA":1' in stdout.replace(
        " ",
        ""
    ):

        return result(
            "UAC",
            "OK",
            "UAC est activé",
            "Windows"
        )

    return result(
        "UAC",
        "KO",
        "UAC semble désactivé",
        "Windows"
    )


# ============================================================
# WINDOWS - ADMINISTRATEURS LOCAUX
# ============================================================

def windows_local_admins():

    logging.info(
        "Windows : contrôle des administrateurs locaux"
    )

    command = """
Get-LocalGroupMember -Group 'Administrators' |
Select-Object Name, PrincipalSource |
ConvertTo-Json -Compress
"""

    code, stdout, stderr = run_command(
        command,
        powershell=True
    )

    if code != 0:

        return result(
            "Administrateurs locaux",
            "WARNING",
            "Impossible de récupérer les administrateurs locaux",
            "Windows"
        )

    if not stdout:

        return result(
            "Administrateurs locaux",
            "WARNING",
            "Aucun résultat récupéré",
            "Windows"
        )

    members = re.findall(
        r'"Name"\s*:\s*"([^"]+)"',
        stdout
    )

    if not members:

        return result(
            "Administrateurs locaux",
            "WARNING",
            "Liste des administrateurs impossible à analyser",
            "Windows"
        )

    return result(
        "Administrateurs locaux",
        "OK",
        f"{len(members)} membre(s) du groupe Administrators détecté(s)",
        "Windows"
    )


# ============================================================
# WINDOWS - MISES À JOUR
# ============================================================

def windows_updates():

    logging.info(
        "Windows : contrôle des mises à jour"
    )

    command = """
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0")
$result.Updates.Count
"""

    code, stdout, stderr = run_command(
        command,
        timeout=60,
        powershell=True
    )

    if code != 0:

        return result(
            "Mises à jour Windows",
            "WARNING",
            "Impossible d'interroger Windows Update",
            "Windows"
        )

    try:

        count = int(
            stdout.strip()
        )

    except ValueError:

        return result(
            "Mises à jour Windows",
            "WARNING",
            "Nombre de mises à jour impossible à déterminer",
            "Windows"
        )

    if count == 0:

        return result(
            "Mises à jour Windows",
            "OK",
            "Aucune mise à jour non installée détectée",
            "Windows"
        )

    return result(
        "Mises à jour Windows",
        "WARNING",
        f"{count} mise(s) à jour non installée(s) détectée(s)",
        "Windows"
    )


# ============================================================
# WINDOWS - COMPTES LOCAUX
# ============================================================

def windows_accounts():

    logging.info(
        "Windows : contrôle des comptes locaux"
    )

    command = """
Get-LocalUser |
Select-Object Name, Enabled, PasswordRequired, PasswordExpires |
ConvertTo-Json -Compress
"""

    code, stdout, stderr = run_command(
        command,
        powershell=True
    )

    if code != 0:

        return result(
            "Comptes locaux",
            "WARNING",
            "Impossible de récupérer les comptes locaux",
            "Windows"
        )

    users = re.findall(
        r'"Name"\s*:\s*"([^"]+)"',
        stdout
    )

    if not users:

        return result(
            "Comptes locaux",
            "WARNING",
            "Impossible d'analyser les comptes locaux",
            "Windows"
        )

    return result(
        "Comptes locaux",
        "OK",
        f"{len(users)} compte(s) local(aux) détecté(s)",
        "Windows"
    )


# ============================================================
# WINDOWS - SERVICES SENSIBLES
# ============================================================

def windows_services():

    logging.info(
        "Windows : contrôle des services"
    )

    services = [

        "RemoteRegistry",

        "Telnet",

    ]

    suspicious = []

    for service in services:

        command = (
            f"(Get-Service -Name '{service}' "
            f"-ErrorAction SilentlyContinue).Status"
        )

        code, stdout, stderr = run_command(
            command,
            powershell=True
        )

        if (
            code == 0
            and
            stdout.strip().lower() == "running"
        ):

            suspicious.append(
                service
            )

    if suspicious:

        return result(
            "Services sensibles",
            "WARNING",
            "Service(s) sensible(s) actif(s) : "
            + ", ".join(suspicious),
            "Windows"
        )

    return result(
        "Services sensibles",
        "OK",
        "Aucun des services contrôlés n'est actif",
        "Windows"
    )


# ============================================================
# LINUX - SSH
# ============================================================

def linux_sshd_config():

    logging.info(
        "Linux : contrôle de la configuration SSH"
    )

    sshd_config = Path(
        "/etc/ssh/sshd_config"
    )

    if not sshd_config.exists():

        return [

            result(
                "SSH - Configuration",
                "N/A",
                "OpenSSH non configuré ou fichier sshd_config absent",
                "Linux"
            )

        ]

    config = {}

    try:

        content = sshd_config.read_text(
            encoding="utf-8",
            errors="replace"
        )

    except Exception as exc:

        return [

            result(
                "SSH - Configuration",
                "WARNING",
                f"Impossible de lire sshd_config : {exc}",
                "Linux"
            )

        ]

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

        if len(parts) == 2:

            key = parts[0].lower()

            value = parts[1].strip()

            config[key] = value

    results = []

    # --------------------------------------------------------
    # PermitRootLogin
    # --------------------------------------------------------

    root_login = config.get(
        "permitrootlogin"
    )

    if root_login:

        if root_login.lower() == "no":

            results.append(
                result(
                    "SSH - Connexion root",
                    "OK",
                    "PermitRootLogin est désactivé",
                    "Linux"
                )
            )

        else:

            results.append(
                result(
                    "SSH - Connexion root",
                    "KO",
                    f"PermitRootLogin = {root_login}",
                    "Linux"
                )
            )

    else:

        results.append(
            result(
                "SSH - Connexion root",
                "WARNING",
                "PermitRootLogin non explicitement défini",
                "Linux"
            )
        )

    # --------------------------------------------------------
    # PasswordAuthentication
    # --------------------------------------------------------

    password_auth = config.get(
        "passwordauthentication"
    )

    if password_auth:

        if password_auth.lower() == "no":

            results.append(
                result(
                    "SSH - Authentification par mot de passe",
                    "OK",
                    "PasswordAuthentication est désactivé",
                    "Linux"
                )
            )

        else:

            results.append(
                result(
                    "SSH - Authentification par mot de passe",
                    "WARNING",
                    "L'authentification SSH par mot de passe est activée",
                    "Linux"
                )
            )

    else:

        results.append(
            result(
                "SSH - Authentification par mot de passe",
                "WARNING",
                "PasswordAuthentication non explicitement défini",
                "Linux"
            )
        )

    # --------------------------------------------------------
    # PubkeyAuthentication
    # --------------------------------------------------------

    pubkey = config.get(
        "pubkeyauthentication"
    )

    if pubkey:

        if pubkey.lower() == "yes":

            results.append(
                result(
                    "SSH - Authentification par clé",
                    "OK",
                    "PubkeyAuthentication est activé",
                    "Linux"
                )
            )

        else:

            results.append(
                result(
                    "SSH - Authentification par clé",
                    "WARNING",
                    "PubkeyAuthentication est désactivé",
                    "Linux"
                )
            )

    else:

        results.append(
            result(
                "SSH - Authentification par clé",
                "WARNING",
                "PubkeyAuthentication non explicitement défini",
                "Linux"
            )
        )

    # --------------------------------------------------------
    # Port SSH
    # --------------------------------------------------------

    port = config.get(
        "port"
    )

    if port:

        try:

            port_number = int(
                port
            )

            if port_number != 22:

                results.append(
                    result(
                        "SSH - Port",
                        "OK",
                        f"Port SSH configuré : {port_number}",
                        "Linux"
                    )
                )

            else:

                results.append(
                    result(
                        "SSH - Port",
                        "WARNING",
                        "SSH utilise le port standard 22",
                        "Linux"
                    )
                )

        except ValueError:

            results.append(
                result(
                    "SSH - Port",
                    "WARNING",
                    f"Port SSH invalide : {port}",
                    "Linux"
                )
            )

    return results


# ============================================================
# LINUX - FIREWALL
# ============================================================

def linux_firewall():

    logging.info(
        "Linux : contrôle du firewall"
    )

    # UFW
    if command_exists(
        "ufw"
    ):

        code, stdout, stderr = run_command(
            ["ufw", "status"]
        )

        if "Status: active" in stdout:

            return result(
                "Firewall",
                "OK",
                "UFW est actif",
                "Linux"
            )

    # firewalld
    if command_exists(
        "firewall-cmd"
    ):

        code, stdout, stderr = run_command(
            [
                "firewall-cmd",
                "--state"
            ]
        )

        if stdout.strip() == "running":

            return result(
                "Firewall",
                "OK",
                "firewalld est actif",
                "Linux"
            )

    # nftables
    if command_exists(
        "nft"
    ):

        code, stdout, stderr = run_command(
            [
                "nft",
                "list",
                "ruleset"
            ]
        )

        if code == 0 and stdout.strip():

            return result(
                "Firewall",
                "OK",
                "nftables contient des règles",
                "Linux"
            )

    # iptables
    if command_exists(
        "iptables"
    ):

        code, stdout, stderr = run_command(
            [
                "iptables",
                "-L",
                "-n"
            ]
        )

        if code == 0:

            lines = []

            for line in stdout.splitlines():

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

                lines.append(
                    line
                )

            if lines:

                return result(
                    "Firewall",
                    "OK",
                    "iptables contient des règles",
                    "Linux"
                )

    return result(
        "Firewall",
        "KO",
        "Aucun firewall actif détecté",
        "Linux"
    )


# ============================================================
# LINUX - MISES À JOUR
# ============================================================

def linux_updates():

    logging.info(
        "Linux : contrôle des mises à jour"
    )

    # Debian / Ubuntu
    if command_exists(
        "apt"
    ):

        code, stdout, stderr = run_command(
            [
                "apt",
                "list",
                "--upgradable"
            ],
            timeout=60
        )

        if code == 0:

            updates = []

            for line in stdout.splitlines():

                if line.startswith(
                    "Listing..."
                ):
                    continue

                if line.strip():

                    updates.append(
                        line
                    )

            if updates:

                return result(
                    "Mises à jour",
                    "WARNING",
                    f"{len(updates)} paquet(s) pouvant être mis à jour",
                    "Linux"
                )

            return result(
                "Mises à jour",
                "OK",
                "Aucune mise à jour détectée",
                "Linux"
            )

    # RHEL / Rocky / Alma / Fedora
    for manager in [
        "dnf",
        "yum"
    ]:

        if command_exists(
            manager
        ):

            code, stdout, stderr = run_command(
                [
                    manager,
                    "check-update"
                ],
                timeout=60
            )

            if code == 100:

                return result(
                    "Mises à jour",
                    "WARNING",
                    "Des mises à jour sont disponibles",
                    "Linux"
                )

            if code == 0:

                return result(
                    "Mises à jour",
                    "OK",
                    "Aucune mise à jour détectée",
                    "Linux"
                )

            return result(
                "Mises à jour",
                "WARNING",
                f"Impossible d'interroger {manager}",
                "Linux"
            )

    return result(
        "Mises à jour",
        "WARNING",
        "Gestionnaire de paquets non reconnu",
        "Linux"
    )


# ============================================================
# LINUX - JOURNAUX
# ============================================================

def linux_logs():

    logging.info(
        "Linux : contrôle des journaux"
    )

    paths = [

        "/var/log/auth.log",

        "/var/log/secure",

        "/var/log/syslog",

        "/var/log/messages"

    ]

    existing = []

    for path_string in paths:

        path = Path(
            path_string
        )

        try:

            if (
                path.exists()
                and
                path.stat().st_size > 0
            ):

                existing.append(
                    path_string
                )

        except PermissionError:

            logging.warning(
                "Permission refusée : %s",
                path_string
            )

    if command_exists(
        "journalctl"
    ):

        code, stdout, stderr = run_command(
            [
                "journalctl",
                "--no-pager",
                "-n",
                "5"
            ]
        )

        if code == 0 and stdout:

            return result(
                "Journaux système",
                "OK",
                "journald est disponible",
                "Linux"
            )

    if existing:

        return result(
            "Journaux système",
            "OK",
            "Journal(s) détecté(s) : "
            + ", ".join(existing),
            "Linux"
        )

    return result(
        "Journaux système",
        "WARNING",
        "Aucun journal système exploitable détecté",
        "Linux"
    )


# ============================================================
# LINUX - PERMISSIONS SSH
# ============================================================

def linux_ssh_permissions():

    logging.info(
        "Linux : contrôle des permissions SSH"
    )

    sshd_config = Path(
        "/etc/ssh/sshd_config"
    )

    if not sshd_config.exists():

        return result(
            "Permissions SSH",
            "N/A",
            "sshd_config absent",
            "Linux"
        )

    try:

        mode = (
            sshd_config.stat()
            .st_mode
        )

        permissions = (
            oct(
                mode & 0o777
            )
        )

        if (
            mode & 0o002
            or
            mode & 0o020
        ):

            return result(
                "Permissions SSH",
                "KO",
                f"sshd_config est trop permissif : {permissions}",
                "Linux"
            )

        return result(
            "Permissions SSH",
            "OK",
            f"Permissions sshd_config : {permissions}",
            "Linux"
        )

    except Exception as exc:

        return result(
            "Permissions SSH",
            "WARNING",
            f"Impossible de vérifier les permissions : {exc}",
            "Linux"
        )


# ============================================================
# LINUX - UTILISATEUR ROOT
# ============================================================

def linux_root_ssh_keys():

    logging.info(
        "Linux : contrôle des clés SSH de root"
    )

    authorized_keys = Path(
        "/root/.ssh/authorized_keys"
    )

    if not authorized_keys.exists():

        return result(
            "Clés SSH root",
            "OK",
            "Aucune clé authorized_keys root détectée",
            "Linux"
        )

    try:

        lines = [

            line

            for line in authorized_keys.read_text(
                encoding="utf-8",
                errors="replace"
            ).splitlines()

            if line.strip()
            and not line.strip().startswith("#")

        ]

        return result(
            "Clés SSH root",
            "WARNING",
            f"{len(lines)} clé(s) SSH root détectée(s) ; vérifier leur nécessité",
            "Linux"
        )

    except PermissionError:

        return result(
            "Clés SSH root",
            "WARNING",
            "Permission insuffisante pour lire authorized_keys",
            "Linux"
        )


# ============================================================
# AUDIT WINDOWS
# ============================================================

def run_windows_audit():

    logging.info("=" * 70)
    logging.info("AUDIT WINDOWS")
    logging.info("=" * 70)

    results = []

    checks = [

        windows_firewall,

        windows_defender,

        windows_rdp,

        windows_smb1,

        windows_uac,

        windows_local_admins,

        windows_updates,

        windows_accounts,

        windows_services

    ]

    for check in checks:

        try:

            check_result = check()

            results.append(
                check_result
            )

            logging.info(
                "%s : %s",
                check_result["name"],
                check_result["status"]
            )

        except Exception as exc:

            logging.exception(
                "Erreur dans %s",
                check.__name__
            )

            results.append(
                result(
                    check.__name__,
                    "WARNING",
                    str(exc),
                    "Windows"
                )
            )

    return results


# ============================================================
# AUDIT LINUX
# ============================================================

def run_linux_audit():

    logging.info("=" * 70)
    logging.info("AUDIT LINUX")
    logging.info("=" * 70)

    results = []

    checks = [

        linux_firewall,

        linux_updates,

        linux_logs,

        linux_ssh_permissions,

        linux_root_ssh_keys

    ]

    for check in checks:

        try:

            check_result = check()

            if isinstance(
                check_result,
                list
            ):

                results.extend(
                    check_result
                )

                for item in check_result:

                    logging.info(
                        "%s : %s",
                        item["name"],
                        item["status"]
                    )

            else:

                results.append(
                    check_result
                )

                logging.info(
                    "%s : %s",
                    check_result["name"],
                    check_result["status"]
                )

        except Exception as exc:

            logging.exception(
                "Erreur dans %s",
                check.__name__
            )

            results.append(
                result(
                    check.__name__,
                    "WARNING",
                    str(exc),
                    "Linux"
                )
            )

    # SSH
    try:

        ssh_results = (
            linux_sshd_config()
        )

        results.extend(
            ssh_results
        )

        for item in ssh_results:

            logging.info(
                "%s : %s",
                item["name"],
                item["status"]
            )

    except Exception as exc:

        logging.exception(
            "Erreur SSH"
        )

        results.append(
            result(
                "SSH",
                "WARNING",
                str(exc),
                "Linux"
            )
        )

    return results


# ============================================================
# AUDIT AUTRE OS
# ============================================================

def run_generic_audit():

    logging.warning(
        "Système non officiellement supporté : %s",
        platform.system()
    )

    return [

        result(
            "Système d'exploitation",
            "WARNING",
            f"Système détecté : {platform.system()} ; "
            "les contrôles spécifiques ne sont pas disponibles",
            "Système"
        )

    ]


# ============================================================
# CALCUL STATISTIQUES
# ============================================================

def calculate_statistics(
    results
):

    ok = 0

    warning = 0

    ko = 0

    na = 0

    for item in results:

        status = item["status"]

        if status == "OK":

            ok += 1

        elif status == "WARNING":

            warning += 1

        elif status == "KO":

            ko += 1

        elif status == "N/A":

            na += 1

    applicable = (
        ok +
        warning +
        ko
    )

    if applicable:

        score = round(
            (
                ok +
                (warning * 0.5)
            )
            /
            applicable
            *
            100
        )

    else:

        score = 0

    if ko > 0:

        global_status = "NON CONFORME"

    elif warning > 0:

        global_status = "AVERTISSEMENT"

    else:

        global_status = "OK"

    return {

        "total": len(results),

        "ok": ok,

        "warning": warning,

        "ko": ko,

        "na": na,

        "score": score,

        "global_status": global_status

    }


# ============================================================
# RAPPORT TXT
# ============================================================

def generate_text_report(
    results,
    system_info,
    statistics,
    output_file
):

    lines = []

    lines.append(
        "=" * 80
    )

    lines.append(
        "AUDIT DE SÉCURITÉ"
    )

    lines.append(
        "=" * 80
    )

    lines.append("")

    lines.append(
        f"Date              : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    lines.append(
        f"Système           : "
        f"{system_info['os']}"
    )

    lines.append(
        f"Hostname           : "
        f"{system_info['hostname']}"
    )

    lines.append(
        f"Architecture       : "
        f"{system_info['architecture']}"
    )

    lines.append(
        f"Version            : "
        f"{system_info['version']}"
    )

    lines.append("")

    lines.append(
        "-" * 80
    )

    lines.append(
        "RÉSULTATS"
    )

    lines.append(
        "-" * 80
    )

    for index, item in enumerate(
        results,
        1
    ):

        lines.append("")

        lines.append(
            f"{index}. {item['name']}"
        )

        lines.append(
            f"   Catégorie : {item['category']}"
        )

        lines.append(
            f"   Statut    : {status_text(item['status'])}"
        )

        lines.append(
            f"   Détail    : {item['details']}"
        )

    lines.append("")

    lines.append(
        "-" * 80
    )

    lines.append(
        "SYNTHÈSE"
    )

    lines.append(
        "-" * 80
    )

    lines.append("")

    lines.append(
        f"Contrôles       : {statistics['total']}"
    )

    lines.append(
        f"OK              : {statistics['ok']}"
    )

    lines.append(
        f"Avertissements  : {statistics['warning']}"
    )

    lines.append(
        f"Non conformes   : {statistics['ko']}"
    )

    lines.append(
        f"Non applicables : {statistics['na']}"
    )

    lines.append(
        f"Score indicatif : {statistics['score']}%"
    )

    lines.append(
        f"État global     : {statistics['global_status']}"
    )

    lines.append("")

    lines.append(
        "=" * 80
    )

    output_file.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    logging.info(
        "Rapport TXT créé : %s",
        output_file
    )


# ============================================================
# RAPPORT HTML
# ============================================================

def generate_html_report(
    results,
    system_info,
    statistics,
    output_file
):

    logging.info(
        "Lecture du template HTML : %s",
        BASE_HTML
    )

    if not BASE_DIR.exists():

        raise FileNotFoundError(
            f"Dossier base introuvable : {BASE_DIR}"
        )

    if not BASE_HTML.exists():

        raise FileNotFoundError(
            f"Fichier rapport_conformite.html "
            f"introuvable : {BASE_HTML}"
        )

    if not BASE_HTML.is_file():

        raise FileNotFoundError(
            f"{BASE_HTML} n'est pas un fichier"
        )

    template = BASE_HTML.read_text(
        encoding="utf-8"
    )

    rows = []

    for index, item in enumerate(
        results,
        1
    ):

        color = status_color(
            item["status"]
        )

        status = status_text(
            item["status"]
        )

        rows.append(
            f"""
<tr>
    <td>{index}</td>

    <td>
        {html.escape(item["category"])}
    </td>

    <td>
        {html.escape(item["name"])}
    </td>

    <td>
        <span
            style="
                display:inline-block;
                padding:5px 10px;
                border-radius:5px;
                color:#fff;
                background:{color};
            "
        >
            {html.escape(status)}
        </span>
    </td>

    <td>
        {html.escape(item["details"])}
    </td>
</tr>
"""
        )

    results_rows = "\n".join(
        rows
    )

    if statistics["global_status"] == "OK":

        global_color = "#198754"

    elif statistics["global_status"] == "AVERTISSEMENT":

        global_color = "#f0ad00"

    else:

        global_color = "#dc3545"

    variables = {

        "{{TITLE}}":
            "Rapport de conformité sécurité",

        "{{SUBTITLE}}":
            "Audit automatique Windows / Linux",

        "{{DATE}}":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "{{HOSTNAME}}":
            html.escape(
                system_info["hostname"]
            ),

        "{{OS}}":
            html.escape(
                system_info["os"]
            ),

        "{{VERSION}}":
            html.escape(
                system_info["version"]
            ),

        "{{ARCHITECTURE}}":
            html.escape(
                system_info["architecture"]
            ),

        "{{GLOBAL_STATUS}}":
            html.escape(
                statistics["global_status"]
            ),

        "{{GLOBAL_COLOR}}":
            global_color,

        "{{SCORE}}":
            str(
                statistics["score"]
            ),

        "{{TOTAL}}":
            str(
                statistics["total"]
            ),

        "{{OK_COUNT}}":
            str(
                statistics["ok"]
            ),

        "{{WARNING_COUNT}}":
            str(
                statistics["warning"]
            ),

        "{{KO_COUNT}}":
            str(
                statistics["ko"]
            ),

        "{{NA_COUNT}}":
            str(
                statistics["na"]
            ),

        "{{RESULTS_ROWS}}":
            results_rows

    }

    report = template

    for variable, value in variables.items():

        report = report.replace(
            variable,
            value
        )

    output_file.write_text(
        report,
        encoding="utf-8"
    )

    logging.info(
        "Rapport HTML créé : %s",
        output_file
    )


# ============================================================
# VÉRIFICATION ENVIRONNEMENT
# ============================================================

def prepare_environment():

    logging.info(
        "Préparation de l'environnement"
    )

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

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

    logging.info(
        "Template HTML validé : %s",
        BASE_HTML
    )


# ============================================================
# AFFICHAGE TERMINAL
# ============================================================

def display_summary(
    results,
    statistics,
    txt_file,
    html_file,
    log_file
):

    print()

    print(
        "=" * 80
    )

    print(
        "AUDIT DE SÉCURITÉ TERMINÉ"
    )

    print(
        "=" * 80
    )

    print()

    print(
        f"État global     : "
        f"{statistics['global_status']}"
    )

    print(
        f"Score indicatif : "
        f"{statistics['score']}%"
    )

    print()

    print(
        f"OK              : "
        f"{statistics['ok']}"
    )

    print(
        f"Avertissements  : "
        f"{statistics['warning']}"
    )

    print(
        f"Non conformes   : "
        f"{statistics['ko']}"
    )

    print(
        f"Non applicables : "
        f"{statistics['na']}"
    )

    print()

    print(
        "Fichiers générés :"
    )

    print()

    print(
        f"TXT : {txt_file}"
    )

    print(
        f"HTML: {html_file}"
    )

    print(
        f"LOG : {log_file}"
    )

    print()

    print(
        "=" * 80
    )


# ============================================================
# MAIN
# ============================================================

def main():

    log_file = setup_logging()

    try:

        # ----------------------------------------------------
        # Vérification environnement
        # ----------------------------------------------------

        prepare_environment()

        # ----------------------------------------------------
        # Informations système
        # ----------------------------------------------------

        system_info = get_system_info()

        logging.info(
            "Hostname : %s",
            system_info["hostname"]
        )

        logging.info(
            "OS : %s",
            system_info["os"]
        )

        logging.info(
            "Architecture : %s",
            system_info["architecture"]
        )

        # ----------------------------------------------------
        # Détection OS
        # ----------------------------------------------------

        if IS_WINDOWS:

            results = run_windows_audit()

        elif IS_LINUX:

            results = run_linux_audit()

        else:

            results = run_generic_audit()

        # ----------------------------------------------------
        # Statistiques
        # ----------------------------------------------------

        statistics = calculate_statistics(
            results
        )

        logging.info(
            "Nombre de contrôles : %d",
            statistics["total"]
        )

        logging.info(
            "OK : %d",
            statistics["ok"]
        )

        logging.info(
            "WARNING : %d",
            statistics["warning"]
        )

        logging.info(
            "KO : %d",
            statistics["ko"]
        )

        logging.info(
            "N/A : %d",
            statistics["na"]
        )

        logging.info(
            "Score : %d%%",
            statistics["score"]
        )

        # ----------------------------------------------------
        # Nom des fichiers
        # ----------------------------------------------------

        timestamp = datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S"
        )

        txt_file = (
            REPORT_DIR /
            f"audit_securite_{timestamp}.txt"
        )

        html_file = (
            REPORT_DIR /
            f"rapport_conformite_{timestamp}.html"
        )

        # ----------------------------------------------------
        # Rapport TXT
        # ----------------------------------------------------

        generate_text_report(
            results,
            system_info,
            statistics,
            txt_file
        )

        # ----------------------------------------------------
        # Rapport HTML
        # ----------------------------------------------------

        generate_html_report(
            results,
            system_info,
            statistics,
            html_file
        )

        # ----------------------------------------------------
        # Résumé
        # ----------------------------------------------------

        display_summary(
            results,
            statistics,
            txt_file,
            html_file,
            log_file
        )

        logging.info(
            "=" * 70
        )

        logging.info(
            "AUDIT TERMINÉ"
        )

        logging.info(
            "=" * 70
        )

        return 0

    except KeyboardInterrupt:

        logging.warning(
            "Audit interrompu par l'utilisateur"
        )

        print(
            "\nAudit interrompu."
        )

        return 130

    except Exception as exc:

        logging.exception(
            "ERREUR FATALE"
        )

        print()
        print(
            "ERREUR :",
            exc
        )

        print()
        print(
            "Consulte le fichier log :"
        )

        print(
            log_file
        )

        return 1


# ============================================================
# POINT D'ENTRÉE
# ============================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )
