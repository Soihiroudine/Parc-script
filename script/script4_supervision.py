#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S4 - Supervision et alerte de disponibilité des services
Fichier : script4_supervision.py

Ce que fait le script (conforme à la fiche S4) :
  - Définit une liste de services à surveiller (nom + IP + port)
  - Teste la disponibilité de chaque service toutes les X secondes
  - Journalise chaque test avec horodatage et résultat   -> logs/supervision.log
  - Détecte les pannes : 3 échecs consécutifs = panne confirmée
  - Génère une alerte dans la console et dans un log dédié -> logs/incidents.log
  - Détecte le retour à la normale (avec la durée d'indisponibilité)

Niveau avancé :
  - Calcul du taux de disponibilité (SLA) et rapport automatique
                                                   -> rapport/supervision/rapport_sla.txt
  - Alerte e-mail via smtplib (désactivée par défaut, option --email)

Bonus conservé : découverte automatique des ports TCP en écoute (option --auto).

Liens avec le projet :
  - EF02 : alerte en moins de 5 minutes (le délai maximal est calculé au démarrage)
  - SLA cible : 99,9 %

Arborescence :
  Parc-script/
  ├── script/script4_supervision.py
  ├── logs/supervision.log, incidents.log
  └── rapport/supervision/rapport_sla.txt

Exemples :
  python script/script4_supervision.py                      # services de SERVICES_A_SURVEILLER
  python script/script4_supervision.py --auto               # + ports découverts automatiquement
  python script/script4_supervision.py -s "Web=127.0.0.1:8080" -s "DB=127.0.0.1:3306" -s "DNS=8.8.8.8:53"
  python script/script4_supervision.py --intervalle 5 --duree 60   # test rapide d'une minute
  python script/script4_supervision.py --email              # active les alertes e-mail

Arrêt : Ctrl+C (le rapport SLA est alors finalisé).
"""

import argparse
import logging
import os
import platform
import signal
import smtplib
import subprocess
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional

# ============================================================
# CONFIGURATION
# ============================================================

INTERVALLE = 30          # secondes entre deux cycles de test
SEUIL_ECHECS = 3         # échecs consécutifs avant panne confirmée
TIMEOUT = 5              # secondes max pour tester un port
SLA_CIBLE = 99.9         # objectif de disponibilité (%)
DELAI_ALERTE_MAX = 300   # EF02 : alerte en moins de 5 minutes (secondes)

# Services critiques à surveiller (IP + port + nom). À ADAPTER à votre infrastructure.
# La fiche exige au moins 3 services.
SERVICES_A_SURVEILLER = [
    {"nom": "SSH",        "ip": "127.0.0.1", "port": 22},
    {"nom": "HTTP",       "ip": "127.0.0.1", "port": 80},
    {"nom": "DNS public", "ip": "8.8.8.8",   "port": 53},
]

# Adresse utilisée pour les services découverts automatiquement (--auto)
ADRESSE_LOCALE = "127.0.0.1"

# Noms lisibles pour les ports découverts automatiquement
SERVICES_CONNUS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1433: "Microsoft SQL Server", 1521: "Oracle",
    2049: "NFS", 2375: "Docker", 2376: "Docker TLS", 3000: "Application Web",
    3306: "MySQL", 3389: "RDP", 5000: "Application Web", 5432: "PostgreSQL",
    5672: "RabbitMQ", 6379: "Redis", 6443: "Kubernetes API", 8000: "Application Web",
    8080: "HTTP-ALT", 8081: "Application Web", 8443: "HTTPS-ALT", 9000: "Application",
    9090: "Prometheus", 9200: "Elasticsearch", 27017: "MongoDB",
}

# ------------------------------------------------------------
# E-mail (smtplib) - désactivé par défaut, activé avec --email.
# Les identifiants ne sont PAS écrits dans le script (risque de fuite via Git) :
# ils se lisent dans des variables d'environnement.
#
#   Windows (PowerShell) : $env:SMTP_UTILISATEUR="moi@gmail.com"
#                          $env:SMTP_MOT_DE_PASSE="mot_de_passe_application"
#                          $env:EMAIL_DESTINATAIRE="admin@example.com"
#   Linux / macOS        : export SMTP_UTILISATEUR=... (idem)
# ------------------------------------------------------------
EMAIL_ACTIF = False
SMTP_SERVEUR = os.environ.get("SMTP_SERVEUR", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_UTILISATEUR = os.environ.get("SMTP_UTILISATEUR", "")
SMTP_MOT_DE_PASSE = os.environ.get("SMTP_MOT_DE_PASSE", "")
EMAIL_DESTINATAIRE = os.environ.get("EMAIL_DESTINATAIRE", "")

# ============================================================
# CHEMINS
# ============================================================

DOSSIER_SCRIPT = Path(__file__).resolve().parent
RACINE = DOSSIER_SCRIPT.parent                       # Parc-script/
DOSSIER_LOGS = RACINE / "logs"
DOSSIER_RAPPORT = RACINE / "rapport" / "supervision"

FICHIER_LOG = DOSSIER_LOGS / "supervision.log"
FICHIER_INCIDENTS = DOSSIER_LOGS / "incidents.log"
FICHIER_RAPPORT = DOSSIER_RAPPORT / "rapport_sla.txt"

DOSSIER_LOGS.mkdir(parents=True, exist_ok=True)
DOSSIER_RAPPORT.mkdir(parents=True, exist_ok=True)

# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("supervision")
logger.setLevel(logging.INFO)
_handler = logging.FileHandler(FICHIER_LOG, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s",
                                        "%Y-%m-%d %H:%M:%S"))
logger.addHandler(_handler)

ARRET = threading.Event()          # positionné par Ctrl+C
THREADS_EMAIL: List[threading.Thread] = []


def arreter_programme(signal_num, frame):
    print("\nArrêt de la supervision demandé...")
    logger.info("Arrêt demandé par l'utilisateur.")
    ARRET.set()


signal.signal(signal.SIGINT, arreter_programme)
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, arreter_programme)


# ============================================================
# MODÈLE D'UN SERVICE SURVEILLÉ
# ============================================================

@dataclass
class Service:
    nom: str
    ip: str
    port: int
    total: int = 0
    succes: int = 0
    echecs: int = 0
    consecutifs: int = 0
    panne: bool = False
    premier_echec: Optional[datetime] = None
    debut_panne: Optional[datetime] = None
    incidents: int = 0
    indispo_s: float = 0.0

    @property
    def cle(self):
        return f"{self.ip}:{self.port}"

    @property
    def sla(self):
        return 100 * self.succes / self.total if self.total else None

    def indisponibilite(self, maintenant):
        """Durée totale d'indisponibilité (panne en cours incluse), en secondes."""
        en_cours = (maintenant - self.debut_panne).total_seconds() if self.panne and self.debut_panne else 0
        return self.indispo_s + en_cours


def formater_duree(secondes):
    secondes = int(secondes)
    h, reste = divmod(secondes, 3600)
    m, s = divmod(reste, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"


# ============================================================
# TEST D'UN SERVICE
# ============================================================

def tester_service(ip, port, timeout=TIMEOUT):
    """True si une connexion TCP aboutit (IPv4 ou IPv6)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def tester_tous(services):
    """Teste tous les services en parallèle : un cycle dure au plus TIMEOUT secondes,
    ce qui garantit un délai de détection prévisible (EF02)."""
    if not services:
        return []
    with ThreadPoolExecutor(max_workers=min(32, len(services))) as pool:
        return list(pool.map(lambda s: tester_service(s.ip, s.port), services))


# ============================================================
# DÉCOUVERTE AUTOMATIQUE DES PORTS (option --auto)
# ============================================================

def extraire_ports_proc(texte):
    """Linux : contenu de /proc/net/tcp ou tcp6 (état 0A = LISTEN)."""
    ports = set()
    for ligne in texte.splitlines()[1:]:
        el = ligne.split()
        if len(el) >= 4 and el[3] == "0A":
            try:
                ports.add(int(el[1].split(":")[1], 16))
            except (ValueError, IndexError):
                pass
    return ports


def extraire_ports_netstat(texte):
    """Windows : sortie de `netstat -ano`. Ne dépend pas de la langue : une ligne
    en écoute a une adresse distante se terminant par ':0'."""
    ports = set()
    for ligne in texte.splitlines():
        el = ligne.split()
        if len(el) >= 4 and el[0].upper() == "TCP" and el[2].endswith(":0"):
            try:
                ports.add(int(el[1].rsplit(":", 1)[1]))
            except (ValueError, IndexError):
                pass
    return ports


def extraire_ports_lsof(texte):
    """macOS : sortie de `lsof -nP -iTCP -sTCP:LISTEN`.
    La dernière colonne est '(LISTEN)' ; l'adresse est l'avant-dernière."""
    ports = set()
    for ligne in texte.splitlines()[1:]:
        el = ligne.split()
        if len(el) >= 9 and ":" in el[-2]:
            try:
                ports.add(int(el[-2].rsplit(":", 1)[1]))
            except ValueError:
                pass
    return ports


def executer(commande, encodage):
    return subprocess.run(commande, capture_output=True, text=True, timeout=10,
                          encoding=encodage, errors="replace").stdout


def decouvrir_ports():
    systeme = platform.system()
    try:
        if systeme == "Linux":
            ports = set()
            for chemin in ("/proc/net/tcp", "/proc/net/tcp6"):
                try:
                    with open(chemin, encoding="utf-8") as f:
                        ports |= extraire_ports_proc(f.read())
                except OSError:
                    continue
            return sorted(ports)
        if systeme == "Windows":
            return sorted(extraire_ports_netstat(executer(["netstat", "-ano"], "cp850")))
        if systeme == "Darwin":
            return sorted(extraire_ports_lsof(
                executer(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], "utf-8")))
    except (OSError, subprocess.TimeoutExpired) as erreur:
        logger.error("Découverte des ports impossible : %s", erreur)
        return []
    logger.error("Système non supporté pour la découverte : %s", systeme)
    return []


def nom_service(port):
    return SERVICES_CONNUS.get(port, f"Service TCP - port {port}")


def ajouter_decouverts(services):
    """Ajoute les ports en écoute pas encore surveillés. Retourne le nombre ajouté."""
    existants = {s.cle for s in services}
    noms = {s.nom for s in services}
    ajoutes = 0
    for port in decouvrir_ports():
        cle = f"{ADRESSE_LOCALE}:{port}"
        if cle in existants:
            continue
        nom = nom_service(port)
        if nom in noms:
            nom = f"{nom} ({port})"
        services.append(Service(nom, ADRESSE_LOCALE, port))
        existants.add(cle)
        noms.add(nom)
        ajoutes += 1
        logger.info("Nouveau service découvert : %s (%s)", nom, cle)
    return ajoutes


# ============================================================
# ALERTES : INCIDENTS + E-MAIL
# ============================================================

def enregistrer_incident(message):
    """Ajoute une ligne horodatée dans incidents.log."""
    try:
        with open(FICHIER_INCIDENTS, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {message}\n")
    except OSError as erreur:
        logger.error("Écriture incidents.log impossible : %s", erreur)


def envoyer_email(sujet, corps):
    """Envoi via smtplib dans un thread : un SMTP lent ne retarde pas la supervision."""
    if not EMAIL_ACTIF:
        return

    def _envoi():
        try:
            msg = EmailMessage()
            msg["Subject"] = sujet
            msg["From"] = SMTP_UTILISATEUR
            msg["To"] = EMAIL_DESTINATAIRE
            msg.set_content(corps)
            with smtplib.SMTP(SMTP_SERVEUR, SMTP_PORT, timeout=15) as serveur:
                serveur.starttls()
                serveur.login(SMTP_UTILISATEUR, SMTP_MOT_DE_PASSE)
                serveur.send_message(msg)
            logger.info("E-MAIL | envoyé | %s", sujet)
        except Exception as erreur:
            logger.error("E-MAIL | échec d'envoi (%s) | %s", sujet, erreur)

    t = threading.Thread(target=_envoi, daemon=True)
    THREADS_EMAIL.append(t)
    t.start()


# ============================================================
# TRAITEMENT D'UN RÉSULTAT DE TEST
# ============================================================

def traiter_resultat(s, disponible):
    maintenant = datetime.now()
    s.total += 1

    if disponible:
        s.succes += 1
        logger.info("TEST | OK | %s | %s", s.nom, s.cle)
        print(f"[{maintenant:%Y-%m-%d %H:%M:%S}] [OK]     {s.nom} ({s.cle})")

        if s.panne:                                    # retour à la normale
            duree = (maintenant - s.debut_panne).total_seconds()
            s.indispo_s += duree
            message = (f"RETOUR A LA NORMALE | {s.nom} | {s.cle} | "
                       f"indisponible pendant {formater_duree(duree)}")
            logger.info(message)
            enregistrer_incident(message)
            print(f"\n>>> RETOUR À LA NORMALE : {s.nom} ({s.cle}) - "
                  f"indisponible pendant {formater_duree(duree)}\n")
            envoyer_email(f"[RECOVERY] {s.nom}",
                          f"Retour à la normale\n\nService : {s.nom}\nAdresse : {s.cle}\n"
                          f"Indisponibilité : {formater_duree(duree)}\n")
            s.panne = False
            s.debut_panne = None
        s.consecutifs = 0
        s.premier_echec = None
        return

    # --- échec ---
    s.echecs += 1
    if s.consecutifs == 0:
        s.premier_echec = maintenant
    s.consecutifs += 1
    logger.warning("TEST | ECHEC | %s | %s | échecs consécutifs = %s", s.nom, s.cle, s.consecutifs)
    print(f"[{maintenant:%Y-%m-%d %H:%M:%S}] [ERREUR] {s.nom} ({s.cle}) "
          f"- échecs consécutifs : {s.consecutifs}")

    if s.consecutifs >= SEUIL_ECHECS and not s.panne:   # panne confirmée
        s.panne = True
        s.debut_panne = s.premier_echec
        s.incidents += 1
        message = (f"PANNE CONFIRMEE | {s.nom} | {s.cle} | "
                   f"{s.consecutifs} échecs consécutifs | "
                   f"premier échec : {s.debut_panne:%Y-%m-%d %H:%M:%S}")
        logger.error(message)
        enregistrer_incident(message)
        print("\n" + "!" * 80)
        print(f"!!! ALERTE PANNE CONFIRMÉE : {s.nom} ({s.cle}) - "
              f"{s.consecutifs} échecs consécutifs")
        print("!" * 80 + "\n")
        envoyer_email(f"[ALERTE PANNE] {s.nom}",
                      f"Panne confirmée\n\nService : {s.nom}\nAdresse : {s.cle}\n"
                      f"Échecs consécutifs : {s.consecutifs}\n"
                      f"Premier échec : {s.debut_panne:%Y-%m-%d %H:%M:%S}\n")


# ============================================================
# RAPPORT SLA
# ============================================================

def generer_rapport(services, debut, fin, intervalle):
    L = []
    L.append("=" * 92)
    L.append("RAPPORT DE SUPERVISION SLA".center(92))
    L.append("=" * 92)
    L.append("")
    L.append("INFORMATIONS GÉNÉRALES")
    L.append("-" * 92)
    L.append(f"Début            : {debut:%Y-%m-%d %H:%M:%S}")
    L.append(f"Fin              : {fin:%Y-%m-%d %H:%M:%S}")
    L.append(f"Durée            : {formater_duree((fin - debut).total_seconds())}")
    L.append(f"Intervalle       : {intervalle} secondes")
    L.append(f"Seuil de panne   : {SEUIL_ECHECS} échecs consécutifs")
    L.append(f"Objectif SLA     : {SLA_CIBLE:.3f} %")
    L.append("")
    L.append("SERVICES SURVEILLÉS")
    L.append("-" * 92)
    L.append(f"{'Service':<26}{'Adresse':<22}{'Tests':>7}{'OK':>7}{'Échecs':>8}"
             f"{'SLA':>10}{'Indispo':>12}")
    L.append("-" * 92)
    for s in services:
        sla = f"{s.sla:.3f}%" if s.sla is not None else "n/a"
        L.append(f"{s.nom[:25]:<26}{s.cle[:21]:<22}{s.total:>7}{s.succes:>7}{s.echecs:>8}"
                 f"{sla:>10}{formater_duree(s.indisponibilite(fin)):>12}")
    L.append("-" * 92)
    L.append("")

    total = sum(s.total for s in services)
    succes = sum(s.succes for s in services)
    sla_global = 100 * succes / total if total else None
    L.append("RÉSUMÉ GLOBAL")
    L.append("-" * 92)
    L.append(f"Nombre total de tests : {total}")
    L.append(f"Tests réussis         : {succes}")
    L.append(f"Tests échoués         : {total - succes}")
    L.append(f"Pannes confirmées     : {sum(s.incidents for s in services)}")
    L.append(f"SLA global            : {sla_global:.3f} %" if sla_global is not None
             else "SLA global            : n/a")
    L.append("")
    L.append("OBJECTIF SLA PAR SERVICE")
    L.append("-" * 92)
    if not services:
        L.append("Aucun service surveillé.")
    for s in services:
        if s.sla is None:
            etat = "non évalué"
        elif s.sla >= SLA_CIBLE:
            etat = "objectif atteint"
        else:
            etat = "OBJECTIF NON ATTEINT"
        L.append(f"{s.nom[:30]:<32}{etat}")
    L.append("")
    L.append("Remarque : le SLA est calculé sur le ratio de tests réussis ; "
             "l'indisponibilité part du premier échec.")
    L.append("=" * 92)

    try:
        FICHIER_RAPPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    except OSError as erreur:
        logger.error("Écriture du rapport impossible : %s", erreur)


# ============================================================
# ARGUMENTS
# ============================================================

def lire_arguments():
    p = argparse.ArgumentParser(description="S4 - Supervision et alerte de disponibilité")
    p.add_argument("-s", "--service", action="append", metavar="NOM=IP:PORT",
                   help="service à surveiller (répétable) ; remplace SERVICES_A_SURVEILLER")
    p.add_argument("--auto", action="store_true",
                   help="ajoute les ports TCP en écoute découverts automatiquement")
    p.add_argument("--intervalle", type=int, default=INTERVALLE,
                   help=f"secondes entre deux cycles (défaut : {INTERVALLE})")
    p.add_argument("--duree", type=int, default=0,
                   help="arrêt automatique après N secondes (0 = jusqu'à Ctrl+C)")
    p.add_argument("--email", action="store_true", help="active les alertes e-mail (smtplib)")
    return p.parse_args()


def construire_services(args):
    if args.service:
        definitions = []
        for texte in args.service:
            try:
                nom, adresse = texte.split("=", 1)
                ip, port = adresse.rsplit(":", 1)
                definitions.append({"nom": nom.strip(), "ip": ip.strip("[] "), "port": int(port)})
            except ValueError:
                print(f"[!] Service ignoré (format attendu NOM=IP:PORT) : {texte}", file=sys.stderr)
    else:
        definitions = SERVICES_A_SURVEILLER

    services, vus = [], set()
    for d in definitions:
        s = Service(d["nom"], d["ip"], int(d["port"]))
        if s.cle not in vus:                       # pas de doublon IP:port
            services.append(s)
            vus.add(s.cle)
    return services


# ============================================================
# PROGRAMME PRINCIPAL
# ============================================================

def main():
    global EMAIL_ACTIF
    args = lire_arguments()
    intervalle = max(1, args.intervalle)
    services = construire_services(args)

    if args.email:
        if all([SMTP_SERVEUR, SMTP_UTILISATEUR, SMTP_MOT_DE_PASSE, EMAIL_DESTINATAIRE]):
            EMAIL_ACTIF = True
        else:
            print("[!] --email demandé mais SMTP_UTILISATEUR / SMTP_MOT_DE_PASSE / "
                  "EMAIL_DESTINATAIRE ne sont pas définis : e-mails désactivés.")
            logger.warning("E-mail désactivé : variables d'environnement manquantes.")

    if args.auto:
        ajouter_decouverts(services)

    # --- en-tête ---
    print("\n" + "=" * 80)
    print("     S4 - SUPERVISION ET ALERTE DE DISPONIBILITÉ DES SERVICES")
    print("=" * 80)
    print(f"Système       : {platform.system()}")
    print(f"Intervalle    : {intervalle} s | Timeout : {TIMEOUT} s | "
          f"Panne après {SEUIL_ECHECS} échecs | SLA cible : {SLA_CIBLE} %")
    print(f"Alertes e-mail: {'activées' if EMAIL_ACTIF else 'désactivées'}")
    print(f"\n{len(services)} service(s) surveillé(s) :")
    for s in services:
        print(f"  - {s.nom} -> {s.cle}")

    if len(services) < 3:
        print("\n[!] La fiche S4 demande au moins 3 services surveillés.")

    # EF02 : délai maximal entre le début d'une panne et l'alerte
    delai_max = SEUIL_ECHECS * (intervalle + TIMEOUT)
    verdict = "conforme" if delai_max <= DELAI_ALERTE_MAX else "NON CONFORME"
    print(f"\nDélai maximal de détection d'une panne : ~{delai_max} s "
          f"(EF02 : < {DELAI_ALERTE_MAX} s) -> {verdict}")
    logger.info("Démarrage | %s service(s) | intervalle=%ss | délai max détection=%ss (%s)",
                len(services), intervalle, delai_max, verdict)

    debut = datetime.now()
    fin_prevue = debut + timedelta(seconds=args.duree) if args.duree else None

    # --- boucle de supervision ---
    while not ARRET.is_set():
        print("\n" + "=" * 80)
        print(f"Cycle de supervision - {datetime.now():%Y-%m-%d %H:%M:%S}")
        print("=" * 80)

        if args.auto:
            nouveaux = ajouter_decouverts(services)
            if nouveaux:
                print(f"{nouveaux} nouveau(x) service(s) découvert(s).")

        for service, ok in zip(services, tester_tous(services)):
            traiter_resultat(service, ok)

        generer_rapport(services, debut, datetime.now(), intervalle)   # rapport toujours à jour

        attente = intervalle
        if fin_prevue:
            restant = (fin_prevue - datetime.now()).total_seconds()
            if restant <= 0:
                break
            attente = min(intervalle, restant)
        print(f"\nProchain test dans {int(attente)} secondes...")
        ARRET.wait(attente)

    # --- fin ---
    fin = datetime.now()
    generer_rapport(services, debut, fin, intervalle)
    for t in THREADS_EMAIL:
        t.join(timeout=15)                        # laisse finir les envois en cours
    logger.info("Fin de la supervision.")

    print("\n" + "=" * 80)
    print("Fin de la supervision.")
    print("=" * 80)
    print(f"\nFichiers générés :\n  {FICHIER_LOG}\n  {FICHIER_INCIDENTS}\n  {FICHIER_RAPPORT}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as erreur:
        logger.exception("Erreur critique : %s", erreur)
        print(f"\nERREUR CRITIQUE : {erreur}", file=sys.stderr)
        sys.exit(1)