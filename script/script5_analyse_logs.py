#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S5 - Analyse de logs et détection d'anomalies
Fichier : script5_analyse_logs.py

Ce que fait le script :
  - Lit un fichier de log système (auth.log, syslog ou log simulé)
  - Compte les tentatives de connexion échouées par IP source
  - Identifie les IP dépassant un seuil (> 5 échecs en 10 minutes)
  - Détecte les connexions réussies hors horaires autorisés (avant 6h / après 22h)
  - Génère un rapport d'anomalies, un CSV des IP suspectes et (bonus)
    un script de règles iptables pour bloquer les IP critiques

Fichiers générés (dans rapport/analyse_logs/) :
  - rapport_anomalies_AAAA-MM-JJ.txt
  - ip_suspectes.csv
  - regles_firewall.sh

Usage :
  python script5_analyse_logs.py                        # logs/auth.log par défaut
  python script5_analyse_logs.py -l logs/auth.log
  python script5_analyse_logs.py --generer-demo         # log simulé avec l'IP réelle de cette machine
  python script5_analyse_logs.py --generer-demo --scan-reseau   # + IP trouvées par ping dans le réseau local
"""

import argparse
import csv
import ipaddress
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
RACINE = Path(__file__).resolve().parent.parent          # Parc-script/
LOG_PAR_DEFAUT = RACINE / "logs" / "auth.log"
DOSSIER_SORTIE = RACINE / "rapport" / "analyse_logs"

SEUIL_ECHECS = 5                  # plus de 5 échecs...
FENETRE = timedelta(minutes=10)   # ...en 10 minutes
HEURE_DEBUT = 6                   # connexions autorisées de 6h...
HEURE_FIN = 22                    # ...à 22h

# Seuils de classification (nombre max d'échecs dans une fenêtre de 10 min)
SEUIL_MODERE = SEUIL_ECHECS + 1   # 6 à 14  -> modérée
SEUIL_CRITIQUE = 15               # >= 15   -> critique

# Format syslog classique : "Oct  1 12:34:56 hote sshd[123]: ..."
RE_DATE = re.compile(r"^(?P<mois>[A-Z][a-z]{2})\s+(?P<jour>\d{1,2})\s+(?P<heure>\d{2}:\d{2}:\d{2})\s")
# Format ISO : "2026-10-01T12:34:56..." ou "2026-10-01 12:34:56"
RE_DATE_ISO = re.compile(r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")

RE_ECHEC = re.compile(
    r"(?:Failed (?:password|publickey)|authentication failure|Invalid user).*?"
    r"(?:for (?:invalid user )?(?P<user>\S+) from |rhost=|from )(?P<ip>[0-9a-fA-F:.]{3,45})"
)
RE_SUCCES = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive\S*) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]{3,45})"
)

MOIS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


# --------------------------------------------------------------------------
# Lecture et parsing
# --------------------------------------------------------------------------
def extraire_date(ligne, annee):
    """Retourne un datetime à partir d'une ligne de log, ou None."""
    m = RE_DATE_ISO.match(ligne)
    if m:
        return datetime.fromisoformat(m.group("iso").replace(" ", "T"))
    m = RE_DATE.match(ligne)
    if m and m.group("mois") in MOIS:
        try:
            return datetime.strptime(
                f"{annee} {MOIS[m.group('mois')]} {m.group('jour')} {m.group('heure')}",
                "%Y %m %d %H:%M:%S",
            )
        except ValueError:
            return None
    return None


def ip_valide(texte):
    try:
        return str(ipaddress.ip_address(texte.strip(".:")))
    except ValueError:
        return None


def analyser_fichier(chemin, annee):
    """Parcourt le log et retourne (échecs, succès).

    échecs : {ip: [(datetime, utilisateur), ...]}
    succès : [(datetime, utilisateur, ip), ...]
    """
    echecs = defaultdict(list)
    succes = []
    ignorees = 0

    with open(chemin, "r", encoding="utf-8", errors="replace") as f:
        for ligne in f:
            ligne = ligne.rstrip("\n")
            horodatage = extraire_date(ligne, annee)
            if horodatage is None:
                ignorees += 1
                continue

            m = RE_SUCCES.search(ligne)
            if m and ip_valide(m.group("ip")):
                succes.append((horodatage, m.group("user"), ip_valide(m.group("ip"))))
                continue

            m = RE_ECHEC.search(ligne)
            if m and ip_valide(m.group("ip")):
                utilisateur = m.group("user") or "?"
                echecs[ip_valide(m.group("ip"))].append((horodatage, utilisateur))

    return echecs, succes, ignorees


# --------------------------------------------------------------------------
# Détection
# --------------------------------------------------------------------------
def max_echecs_fenetre(horodatages):
    """Nombre maximal d'échecs dans une fenêtre glissante de 10 minutes."""
    horodatages = sorted(horodatages)
    maxi, debut = 0, 0
    for fin in range(len(horodatages)):
        while horodatages[fin] - horodatages[debut] > FENETRE:
            debut += 1
        maxi = max(maxi, fin - debut + 1)
    return maxi


def classifier(max_fenetre):
    if max_fenetre >= SEUIL_CRITIQUE:
        return "critique"
    if max_fenetre >= SEUIL_MODERE:
        return "modérée"
    return "faible"


def detecter_ip_suspectes(echecs):
    suspectes = []
    for ip, evenements in echecs.items():
        horodatages = [e[0] for e in evenements]
        pic = max_echecs_fenetre(horodatages)
        if pic > SEUIL_ECHECS:
            suspectes.append({
                "ip": ip,
                "total_echecs": len(evenements),
                "max_echecs_10min": pic,
                "premiere_tentative": min(horodatages).strftime("%Y-%m-%d %H:%M:%S"),
                "derniere_tentative": max(horodatages).strftime("%Y-%m-%d %H:%M:%S"),
                "comptes_cibles": ", ".join(sorted({e[1] for e in evenements})[:5]),
                "niveau_menace": classifier(pic),
            })
    ordre = {"critique": 0, "modérée": 1, "faible": 2}
    suspectes.sort(key=lambda s: (ordre[s["niveau_menace"]], -s["total_echecs"]))
    return suspectes


def detecter_hors_horaires(succes):
    return [s for s in succes if not (HEURE_DEBUT <= s[0].hour < HEURE_FIN)]


# --------------------------------------------------------------------------
# Génération des fichiers de sortie
# --------------------------------------------------------------------------
def ecrire_csv(suspectes, chemin):
    champs = ["ip", "total_echecs", "max_echecs_10min", "premiere_tentative",
              "derniere_tentative", "comptes_cibles", "niveau_menace"]
    with open(chemin, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=champs, delimiter=";")
        w.writeheader()
        w.writerows(suspectes)


def ecrire_regles_firewall(suspectes, chemin):
    critiques = [s for s in suspectes if s["niveau_menace"] == "critique"]
    lignes = [
        "#!/bin/bash",
        f"# Règles iptables générées le {datetime.now():%Y-%m-%d %H:%M:%S} par script5_analyse_logs.py",
        "# ATTENTION : à relire et valider avant application (root requis).",
        "# Ne jamais bloquer une IP d'administration légitime.",
        "",
    ]
    if not critiques:
        lignes.append("# Aucune IP de niveau critique détectée : rien à bloquer.")
    locales = ips_locales()
    for s in critiques:
        ip = s["ip"]
        if ip in locales:
            lignes.append(f"# {ip} : IP de cette machine, NON bloquée ({s['total_echecs']} échecs)")
            continue
        cmd = "ip6tables" if ":" in ip else "iptables"
        lignes.append(f"# {s['total_echecs']} échecs (pic {s['max_echecs_10min']}/10 min)")
        lignes.append(f"{cmd} -C INPUT -s {ip} -j DROP 2>/dev/null || {cmd} -A INPUT -s {ip} -j DROP")
    chemin.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    try:
        chemin.chmod(0o750)
    except OSError:
        pass


def ecrire_rapport(chemin, fichier_log, nb_echecs, suspectes, hors_horaires):
    nb_crit = sum(1 for s in suspectes if s["niveau_menace"] == "critique")
    L = []
    L.append("=" * 70)
    L.append("RAPPORT D'ANOMALIES - ANALYSE DE LOGS")
    L.append("=" * 70)
    L.append(f"Date de l'analyse : {datetime.now():%Y-%m-%d %H:%M:%S}")
    L.append(f"Fichier analysé   : {fichier_log}")
    L.append(f"Seuil de détection: > {SEUIL_ECHECS} échecs en {int(FENETRE.total_seconds() // 60)} minutes")
    L.append(f"Horaires autorisés: {HEURE_DEBUT}h - {HEURE_FIN}h")
    L.append("")
    L.append("RÉSUMÉ")
    L.append("-" * 70)
    L.append(f"Échecs de connexion au total : {nb_echecs}")
    L.append(f"IP suspectes                 : {len(suspectes)} (dont {nb_crit} critique(s))")
    L.append(f"Connexions hors horaires     : {len(hors_horaires)}")
    L.append("")
    L.append("IP SUSPECTES")
    L.append("-" * 70)
    if suspectes:
        L.append(f"{'IP':<40}{'Échecs':>7}{'Pic/10min':>11}  Menace")
        for s in suspectes:
            L.append(f"{s['ip']:<40}{s['total_echecs']:>7}{s['max_echecs_10min']:>11}  {s['niveau_menace']}")
    else:
        L.append("Aucune IP au-dessus du seuil.")
    L.append("")
    L.append("CONNEXIONS RÉUSSIES HORS HORAIRES")
    L.append("-" * 70)
    if hors_horaires:
        for dt, user, ip in hors_horaires:
            L.append(f"{dt:%Y-%m-%d %H:%M:%S}  utilisateur={user}  ip={ip}")
    else:
        L.append("Aucune.")
    L.append("")
    L.append("PROCÉDURE NIS2 (notification d'incident)")
    L.append("-" * 70)
    if nb_crit or hors_horaires:
        L.append("Des anomalies significatives ont été détectées. Si elles sont qualifiées")
        L.append("d'incident significatif, la directive NIS2 prévoit :")
        L.append("  - alerte précoce à l'autorité compétente : sous 24 h")
        L.append("  - notification d'incident                : sous 72 h")
        L.append("  - rapport final                          : sous 1 mois")
        L.append("-> Informer le RSSI / responsable sécurité et documenter l'incident.")
    else:
        L.append("Aucun incident significatif détecté : pas de notification requise.")
    L.append("")
    L.append("Fichiers associés : ip_suspectes.csv, regles_firewall.sh")
    chemin.write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Adresses IP réelles (machine locale + découverte réseau par ping)
# --------------------------------------------------------------------------
def obtenir_ip_locale():
    """IP de la machine qui exécute le script (interface utilisée pour sortir sur le réseau).
    Aucun paquet n'est envoyé : la 'connexion' UDP sert seulement à choisir l'interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        s.close()


def ips_locales():
    """Ensemble des IP appartenant à cette machine (à ne jamais bloquer)."""
    ips = {"127.0.0.1", "::1", obtenir_ip_locale()}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except OSError:
        pass
    return ips


def ping(ip):
    """True si l'hôte répond à un ping (Windows et Linux/macOS)."""
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=3).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def decouvrir_hotes(ip_locale, max_hotes=3):
    """Balayage ping du /24 de la machine ; retourne les premières IP qui répondent."""
    try:
        reseau = ipaddress.ip_network(f"{ip_locale}/24", strict=False)
    except ValueError:
        return []
    if not reseau.is_private or ip_locale.startswith("127."):
        print("[i] Réseau non privé : balayage ping ignoré.")
        return []
    print(f"[i] Balayage ping de {reseau} (quelques secondes)...")
    candidats = [str(h) for h in reseau.hosts() if str(h) != ip_locale]
    with ThreadPoolExecutor(max_workers=64) as ex:
        vivants = [ip for ip, ok in zip(candidats, ex.map(ping, candidats)) if ok]
    return vivants[:max_hotes]


# --------------------------------------------------------------------------
# Log simulé (pour tester le script) - IP réelles, aucun tirage aléatoire
# --------------------------------------------------------------------------
def generer_log_demo(chemin, scan_reseau=False):
    ip_locale = obtenir_ip_locale()
    hote = socket.gethostname().split(".")[0]
    sources = []
    if scan_reseau:
        sources = decouvrir_hotes(ip_locale)
        print(f"[i] Hôtes trouvés par ping : {', '.join(sources) if sources else 'aucun'}")
    if not sources:
        sources = [ip_locale]
        print(f"[i] IP de cette machine utilisée comme source simulée : {ip_locale}")

    # Rôles dans le scénario (si une seule IP, elle joue tous les rôles)
    ip_critique = sources[0]
    ip_moderee = sources[1] if len(sources) > 1 else sources[0]
    ip_faible = sources[2] if len(sources) > 2 else sources[-1]

    chemin.parent.mkdir(parents=True, exist_ok=True)
    base = datetime.now().replace(hour=14, minute=0, second=0, microsecond=0)
    lignes = []

    def horodatage(dt):
        return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S}"

    def ajouter(dt, message):
        lignes.append((dt, f"{horodatage(dt)} {hote} {message}"))

    # IP critique : 20 échecs en quelques minutes
    for i in range(20):
        ajouter(base + timedelta(seconds=15 * i),
                f"sshd[1201]: Failed password for root from {ip_critique} port 4422{i % 10} ssh2")
    # IP modérée : 8 échecs
    for i in range(8):
        ajouter(base + timedelta(minutes=1, seconds=40 * i),
                f"sshd[1202]: Failed password for invalid user admin from {ip_moderee} port 5100{i} ssh2")
    # IP sous le seuil : 3 échecs
    for i in range(3):
        ajouter(base + timedelta(minutes=30 + i),
                f"sshd[1203]: Failed password for alice from {ip_faible} port 6000{i} ssh2")
    # Connexions réussies : normale + hors horaires
    ajouter(base + timedelta(minutes=45),
            f"sshd[1210]: Accepted password for alice from {ip_faible} port 60010 ssh2")
    ajouter(base.replace(hour=3, minute=12),
            f"sshd[1211]: Accepted publickey for bob from {ip_faible} port 60044 ssh2")
    ajouter(base.replace(hour=23, minute=40),
            f"sshd[1212]: Accepted password for root from {ip_critique} port 60099 ssh2")
    # Bruit (lignes sans IP, horaires fixes)
    for i in range(5):
        ajouter(base + timedelta(minutes=11 * i),
                f"CRON[99{i}]: pam_unix(cron:session): session opened for user root")

    lignes.sort(key=lambda x: x[0])
    chemin.write_text("\n".join(l for _, l in lignes) + "\n", encoding="utf-8")
    print(f"[+] Log simulé créé : {chemin}")


# --------------------------------------------------------------------------
# Programme principal
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Analyse de logs et détection d'anomalies (S5)")
    parser.add_argument("-l", "--log", type=Path, default=LOG_PAR_DEFAUT,
                        help=f"fichier de log à analyser (défaut : {LOG_PAR_DEFAUT})")
    parser.add_argument("-o", "--sortie", type=Path, default=DOSSIER_SORTIE,
                        help="dossier de sortie des rapports")
    parser.add_argument("--annee", type=int, default=datetime.now().year,
                        help="année à utiliser pour les logs syslog (sans année)")
    parser.add_argument("--generer-demo", action="store_true",
                        help="génère un log simulé (avec l'IP réelle de la machine) avant l'analyse")
    parser.add_argument("--scan-reseau", action="store_true",
                        help="avec --generer-demo : utilise des IP trouvées par ping dans le /24 local")
    args = parser.parse_args()

    if args.generer_demo:
        generer_log_demo(args.log, scan_reseau=args.scan_reseau)

    if not args.log.is_file():
        print(f"[!] Fichier de log introuvable : {args.log}", file=sys.stderr)
        print("    Utilisez --generer-demo pour créer un log simulé.", file=sys.stderr)
        return 1

    args.sortie.mkdir(parents=True, exist_ok=True)
    date_jour = datetime.now().strftime("%Y-%m-%d")

    echecs, succes, ignorees = analyser_fichier(args.log, args.annee)
    suspectes = detecter_ip_suspectes(echecs)
    hors_horaires = detecter_hors_horaires(succes)
    nb_echecs = sum(len(v) for v in echecs.values())

    f_rapport = args.sortie / f"rapport_anomalies_{date_jour}.txt"
    f_csv = args.sortie / "ip_suspectes.csv"
    f_fw = args.sortie / "regles_firewall.sh"

    ecrire_rapport(f_rapport, args.log, nb_echecs, suspectes, hors_horaires)
    ecrire_csv(suspectes, f_csv)
    ecrire_regles_firewall(suspectes, f_fw)

    print(f"[+] {nb_echecs} échecs analysés, {len(suspectes)} IP suspecte(s), "
          f"{len(hors_horaires)} connexion(s) hors horaires")
    if ignorees:
        print(f"[i] {ignorees} ligne(s) ignorée(s) (format de date non reconnu)")
    print(f"[+] Rapport  : {f_rapport}")
    print(f"[+] CSV      : {f_csv}")
    print(f"[+] Firewall : {f_fw}")
    return 0


if __name__ == "__main__":
    sys.exit(main())