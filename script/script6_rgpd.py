#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S6 - Rapport de conformité RGPD automatisé
Fichier : script6_rgpd.py

Ce que fait le script :
  - Charge un registre des traitements simplifié depuis un fichier JSON
  - Pour chaque traitement, vérifie : base légale, durée de conservation,
    responsable désigné
  - Calcule un score de conformité global (en %)
  - Identifie les traitements non conformes avec leur niveau de risque
  - Génère un rapport structuré avec les actions correctives recommandées

Niveau avancé :
  - Rapport HTML avec graphique de conformité par catégorie
  - Actions correctives priorisées par niveau de risque (CNIL)
  - Brouillon de notification CNIL si une violation de données est détectée

Fichiers générés (dans rapport/rgpd/) :
  - rapport_rgpd_AAAA-MM-JJ.txt
  - rapport_rgpd.html
  - notification_cnil_draft.txt (uniquement si violation détectée)

Lien avec le projet : conformité RGPD (EF05, EF06) et plan de traitement des
données passagers défini dans le CDC.

Usage :
  python script6_rgpd.py                         # lit script/registre_traitements.json
  python script6_rgpd.py -r mon_registre.json
  python script6_rgpd.py --generer-demo          # crée un registre d'exemple puis l'analyse

Format du JSON (liste de traitements) :
  {
    "organisme": "Aéroport ...",
    "traitements": [
      {
        "id": "T01",
        "nom": "Enregistrement des passagers",
        "categorie": "Données passagers",
        "base_legale": "contrat",
        "duree_conservation": "24 mois",
        "responsable": "Direction exploitation",
        "donnees_sensibles": false,          (optionnel)
        "niveau_risque": "élevé",            (optionnel, sinon calculé)
        "violation_detectee": false,         (optionnel)
        "details_violation": "..."           (optionnel)
      }
    ]
  }
"""

import argparse
import html
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
DOSSIER_SCRIPT = Path(__file__).resolve().parent
RACINE = DOSSIER_SCRIPT.parent                                  # Parc-script/
REGISTRE_PAR_DEFAUT = DOSSIER_SCRIPT / "registre_traitements.json"
DOSSIER_SORTIE = RACINE / "rapport" / "rgpd"

# Bases légales prévues par l'article 6 du RGPD
BASES_LEGALES = {
    "consentement", "contrat", "obligation légale", "obligation legale",
    "intérêts vitaux", "interets vitaux", "mission d'intérêt public",
    "mission d'interet public", "intérêt légitime", "interet legitime",
}

NIVEAUX = ["critique", "élevé", "moyen", "faible"]
ORDRE_RISQUE = {n: i for i, n in enumerate(NIVEAUX)}

CONTROLES = {
    "base_legale": "Base légale (art. 6 RGPD)",
    "duree_conservation": "Durée de conservation (art. 5.1.e)",
    "responsable": "Responsable désigné (art. 24 / 30)",
}

ACTIONS = {
    "base_legale": "Identifier et documenter la base légale du traitement (art. 6 RGPD).",
    "duree_conservation": "Définir et documenter une durée de conservation, avec purge automatique.",
    "responsable": "Désigner un responsable de traitement et le mentionner au registre (art. 30).",
}


# --------------------------------------------------------------------------
# Chargement et vérification
# --------------------------------------------------------------------------
def charger_registre(chemin):
    with open(chemin, "r", encoding="utf-8") as f:
        donnees = json.load(f)
    if isinstance(donnees, list):                       # liste simple acceptée
        donnees = {"organisme": "Non précisé", "traitements": donnees}
    if not isinstance(donnees.get("traitements"), list):
        raise ValueError("Le JSON doit contenir une liste « traitements ».")
    return donnees


def est_renseigne(valeur):
    return isinstance(valeur, str) and valeur.strip() != ""


def verifier_traitement(t):
    """Retourne le dictionnaire des contrôles {clé: True/False}."""
    base = t.get("base_legale")
    return {
        "base_legale": est_renseigne(base) and base.strip().lower() in BASES_LEGALES,
        "duree_conservation": est_renseigne(t.get("duree_conservation")),
        "responsable": est_renseigne(t.get("responsable")),
    }


def niveau_risque(t):
    """Niveau de risque : valeur du JSON si valide, sinon calculé."""
    declare = str(t.get("niveau_risque", "")).strip().lower()
    declare = {"eleve": "élevé", "critical": "critique"}.get(declare, declare)
    if declare in ORDRE_RISQUE:
        return declare
    if t.get("violation_detectee"):
        return "critique"
    if t.get("donnees_sensibles"):
        return "élevé"
    return "moyen"


def analyser(registre):
    resultats = []
    for i, t in enumerate(registre["traitements"], start=1):
        controles = verifier_traitement(t)
        resultats.append({
            "id": t.get("id", f"T{i:02d}"),
            "nom": t.get("nom", "(sans nom)"),
            "categorie": t.get("categorie", "Non classé"),
            "controles": controles,
            "reussis": sum(controles.values()),
            "total": len(controles),
            "conforme": all(controles.values()),
            "risque": niveau_risque(t),
            "violation": bool(t.get("violation_detectee")),
            "details_violation": t.get("details_violation", ""),
            "donnees_sensibles": bool(t.get("donnees_sensibles")),
        })
    return resultats


def pourcentage(reussis, total):
    return round(100 * reussis / total, 1) if total else 0.0


def score_global(resultats):
    return pourcentage(sum(r["reussis"] for r in resultats),
                       sum(r["total"] for r in resultats))


def score_par_categorie(resultats):
    cat = defaultdict(lambda: [0, 0])
    for r in resultats:
        cat[r["categorie"]][0] += r["reussis"]
        cat[r["categorie"]][1] += r["total"]
    return {c: pourcentage(a, b) for c, (a, b) in sorted(cat.items())}


def actions_correctives(resultats):
    """Liste (risque, id, nom, action) triée par priorité de risque."""
    actions = []
    for r in resultats:
        for cle, ok in r["controles"].items():
            if not ok:
                actions.append((r["risque"], r["id"], r["nom"], ACTIONS[cle]))
    actions.sort(key=lambda a: (ORDRE_RISQUE[a[0]], a[1]))
    return actions


def interpretation(score):
    if score >= 90:
        return "Conformité satisfaisante"
    if score >= 70:
        return "Conformité partielle - actions à planifier"
    return "Conformité insuffisante - actions urgentes"


# --------------------------------------------------------------------------
# Rapport texte
# --------------------------------------------------------------------------
def ecrire_rapport_txt(chemin, registre, resultats, fichier):
    score = score_global(resultats)
    non_conformes = [r for r in resultats if not r["conforme"]]
    actions = actions_correctives(resultats)

    L = ["=" * 72, "RAPPORT DE CONFORMITÉ RGPD", "=" * 72,
         f"Organisme         : {registre.get('organisme', 'Non précisé')}",
         f"Date du rapport   : {datetime.now():%Y-%m-%d %H:%M:%S}",
         f"Registre analysé  : {fichier}",
         "Référence projet  : EF05, EF06 (plan de traitement des données passagers)",
         "", "RÉSUMÉ", "-" * 72,
         f"Traitements analysés   : {len(resultats)}",
         f"Traitements conformes  : {len(resultats) - len(non_conformes)}",
         f"Non-conformités        : {len(non_conformes)}",
         f"Score de conformité    : {score} %  ({interpretation(score)})",
         "", "SCORE PAR CATÉGORIE", "-" * 72]
    for cat, s in score_par_categorie(resultats).items():
        L.append(f"{cat:<40}{s:>6} %")

    L += ["", "TRAITEMENTS NON CONFORMES", "-" * 72]
    if non_conformes:
        for r in sorted(non_conformes, key=lambda r: ORDRE_RISQUE[r["risque"]]):
            manques = [CONTROLES[c] for c, ok in r["controles"].items() if not ok]
            L.append(f"[{r['id']}] {r['nom']}  (risque : {r['risque']})")
            for m in manques:
                L.append(f"      - manquant : {m}")
    else:
        L.append("Aucun.")

    L += ["", "ACTIONS CORRECTIVES RECOMMANDÉES (par priorité de risque)", "-" * 72]
    if actions:
        for n, (risque, tid, nom, action) in enumerate(actions, start=1):
            L.append(f"{n:>2}. [{risque.upper()}] {tid} - {nom}")
            L.append(f"      -> {action}")
    else:
        L.append("Aucune action requise.")

    violations = [r for r in resultats if r["violation"]]
    L += ["", "VIOLATIONS DE DONNÉES", "-" * 72]
    if violations:
        L.append(f"{len(violations)} violation(s) détectée(s) : notification à la CNIL "
                 "requise sous 72 h (art. 33 RGPD).")
        L.append("Brouillon généré : notification_cnil_draft.txt")
    else:
        L.append("Aucune violation signalée.")

    chemin.write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Rapport HTML (graphique en barres, sans dépendance externe)
# --------------------------------------------------------------------------
def couleur(score):
    if score >= 90:
        return "#2e9e5b"
    if score >= 70:
        return "#e0a526"
    return "#d64545"


def ecrire_rapport_html(chemin, registre, resultats):
    e = html.escape
    score = score_global(resultats)
    categories = score_par_categorie(resultats)
    actions = actions_correctives(resultats)
    nb_nc = sum(1 for r in resultats if not r["conforme"])

    barres = "\n".join(
        f'<div class="ligne"><span class="lib">{e(c)}</span>'
        f'<div class="piste"><div class="barre" style="width:{s}%;background:{couleur(s)}"></div></div>'
        f'<span class="val">{s} %</span></div>'
        for c, s in categories.items()
    )

    lignes_trait = []
    for r in sorted(resultats, key=lambda r: (r["conforme"], ORDRE_RISQUE[r["risque"]])):
        cases = "".join(
            f'<td class="{"ok" if r["controles"][c] else "ko"}">{"✔" if r["controles"][c] else "✘"}</td>'
            for c in CONTROLES
        )
        lignes_trait.append(
            f'<tr><td>{e(str(r["id"]))}</td><td>{e(r["nom"])}</td><td>{e(r["categorie"])}</td>'
            f'{cases}<td><span class="badge {r["risque"]}">{r["risque"]}</span></td></tr>'
        )

    lignes_actions = "\n".join(
        f'<tr><td><span class="badge {rk}">{rk}</span></td><td>{e(str(tid))}</td>'
        f'<td>{e(nom)}</td><td>{e(act)}</td></tr>'
        for rk, tid, nom, act in actions
    ) or '<tr><td colspan="4">Aucune action requise.</td></tr>'

    entetes = "".join(f"<th>{e(v)}</th>" for v in CONTROLES.values())

    page = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport de conformité RGPD</title>
<style>
  body {{ font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #f3f6fa; color: #1c2a3a; }}
  header {{ background: #003f7f; color: #fff; padding: 24px 32px; }}
  header h1 {{ margin: 0 0 4px; font-size: 24px; }}
  main {{ max-width: 1100px; margin: 24px auto; padding: 0 16px; }}
  section {{ background: #fff; border-radius: 8px; padding: 20px 24px; margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  h2 {{ margin-top: 0; color: #003f7f; font-size: 18px; }}
  .score {{ font-size: 48px; font-weight: 700; color: {couleur(score)}; }}
  .ligne {{ display: flex; align-items: center; gap: 12px; margin: 8px 0; }}
  .lib {{ width: 260px; font-size: 14px; }}
  .piste {{ flex: 1; background: #e4e9f0; border-radius: 6px; height: 18px; overflow: hidden; }}
  .barre {{ height: 100%; }}
  .val {{ width: 60px; text-align: right; font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th {{ background: #003f7f; color: #fff; text-align: left; padding: 8px; }}
  td {{ padding: 8px; border-bottom: 1px solid #e4e9f0; }}
  td.ok {{ color: #2e9e5b; font-weight: 700; text-align: center; }}
  td.ko {{ color: #d64545; font-weight: 700; text-align: center; }}
  .badge {{ padding: 2px 8px; border-radius: 10px; color: #fff; font-size: 12px; }}
  .critique {{ background: #9b1c1c; }} .élevé {{ background: #d64545; }}
  .moyen {{ background: #e0a526; }} .faible {{ background: #2e9e5b; }}
  .scroll {{ overflow-x: auto; }}
</style>
</head>
<body>
<header>
  <h1>Rapport de conformité RGPD</h1>
  <div>{e(registre.get('organisme', 'Non précisé'))} - généré le {datetime.now():%d/%m/%Y à %H:%M}
  - Réf. projet : EF05, EF06</div>
</header>
<main>
<section>
  <h2>Score de conformité global</h2>
  <div class="score">{score} %</div>
  <div>{e(interpretation(score))} - {len(resultats)} traitement(s) analysé(s), {nb_nc} non conforme(s)</div>
</section>
<section>
  <h2>Conformité par catégorie</h2>
  {barres}
</section>
<section>
  <h2>Détail des traitements</h2>
  <div class="scroll"><table>
    <tr><th>ID</th><th>Traitement</th><th>Catégorie</th>{entetes}<th>Risque</th></tr>
    {''.join(lignes_trait)}
  </table></div>
</section>
<section>
  <h2>Actions correctives (priorisées par niveau de risque)</h2>
  <div class="scroll"><table>
    <tr><th>Risque</th><th>ID</th><th>Traitement</th><th>Action recommandée</th></tr>
    {lignes_actions}
  </table></div>
</section>
</main>
</body>
</html>
"""
    chemin.write_text(page, encoding="utf-8")


# --------------------------------------------------------------------------
# Brouillon de notification CNIL (art. 33 RGPD)
# --------------------------------------------------------------------------
def ecrire_notification_cnil(chemin, registre, violations):
    L = ["BROUILLON DE NOTIFICATION DE VIOLATION DE DONNÉES À LA CNIL",
         "(Article 33 du RGPD - à transmettre dans les 72 h après la prise de connaissance)",
         "=" * 72,
         f"Date de rédaction du brouillon : {datetime.now():%Y-%m-%d %H:%M}",
         f"Organisme                      : {registre.get('organisme', 'Non précisé')}",
         "Responsable de traitement      : [à compléter]",
         "Contact DPO / référent         : [à compléter]",
         "Date et heure de la violation  : [à compléter]",
         "Date de prise de connaissance  : [à compléter]",
         "", "TRAITEMENTS CONCERNÉS", "-" * 72]
    for v in violations:
        L.append(f"- [{v['id']}] {v['nom']} (catégorie : {v['categorie']})")
        if v["details_violation"]:
            L.append(f"    Nature : {v['details_violation']}")
        if v["donnees_sensibles"]:
            L.append("    Attention : données sensibles concernées.")
    L += ["",
          "À COMPLÉTER AVANT ENVOI", "-" * 72,
          "1. Nature de la violation (confidentialité / intégrité / disponibilité) : [  ]",
          "2. Catégories et nombre approximatif de personnes concernées            : [  ]",
          "3. Catégories et nombre approximatif d'enregistrements concernés        : [  ]",
          "4. Conséquences probables de la violation                               : [  ]",
          "5. Mesures prises ou envisagées pour y remédier                         : [  ]",
          "6. Personnes concernées informées (art. 34, si risque élevé) ?          : [  ]",
          "",
          "Note : brouillon généré automatiquement, à valider par le DPO / la direction",
          "avant toute transmission via le téléservice de notification de la CNIL."]
    chemin.write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Registre d'exemple (contexte aéroportuaire)
# --------------------------------------------------------------------------
def generer_registre_demo(chemin):
    demo = {
        "organisme": "Aéroport (registre simplifié de démonstration)",
        "traitements": [
            {"id": "T01", "nom": "Enregistrement et embarquement des passagers",
             "categorie": "Données passagers", "base_legale": "contrat",
             "duree_conservation": "24 mois", "responsable": "Direction exploitation"},
            {"id": "T02", "nom": "Données PNR transmises aux autorités",
             "categorie": "Données passagers", "base_legale": "obligation légale",
             "duree_conservation": "", "responsable": "Responsable sûreté",
             "donnees_sensibles": True},
            {"id": "T03", "nom": "Vidéoprotection des terminaux",
             "categorie": "Sûreté et sécurité", "base_legale": "mission d'intérêt public",
             "duree_conservation": "30 jours", "responsable": "Responsable sûreté"},
            {"id": "T04", "nom": "Contrôle d'accès biométrique zone réservée",
             "categorie": "Sûreté et sécurité", "base_legale": "",
             "duree_conservation": "", "responsable": "",
             "donnees_sensibles": True},
            {"id": "T05", "nom": "Gestion de la paie du personnel",
             "categorie": "Ressources humaines", "base_legale": "obligation légale",
             "duree_conservation": "5 ans", "responsable": "DRH"},
            {"id": "T06", "nom": "Wi-Fi public des terminaux (logs de connexion)",
             "categorie": "Systèmes d'information", "base_legale": "obligation légale",
             "duree_conservation": "12 mois", "responsable": "DSI",
             "violation_detectee": True,
             "details_violation": "Accès non autorisé à l'export des logs de connexion"},
            {"id": "T07", "nom": "Newsletter et programme de fidélité",
             "categorie": "Marketing", "base_legale": "consentement",
             "duree_conservation": "3 ans après le dernier contact", "responsable": ""},
        ],
    }
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_text(json.dumps(demo, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Registre de démonstration créé : {chemin}")


# --------------------------------------------------------------------------
# Programme principal
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Rapport de conformité RGPD automatisé (S6)")
    parser.add_argument("-r", "--registre", type=Path, default=REGISTRE_PAR_DEFAUT,
                        help=f"registre des traitements JSON (défaut : {REGISTRE_PAR_DEFAUT})")
    parser.add_argument("-o", "--sortie", type=Path, default=DOSSIER_SORTIE,
                        help="dossier de sortie des rapports")
    parser.add_argument("--generer-demo", action="store_true",
                        help="crée un registre d'exemple dans --registre avant l'analyse")
    args = parser.parse_args()

    if args.generer_demo:
        generer_registre_demo(args.registre)

    if not args.registre.is_file():
        print(f"[!] Registre introuvable : {args.registre}", file=sys.stderr)
        print("    Utilisez --generer-demo pour créer un exemple.", file=sys.stderr)
        return 1

    try:
        registre = charger_registre(args.registre)
    except (json.JSONDecodeError, ValueError) as err:
        print(f"[!] JSON invalide : {err}", file=sys.stderr)
        return 1

    resultats = analyser(registre)
    if not resultats:
        print("[!] Le registre ne contient aucun traitement.", file=sys.stderr)
        return 1

    args.sortie.mkdir(parents=True, exist_ok=True)
    date_jour = datetime.now().strftime("%Y-%m-%d")
    f_txt = args.sortie / f"rapport_rgpd_{date_jour}.txt"
    f_html = args.sortie / "rapport_rgpd.html"
    f_cnil = args.sortie / "notification_cnil_draft.txt"

    ecrire_rapport_txt(f_txt, registre, resultats, args.registre)
    ecrire_rapport_html(f_html, registre, resultats)

    violations = [r for r in resultats if r["violation"]]
    if violations:
        ecrire_notification_cnil(f_cnil, registre, violations)
    elif f_cnil.exists():
        f_cnil.unlink()          # évite de garder un brouillon obsolète

    nb_nc = sum(1 for r in resultats if not r["conforme"])
    print(f"[+] Score de conformité : {score_global(resultats)} % "
          f"({len(resultats)} traitements, {nb_nc} non conforme(s))")
    print(f"[+] Rapport : {f_txt}")
    print(f"[+] HTML    : {f_html}")
    if violations:
        print(f"[!] {len(violations)} violation(s) détectée(s) -> brouillon CNIL : {f_cnil}")
    return 0


if __name__ == "__main__":
    sys.exit(main())