#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S3 - Sauvegarde automatisée avec vérification d'intégrité

Fonctionnalités :
- Copie d'un répertoire source vers une sauvegarde horodatée
- Calcul du SHA-256 de chaque fichier source
- Calcul du SHA-256 du fichier copié
- Vérification de l'intégrité
- Détection des fichiers manquants ou corrompus
- Journalisation dans journal_sauvegarde.log
- Rotation automatique : conservation des 7 dernières sauvegardes
- Compression ZIP optionnelle
- Calcul du RPO réel en heures depuis la dernière sauvegarde réussie
- Mode ponctuel ou mode automatique toutes les heures

Utilisation :
    python script3_sauvegarde.py --source ./donnees --destination ./sauvegardes
    python script3_sauvegarde.py --source ./donnees --destination ./sauvegardes --zip
    python script3_sauvegarde.py --source ./donnees --destination ./sauvegardes --daemon
"""

import argparse
import hashlib
import logging
import shutil
import time
from datetime import datetime
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

NOMBRE_SAUVEGARDES_A_CONSERVER = 7
INTERVALLE_HEURES = 1
NOM_LOG = "journal_sauvegarde.log"


# ============================================================
# JOURNALISATION
# ============================================================

def configurer_logger(destination: Path):
    """Configure le fichier journal."""
    destination.mkdir(parents=True, exist_ok=True)

    fichier_log = destination / NOM_LOG

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(fichier_log, encoding="utf-8"),
            logging.StreamHandler()
        ]
    )


# ============================================================
# HASH SHA-256
# ============================================================

def calculer_sha256(fichier: Path) -> str:
    """
    Calcule le hash SHA-256 d'un fichier.
    Lecture par blocs pour éviter de charger tout le fichier en mémoire.
    """
    sha256 = hashlib.sha256()

    with fichier.open("rb") as f:
        while True:
            bloc = f.read(1024 * 1024)  # 1 Mo
            if not bloc:
                break

            sha256.update(bloc)

    return sha256.hexdigest()


# ============================================================
# SAUVEGARDE
# ============================================================

def copier_fichier(source: Path, destination: Path):
    """Copie un fichier en conservant ses métadonnées."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def sauvegarder(source: Path, destination: Path):
    """
    Effectue une sauvegarde complète du répertoire source.

    Retourne :
        nombre de fichiers
        taille totale
        nombre de fichiers valides
        liste des erreurs
    """

    date_sauvegarde = datetime.now().strftime("%Y-%m-%d_%H%M")
    dossier_backup = destination / f"backup_{date_sauvegarde}"

    # Eviter d'écraser une sauvegarde existante
    compteur = 1
    dossier_original = dossier_backup

    while dossier_backup.exists():
        dossier_backup = destination / f"{dossier_original.name}_{compteur}"
        compteur += 1

    dossier_backup.mkdir(parents=True, exist_ok=True)

    logging.info("=" * 70)
    logging.info("Début de la sauvegarde")
    logging.info("Source : %s", source)
    logging.info("Destination : %s", dossier_backup)

    nombre_fichiers = 0
    taille_totale = 0
    nombre_valides = 0
    erreurs = []

    debut = time.time()

    # Parcours de tous les fichiers
    for fichier_source in source.rglob("*"):

        if not fichier_source.is_file():
            continue

        # Chemin relatif par rapport au répertoire source
        chemin_relatif = fichier_source.relative_to(source)

        fichier_backup = dossier_backup / chemin_relatif

        try:
            # SHA-256 avant copie
            hash_source = calculer_sha256(fichier_source)

            # Copie
            copier_fichier(fichier_source, fichier_backup)

            # Vérification : le fichier existe-t-il ?
            if not fichier_backup.exists():
                message = f"Fichier manquant après copie : {chemin_relatif}"
                logging.error(message)
                erreurs.append(message)
                continue

            # SHA-256 après copie
            hash_backup = calculer_sha256(fichier_backup)

            nombre_fichiers += 1
            taille_totale += fichier_source.stat().st_size

            # Comparaison des hashes
            if hash_source == hash_backup:
                nombre_valides += 1
            else:
                message = (
                    f"FICHIER CORROMPU : {chemin_relatif} "
                    f"(source={hash_source}, backup={hash_backup})"
                )

                logging.error(message)
                erreurs.append(message)

        except Exception as e:
            message = f"Erreur avec {chemin_relatif} : {e}"
            logging.error(message)
            erreurs.append(message)

    duree = time.time() - debut

    # Résultat de l'intégrité
    integrite_ok = (
        nombre_fichiers > 0
        and nombre_valides == nombre_fichiers
        and len(erreurs) == 0
    )

    logging.info("-" * 70)
    logging.info("Nombre de fichiers copiés : %d", nombre_fichiers)
    logging.info("Taille totale : %d octets", taille_totale)
    logging.info("Fichiers vérifiés avec succès : %d", nombre_valides)
    logging.info("Durée : %.2f secondes", duree)

    if integrite_ok:
        logging.info("INTÉGRITÉ : OK")
        logging.info("Sauvegarde réussie : %s", dossier_backup)
    else:
        logging.error("INTÉGRITÉ : ÉCHEC")
        logging.error("ALERTE : des fichiers sont manquants ou corrompus !")

    return (
        dossier_backup,
        nombre_fichiers,
        taille_totale,
        integrite_ok
    )


# ============================================================
# ROTATION DES SAUVEGARDES
# ============================================================

def rotation_sauvegardes(destination: Path):
    """
    Conserve uniquement les 7 sauvegardes les plus récentes.
    """

    backups = [
        dossier
        for dossier in destination.iterdir()
        if dossier.is_dir() and dossier.name.startswith("backup_")
    ]

    backups.sort(key=lambda x: x.stat().st_mtime, reverse=True)

    anciennes = backups[NOMBRE_SAUVEGARDES_A_CONSERVER:]

    for backup in anciennes:
        try:
            logging.info("Suppression ancienne sauvegarde : %s", backup)
            shutil.rmtree(backup)
        except Exception as e:
            logging.error(
                "Impossible de supprimer %s : %s",
                backup,
                e
            )


# ============================================================
# COMPRESSION ZIP
# ============================================================

def compresser_sauvegarde(dossier_backup: Path):
    """
    Compresse une sauvegarde dans un fichier ZIP.
    """

    fichier_zip = dossier_backup.parent / dossier_backup.name

    try:
        archive = shutil.make_archive(
            str(fichier_zip),
            "zip",
            root_dir=dossier_backup.parent,
            base_dir=dossier_backup.name
        )

        logging.info("Archive ZIP créée : %s", archive)

        return Path(archive)

    except Exception as e:
        logging.error("Erreur pendant la compression : %s", e)
        return None


# ============================================================
# CALCUL DU RPO
# ============================================================

def calculer_rpo(destination: Path):
    """
    Calcule le nombre d'heures depuis la dernière sauvegarde réussie.

    Le fichier journal contient les informations nécessaires.
    """

    backups = [
        dossier
        for dossier in destination.iterdir()
        if dossier.is_dir() and dossier.name.startswith("backup_")
    ]

    if not backups:
        logging.warning("RPO : aucune sauvegarde disponible.")
        return None

    derniere_backup = max(
        backups,
        key=lambda x: x.stat().st_mtime
    )

    date_derniere_backup = datetime.fromtimestamp(
        derniere_backup.stat().st_mtime
    )

    maintenant = datetime.now()

    difference = maintenant - date_derniere_backup
    rpo_heures = difference.total_seconds() / 3600

    logging.info(
        "RPO réel : %.2f heure(s) depuis la dernière sauvegarde (%s)",
        rpo_heures,
        date_derniere_backup.strftime("%Y-%m-%d %H:%M:%S")
    )

    return rpo_heures


# ============================================================
# UNE SAUVEGARDE COMPLÈTE
# ============================================================

def executer_sauvegarde(source: Path, destination: Path, utiliser_zip=False):
    """Exécute toutes les étapes d'une sauvegarde."""

    if not source.exists():
        logging.error("Le répertoire source n'existe pas : %s", source)
        return False

    if not source.is_dir():
        logging.error("La source n'est pas un répertoire : %s", source)
        return False

    try:
        backup, nombre, taille, integrite = sauvegarder(
            source,
            destination
        )

        if integrite:

            # Compression facultative
            if utiliser_zip:
                compresser_sauvegarde(backup)

            # Rotation
            rotation_sauvegardes(destination)

            # RPO
            calculer_rpo(destination)

            logging.info(
                "SAUVEGARDE TERMINÉE AVEC SUCCÈS | "
                "fichiers=%d | taille=%d octets",
                nombre,
                taille
            )

            return True

        else:
            logging.error(
                "SAUVEGARDE TERMINÉE AVEC DES ERREURS."
            )

            return False

    except Exception as e:
        logging.exception(
            "Erreur générale pendant la sauvegarde : %s",
            e
        )
        return False


# ============================================================
# MODE AUTOMATIQUE
# ============================================================

def mode_automatique(source: Path, destination: Path, utiliser_zip=False):
    """
    Lance une sauvegarde toutes les heures.
    """

    logging.info("=" * 70)
    logging.info("MODE AUTOMATIQUE ACTIVÉ")
    logging.info(
        "Une sauvegarde sera effectuée toutes les %d heure(s).",
        INTERVALLE_HEURES
    )

    while True:

        debut = time.time()

        executer_sauvegarde(
            source,
            destination,
            utiliser_zip
        )

        # Temps restant avant la prochaine sauvegarde
        duree_attente = (
            INTERVALLE_HEURES * 60 * 60
            - (time.time() - debut)
        )

        if duree_attente > 0:
            logging.info(
                "Prochaine sauvegarde dans %.2f heure(s).",
                duree_attente / 3600
            )

            try:
                time.sleep(duree_attente)
            except KeyboardInterrupt:
                logging.info("Arrêt demandé par l'utilisateur.")
                break


# ============================================================
# PROGRAMME PRINCIPAL
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="Système de sauvegarde avec vérification SHA-256."
    )

    parser.add_argument(
        "--source",
        required=True,
        help="Répertoire source à sauvegarder"
    )

    parser.add_argument(
        "--destination",
        required=True,
        help="Répertoire dans lequel stocker les sauvegardes"
    )

    parser.add_argument(
        "--zip",
        action="store_true",
        help="Compresse chaque sauvegarde en ZIP"
    )

    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Effectue automatiquement une sauvegarde toutes les heures"
    )

    args = parser.parse_args()

    source = Path(args.source).resolve()
    destination = Path(args.destination).resolve()

    configurer_logger(destination)

    logging.info("SYSTÈME DE SAUVEGARDE S3")
    logging.info("Source : %s", source)
    logging.info("Destination : %s", destination)

    if args.daemon:

        mode_automatique(
            source,
            destination,
            args.zip
        )

    else:

        succes = executer_sauvegarde(
            source,
            destination,
            args.zip
        )

        if succes:
            print("\n✓ Sauvegarde terminée avec succès.")
        else:
            print("\n✗ Sauvegarde terminée avec des erreurs.")


if __name__ == "__main__":
    main()
