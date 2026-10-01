# Parc-script

## Description

### Plan du dossier

```bash
Parc-script/
    |__base/
    |__logs/
    |__rapport/
        |__analyse_logs/
        |__audit_securite/
        |__inventaire/
        |__rgpd/
        |__sauvegarde/
        |__supervision/
    |__script/
    |__test/
    .gitignore
    README.md
```

Les dossiers de notre projet
- __Base__ : On y trouve les fichiers qui seront utilisé pour la création de rapport
- __logs__ : Les fichiers logs de chaque script
- __rapport__ : on y retrouve les résulthats des scripts
- __Script__ : Le dossier ou se trouve les script a executer
- __test__ : On dossier pour les tests divère

## Les scripts

### Script1_inventaire

Comment lancé le programme

Analyse globale du réseau :

```shell
    python ./script/script.py

    python3 ./script/script.py # En linux
```

Analyse d'une plage précise :

```shell
   python ./script/script.py --debut 192.168.1.10 --fin 192.168.1.50

   python3 ./script/script.py --debut 192.168.1.10 --fin 192.168.1.50 # En linux
```

 Afficher l'aide :

```shell
    python ./script/script.py --help

    python3 ./script/script.py --help # En linux
```

- Si `--debut` et `--fin` ne sont pas renseignés :
   -> le programme analyse le réseau RESEAU

- Si `--debut` et `--fin` sont renseignés :
    -> le programme analyse uniquement la plage indiquée

- `--debut` et `--fin` doivent être utilisés ensemble.


### Script2_audit_securite

AUDIT DE SÉCURITÉ - `WINDOWS` / `LINUX`

Arborescence :

```bash
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
└── rapport/
    └── audi_securite/
```

Le script détecte automatiquement le système :
- __Windows__
- __Linux__

Le template HTML est TOUJOURS recherché ici :
- __mon_projet/base/rapport_conformite.html__

Les logs sont créés ici :
- __mon_projet/logs/__

Les rapports sont créés ici :
- __mon_projet/rapport/audi_securite/__

Aucune bibliothèque Python externe n'est nécessaire.

Lancement du script

```shell
python ./script/script2_audit_securite.py
```

### Script3_sauvegarde

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

Copie d'un dossier vers un autre dossier

```bash
    python script3_sauvegarde.py --source ./donnees --destination ./sauvegardes
```

Copie d'un dossier vers un autre dossier au format __zip__

```shell
    python script3_sauvegarde.py --source ./donnees --destination ./sauvegardes --zip
```

Copie d'un dossier vers un autre dossier tous les n temps

```shell
    python script3_sauvegarde.py --source ./donnees --destination ./sauvegardes --daemon
```

Pour pouvoir utilisé le script dans linux remplacé `python` à `python3`

### Script4_supervision

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

```bash
Parc-script/
├── script/script4_supervision.py
├── logs/supervision.log, incidents.log
└── rapport/supervision/rapport_sla.txt
```

Exemples :
```shell
  python script/script4_supervision.py                      # services de SERVICES_A_SURVEILLER
  python script/script4_supervision.py --auto               # + ports découverts automatiquement
  python script/script4_supervision.py -s "Web=127.0.0.1:8080" -s "DB=127.0.0.1:3306" -s "DNS=8.8.8.8:53"
  # -s 
  python script/script4_supervision.py --intervalle 5 --duree 60   # test rapide d'une minute
  python script/script4_supervision.py --email              # active les alertes e-mail

```

Arrêt : `Ctrl+C` (le rapport SLA est alors finalisé).

Pour une utilisation en Linux, remplacer `python` par `python3`

