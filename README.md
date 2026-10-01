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
- Base : On y trouve les fichiers qui seront utilisé pour la création de rapport
- logs : Les fichiers logs de chaque script
- rapport : on y retrouve les résulthats des scripts
- Script : Le dossier ou se trouve les script a executer
- test : On dossier pour les tests divère

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

```txt
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

