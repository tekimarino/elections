# Bonoua – Suivi des résultats (Municipales) – Flask + JSON

Application web (MVP) pour **saisir** les résultats par **bureau de vote**, **calculer automatiquement** les pourcentages et le **classement**, et **afficher** les résultats en quasi temps réel (rafraîchissement automatique côté navigateur).

Fonctionnalités basées sur le workflow décrit dans le document *Elections 2023* (représentant par bureau, saisie des scores, calcul %, classement, affichage temps réel, import CSV d'affectations). 

## Nouveautés V1.6

- Admin → **PV saisis** : filtre par **centre de vote** + filtre par **statut**.
- Admin → **Centres de vote** : badges (V/A/R/N) pour voir instantanément les PV validés / en attente / rejetés / non soumis.


## 1) Installation (local)

```bash
python -m venv .venv
# Windows (PowerShell/CMD):
.venv\Scripts\activate
# Git Bash:
source .venv/Scripts/activate
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements.txt
```

## 2) Lancer l’application

```bash
python run.py
```

Puis ouvrir: http://127.0.0.1:5000

## 3) Comptes par défaut

- **Admin**
  - username: `admin`

- **Superviseur (centre)**
  - username: `sup001`
  - password: `Sup123!`
  - centre: `001` (modifiable via l’admin)

- **Représentants**
  - username: `rep1` / password: `Rep123!`
  - username: `rep2` / password: `Rep123!`

> Vous pouvez modifier/ajouter des comptes via l’interface Admin (menu **Représentants / Utilisateurs**).
> Règle: **1 superviseur unique par centre**.

## 4) Données stockées en JSON (sans base de données)

Tout est stocké dans `app/data/` :
- `candidates.json`
- `polling_stations.json`
- `users.json`
- `results.json`
- `meta.json`

⚠️ Pour une utilisation “gros trafic” (beaucoup d’écritures en parallèle), il est recommandé de passer à PostgreSQL. Ce MVP reste volontairement en JSON, comme demandé.

## 5) Import CSV des affectations

Menu Admin → **Affectations (CSV)**

Format CSV attendu (en-têtes obligatoires) :

```csv
username,polling_station_code
rep1,BONOUA-001-BV01
rep2,BONOUA-001-BV02
```

Après import, chaque représentant ne peut saisir que **son** bureau.

## 6) Affichage en temps réel

Page publique: `/results`  
Le navigateur rafraîchit la synthèse automatiquement (polling toutes les 3 secondes).

⚠️ Les résultats publics ne comptent **que** les PV **validés par un superviseur**.

## 7) Structure

- `run.py` : point d’entrée
- `app/app.py` : routes Flask
- `app/utils/storage.py` : lecture/écriture JSON atomique + lock
- `app/utils/calc.py` : consolidation et calcul des %/classement
- `app/templates/` : pages HTML (Bootstrap via CDN)

## 8) Déploiement (simple)

- Un serveur Linux + Python 3.10+
- Lancer avec gunicorn (1 worker recommandé en JSON)

Exemple:

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:8000 run:app
```



## Centres de vote et inscrits (Bonoua)
- Les centres (lieux de vote) sont dans `app/data/voting_centers.json`.
- Les bureaux (avec inscrits) sont dans `app/data/polling_stations.json`.
- Les CSV prêts à importer sont dans `data_import/centres_vote_bonoua.csv` et `data_import/bureaux_vote_bonoua.csv`.


## 4) Gestion (Modifier / Supprimer)

Dans l’interface admin, **Centres de vote**, **Bureaux**, **Représentants**, **Candidats** et **PV** disposent de boutons **Modifier** et **Supprimer**.

Règles de suppression (sécurité) :
- **Centre** : suppression **interdite** tant qu’il contient des bureaux de vote.
- **Bureau** : suppression **interdite** si un **PV** existe pour ce bureau (supprimez d’abord le PV).
- **Représentant** : suppression autorisée (les affectations sont nettoyées).



## V1.7.3
- Bouton Activer/Désactiver (archiver) une élection depuis la page Élections.
- Support propre du cas “aucune élection active”.
