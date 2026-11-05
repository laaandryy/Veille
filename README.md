# Veille technologique

Site vitrine (`index.html`) mis à jour chaque jour par la tâche planifiée **veille**
(GitHub Actions, `.github/workflows/veille.yml`).

## Fonctionnement

1. Chaque jour à 04:17 UTC (avec un passage de rattrapage à 09:43 UTC), le workflow lit `technologies.csv`.
2. Pour chaque technologie, `scripts/veille.py` collecte :
   - la dernière version publiée (GitHub Releases ; kernel.org pour le noyau) ;
   - les billets récents des flux officiels (RSS/Atom) ;
   - les actualités des 30 derniers jours (Google News, FR + EN).
3. Il génère `index.html` et `data/veille.json` (instantané + historique pour repérer les nouveautés),
   puis les pousse sur `main`.

Lancement manuel : onglet **Actions** → **veille** → **Run workflow**.
Modifier `technologies.csv` sur `main` relance aussi la génération.

## Ajouter une technologie

Ajoutez une ligne `Nom;Infos` dans `technologies.csv`. Si la colonne « Informations complémentaires »
contient une URL GitHub, ses releases sont suivies automatiquement. Pour affiner (catégorie, dépôt,
flux officiels, requête de recherche, lien officiel), ajoutez une entrée dans `scripts/sources.json`.

## Filtrage des actualités

Les articles Google News sont filtrés pour écarter publicités, promotions, comparatifs,
tutoriels et billets hors sujet : le nom de la technologie (ou un terme de `match`) doit figurer
dans le titre, et les filtres globaux de `_filtres` dans `scripts/sources.json`
(titres exclus, médias exclus, mots exclus de la recherche) s'appliquent. Ajustez-les librement.

## En local

```bash
python3 scripts/veille.py   # Python 3.10+, aucune dépendance
```

## Version installée

La 3e colonne de `technologies.csv` (« Version installée ») est facultative. Renseignée, elle permet
d'afficher sur la carte « ✓ À jour » ou « Mise à jour → x.y.z » (comparaison avec la dernière release ;
pour le noyau, dans la même branche, ex. 6.1.x) et de signaler les CVE dont la plage vulnérable
contient ta version. Exemple : `Ollama;;0.12.3`.

Pour les produits suivis sur [endoflife.date](https://endoflife.date) (clé `eol` de `sources.json` :
noyau Linux, Debian, Ubuntu, Alpine, Docker Engine, Proxmox VE, VirtualBox), la carte indique
aussi la branche de ta version et sa date de fin de support (⚠ si elle n'est plus supportée), et la
mise à jour est comparée à la dernière version de cette branche.

## Failles (CVE)

L'onglet **Failles CVE** liste, pour chaque technologie, les 5 CVE les plus récentes publiées sur
30 jours dans la base [NVD](https://nvd.nist.gov) : recherche de l'expression `cve` de `sources.json`
dans la description, puis vérification des identifiants CPE (motifs `cpe` de `sources.json`). Une CVE
déjà analysée qui vise un autre produit est écartée. Pour les CVE pas encore analysées par la NVD,
le script consulte [CVE.org](https://www.cve.org) (produits et versions déclarés par l'éditeur dès
la publication, jusqu'à 150 CVE par technologie) ; à défaut, elles restent « À confirmer ». Les CVE touchant ta version installée sont affichées en priorité. Sans clé, la NVD limite le débit (≈ 3 min de collecte). Facultatif : créer
un secret `NVD_API_KEY` (clé gratuite sur nvd.nist.gov) pour accélérer.
