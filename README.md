# AutoForensic Collector

Outil automatisé de collecte de preuves forensiques numériques pour les investigations de sécurité informatique.

## À propos

AutoForensic Collector est un outil multiplateforme conçu pour automatiser et standardiser la collecte de preuves lors d'investigations informatiques. L'outil maintient une chaîne de preuve vérifiable cryptographiquement, ce qui est essentiel pour les investigations formelles et légales.

## Fonctionnalités

- **Collecte automatisée de preuves** sur divers systèmes d'exploitation (Windows, Linux, macOS)
- **Acquisition de la mémoire (RAM)** avec divers outils selon la plateforme (WinPmem, LiME, OSXPmem)
- **Maintien d'une chaîne de preuve** cryptographique pour garantir l'intégrité des données
- **Vérification d'intégrité** via des hachages cryptographiques (MD5, SHA1, SHA256, SHA512)
- **Génération de rapports** formatés (HTML, PDF, JSON)
- **Compression et chiffrement** des données collectées pour un stockage et une transmission sécurisés

## Architecture

L'outil est structuré de manière modulaire pour faciliter l'extension et la maintenance:

```
├── autoforensic.py              # Script principal
├── modules/                     # Modules de collecte
│   ├── common/                  # Fonctionnalités communes
│   │   ├── evidence.py          # Gestion des preuves
│   │   └── system.py            # Informations système
│   └── memory/                  # Module de capture mémoire
│       └── collector.py         # Collecteur de mémoire
└── utils/                       # Utilitaires
    ├── chain_of_custody.py      # Gestion chaîne de preuve
    ├── compression.py           # Compression et chiffrement
    ├── hashing.py               # Calcul et vérification des hachages
    ├── logging.py               # Journalisation des opérations
    └── reporting.py             # Génération de rapports
```

## Prérequis

- Python 3.8+
- Privilèges administratifs (pour la capture mémoire et certaines opérations système)
- Dépendances Python listées dans `requirements.txt`
- Outils spécifiques selon les besoins (installés automatiquement sur certaines plateformes):
  - **Windows**: WinPmem
  - **Linux**: LiME (Linux Memory Extractor), AVML
  - **macOS**: OSXPmem

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/servais1983/autoforensic-collector.git
cd autoforensic-collector
```

### 2. Installer les dépendances Python

```bash
pip install -r requirements.txt
```

Si vous rencontrez des problèmes avec certaines dépendances, vous pouvez installer uniquement les composants essentiels:

```bash
pip install python-dateutil pytz psutil jinja2 cryptography markdown
```

### 3. Installation des outils additionnels (facultatif)

Certains outils spécialisés peuvent être nécessaires pour des fonctionnalités avancées:

#### Windows
Téléchargez WinPmem depuis https://github.com/Velocidex/WinPmem/releases et placez-le dans le dossier `bin/`:

```bash
mkdir -p bin
# Placer winpmem_x64.exe ou winpmem_x86.exe dans le dossier bin
```

#### Linux
Pour LiME (capture mémoire):

```bash
# Installation des outils de développement
sudo apt-get install linux-headers-$(uname -r) build-essential git
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make
sudo cp lime-$(uname -r).ko /lib/modules/$(uname -r)/misc/lime.ko
```

#### macOS
Pour OSXPmem:

```bash
# Pas d'installation automatisée, obtenez OSXPmem et placez-le dans bin/
mkdir -p bin
# Placer osxpmem dans le dossier bin
```

## Utilisation

### Afficher l'aide

```bash
python autoforensic.py --help
```

### Collecte complète de preuves

En tant qu'administrateur/root:

```bash
# Windows (PowerShell en tant qu'administrateur)
python autoforensic.py --all --output evidence_windows

# Linux
sudo python autoforensic.py --all --output evidence_linux

# macOS
sudo python autoforensic.py --all --output evidence_macos
```

### Collecte sélective

Vous pouvez choisir les modules spécifiques à exécuter:

```bash
# Capture mémoire uniquement
sudo python autoforensic.py --memory --output memory_evidence

# Capture processus et réseau
sudo python autoforensic.py --processes --network --output process_network_evidence
```

### Options importantes

- `--all`: Exécute tous les modules de collecte
- `--memory`: Capture la mémoire vive (RAM)
- `--processes`: Capture l'état des processus en cours d'exécution
- `--network`: Capture les informations réseau
- `--logs`: Collecte les logs système
- `--artifacts`: Collecte les artefacts spécifiques au système d'exploitation
- `--output DIR`: Spécifie le répertoire de sortie (par défaut: evidence_YYYYMMDD_HHMMSS)
- `--compress`: Compresse les résultats avec chiffrement
- `--verify`: Vérifie l'intégrité des preuves collectées après la collecte
- `--report FORMAT`: Génère un rapport au format spécifié (html, pdf, json)

## Fonctionnement détaillé des modules

### Module mémoire

Le module mémoire utilise différents outils selon la plateforme détectée:

1. **Windows**: Utilise WinPmem pour capturer la mémoire physique
2. **Linux**: Utilise LiME (de préférence) ou AVML, avec repli sur dd si nécessaire
3. **macOS**: Utilise OSXPmem

Chaque image mémoire est horodatée et un hachage cryptographique est calculé pour garantir l'intégrité.

### Chaîne de preuve

Toutes les actions sont enregistrées dans un fichier de chaîne de preuve qui documente:
- Qui a effectué l'opération (utilisateur)
- Quand elle a été effectuée (horodatage précis)
- Sur quel système (informations détaillées)
- Ce qui a été collecté (détails de la preuve)
- Hachages cryptographiques des preuves

Ce fichier est lui-même protégé contre les modifications.

### Génération de rapports

L'outil peut générer des rapports détaillés qui incluent:
- Informations sur le système analysé
- Liste des preuves collectées
- Statistiques sur les fichiers (taille, extensions, etc.)
- Métadonnées associées aux preuves
- Informations sur la chaîne de preuve

## Considérations légales

L'utilisation de cet outil doit se faire dans un cadre légal et avec les autorisations appropriées. L'utilisation sans consentement ou autorisation légale peut constituer une infraction, voire un délit selon les juridictions.

## Extension et développement

Vous pouvez étendre cet outil en ajoutant de nouveaux modules dans le dossier `modules/`. 
Chaque module doit implémenter une classe avec au moins la méthode `collect(evidence_manager)`.

Exemple de structure pour un nouveau module:

```python
class MyNewCollector:
    def __init__(self, output_dir):
        self.name = "My New Collector"
        self.output_dir = Path(output_dir) / "mynew"
        self.output_dir.mkdir(exist_ok=True)
        # Initialisation
    
    def collect(self, evidence_manager):
        # Logique de collecte de preuves
        # Utiliser evidence_manager.add_evidence() pour ajouter des preuves
        return True  # ou False en cas d'échec
```

## Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## Contribution

Les contributions sont les bienvenues! N'hésitez pas à soumettre des pull requests ou à signaler des problèmes.

## Contact

Pour toute question ou assistance, veuillez créer une issue sur GitHub.

## Avertissement de sécurité

Cet outil manipule des données potentiellement sensibles. Manipulez les preuves collectées avec précaution et assurez-vous qu'elles soient stockées de manière sécurisée.