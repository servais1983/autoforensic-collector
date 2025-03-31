# AutoForensic Collector

Outil automatisé de collecte de preuves forensiques numériques pour les investigations de sécurité informatique.

## Fonctionnalités

- Collecte automatisée de logs système
- Acquisition de la mémoire (RAM)
- Capture des processus en cours d'exécution
- Extraction des artefacts du système d'exploitation
- Analyse du trafic réseau
- Préservation de la chaîne de preuve avec horodatage et hachage
- Création de rapports détaillés

## Prérequis

- Python 3.8+
- Pour la capture mémoire: LiME (Linux), WinPmem (Windows) ou OSXPmem (macOS)
- Droits administrateur sur le système cible

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/autoforensic-collector.git
cd autoforensic-collector

# Installer les dépendances
pip install -r requirements.txt

# Installer les outils externes nécessaires
# Linux
sudo ./install_dependencies.sh linux

# Windows (exécuter en tant qu'administrateur)
.\install_dependencies.ps1

# macOS
sudo ./install_dependencies.sh macos
```