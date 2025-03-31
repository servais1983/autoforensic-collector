#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AutoForensic Collector - Outil automatisé de collecte de preuves forensiques

Ce script principal coordonne la collecte de preuves forensiques
à partir de différents modules spécialisés.
"""

import os
import sys
import argparse
import logging
import platform
import datetime
import json
import hashlib
import shutil
import uuid
from pathlib import Path

# Import des modules de collecte
from modules.common.system import get_system_info, check_privileges
from modules.common.evidence import Evidence, EvidenceManager
from utils.logging import setup_logging
from utils.chain_of_custody import ChainOfCustody
from utils.reporting import ReportGenerator

__version__ = "0.1.0"


def banner():
    """
Affiche la bannière du programme
    """
    print("""
    ╔══════════════════════════════════════════╗
    ║               AUTOFORENSIC                    ║
    ║        Collecteur de Preuves Forensiques      ║
    ║                  v{}                        ║
    ╚══════════════════════════════════════════╝
    """.format(__version__))


def parse_arguments():
    """
    Parse les arguments de ligne de commande
    """
    parser = argparse.ArgumentParser(description="Outil automatisé de collecte de preuves forensiques")
    
    # Options de collecte
    collection_group = parser.add_argument_group('Options de collecte')
    collection_group.add_argument('--all', action='store_true', help='Collecter tous les types de preuves')
    collection_group.add_argument('--memory', action='store_true', help='Capturer la mémoire vive (RAM)')
    collection_group.add_argument('--disk', action='store_true', help='Créer une image du disque ou des partitions spécifiques')
    collection_group.add_argument('--processes', action='store_true', help='Capturer les processus en cours d\'exécution')
    collection_group.add_argument('--network', action='store_true', help='Collecter les informations réseau et le trafic')
    collection_group.add_argument('--logs', action='store_true', help='Récupérer les logs système')
    collection_group.add_argument('--artifacts', action='store_true', help='Extraire les artefacts spécifiques au système d\'exploitation')
    collection_group.add_argument('--browser', action='store_true', help='Collecter les artefacts des navigateurs web')
    
    # Options générales
    parser.add_argument('--output', type=str, default='evidence_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'),
                       help='Dossier de sortie pour les preuves collectées')
    parser.add_argument('--compress', action='store_true', help='Compresser les résultats avec chiffrement')
    parser.add_argument('--verify', action='store_true', help='Vérifier l\'intégrité des preuves collectées')
    parser.add_argument('--report', type=str, choices=['html', 'pdf', 'json'], default='html',
                       help='Format du rapport à générer')
    parser.add_argument('--verbose', '-v', action='count', default=0, help='Niveau de verbosité (v, vv, vvv)')
    parser.add_argument('--version', action='version', version=f'AutoForensic Collector v{__version__}')
    
    return parser.parse_args()


def setup_environment(args):
    """
    Configure l'environnement d'exécution
    """
    # Configurer la journalisation
    log_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    log_level = log_levels[min(args.verbose, len(log_levels) - 1)]
    
    log_dir = os.path.join(args.output, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f'autoforensic_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    
    setup_logging(log_level, log_file)
    logging.info(f"AutoForensic Collector v{__version__} démarré")
    
    # Créer la structure de dossiers pour les preuves
    evidence_dirs = ['memory', 'disk', 'processes', 'network', 'logs', 'artifacts', 'browser', 'reports']
    for dir_name in evidence_dirs:
        os.makedirs(os.path.join(args.output, dir_name), exist_ok=True)
    
    # Initialißer la chaîne de preuve
    case_id = str(uuid.uuid4())
    chain_of_custody = ChainOfCustody(case_id, args.output)
    chain_of_custody.init_case()
    
    return chain_of_custody


def load_modules(args):
    """
    Charge dynamiquement les modules de collecte en fonction des arguments
    """
    modules = []
    
    if args.all or args.memory:
        from modules.memory.collector import MemoryCollector
        modules.append(MemoryCollector(args.output))
    
    if args.all or args.disk:
        from modules.disk.collector import DiskCollector
        modules.append(DiskCollector(args.output))
    
    if args.all or args.processes:
        from modules.process.collector import ProcessCollector
        modules.append(ProcessCollector(args.output))
    
    if args.all or args.network:
        from modules.network.collector import NetworkCollector
        modules.append(NetworkCollector(args.output))
    
    if args.all or args.logs:
        from modules.logs.collector import LogsCollector
        modules.append(LogsCollector(args.output))
    
    if args.all or args.artifacts:
        from modules.artifacts.collector import ArtifactsCollector
        modules.append(ArtifactsCollector(args.output))
    
    if args.all or args.browser:
        from modules.browser.collector import BrowserCollector
        modules.append(BrowserCollector(args.output))
    
    return modules


def main():
    """
    Fonction principale du programme
    """
    # Afficher la bannière
    banner()
    
    # Vérifier les privilèges
    if not check_privileges():
        print("[!] Erreur : Ce programme nécessite des privilèges administrateur pour fonctionner correctement")
        print("    Veuillez relancer avec sudo (Linux/macOS) ou en tant qu'administrateur (Windows)")
        sys.exit(1)
    
    # Parser les arguments
    args = parse_arguments()
    
    # Si aucune option de collecte n'est spécifiée, afficher l'aide
    if not any([args.all, args.memory, args.disk, args.processes, args.network, 
                args.logs, args.artifacts, args.browser]):
        print("[!] Erreur : Vous devez spécifier au moins une option de collecte ou utiliser --all")
        print("    Utiliser -h pour afficher l'aide")
        sys.exit(1)
    
    try:
        # Configurer l'environnement
        chain_of_custody = setup_environment(args)
        logging.info(f"Environnement configuré. ID du cas : {chain_of_custody.case_id}")
        
        # Obtenir les informations système
        system_info = get_system_info()
        logging.info(f"Informations système collectées : {system_info['os_name']} {system_info['os_version']}")
        
        # Charger les modules
        modules = load_modules(args)
        logging.info(f"{len(modules)} modules de collecte chargés")
        
        # Gestionnaire de preuves
        evidence_manager = EvidenceManager(args.output, chain_of_custody)
        
        # Exécuter chaque module de collecte
        for module in modules:
            print(f"[*] Exécution du module : {module.name}")
            try:
                module.collect(evidence_manager)
                print(f"[+] Module {module.name} exécuté avec succès")
            except Exception as e:
                logging.error(f"Erreur lors de l'exécution du module {module.name}: {str(e)}")
                print(f"[!] Erreur dans le module {module.name}: {str(e)}")
        
        # Vérifier l'intégrité si demandé
        if args.verify:
            print("[*] Vérification de l'intégrité des preuves collectées...")
            verification_results = evidence_manager.verify_all()
            if all(verification_results.values()):
                print("[+] Toutes les preuves sont intègres")
            else:
                print("[!] Attention : Certaines preuves ont échoué à la vérification d'intégrité")
                for evidence_id, is_valid in verification_results.items():
                    if not is_valid:
                        print(f"    - Preuve {evidence_id} : ÉCHEC DE VÉRIFICATION")
        
        # Compresser les résultats si demandé
        if args.compress:
            print("[*] Compression des preuves collectées...")
            from utils.compression import compress_evidence
            archive_path = compress_evidence(args.output)
            print(f"[+] Compression terminée : {archive_path}")
        
        # Générer le rapport
        print(f"[*] Génération du rapport au format {args.report}...")
        report_generator = ReportGenerator(args.output, chain_of_custody)
        report_path = report_generator.generate_report(args.report, evidence_manager, system_info)
        print(f"[+] Rapport généré : {report_path}")
        
        # Finaliser la chaîne de preuve
        chain_of_custody.finalize_case()
        
        print("\n[+] Collecte de preuves forensiques terminée avec succès")
        print(f"[+] Les résultats sont disponibles dans : {os.path.abspath(args.output)}")
        
    except KeyboardInterrupt:
        print("\n[!] Opération interrompue par l'utilisateur")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Erreur critique : {str(e)}")
        print(f"\n[!] Erreur critique : {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()