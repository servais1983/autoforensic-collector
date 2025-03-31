#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilitaires de hachage pour les preuves forensiques

Ce module fournit des fonctions pour calculer et vérifier les hachages
de fichiers et de données, y compris avec différents algorithmes.
"""

import os
import hashlib
import logging
import json
import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor


def calculate_file_hash(file_path, algorithms=None):
    """
    Calcule les hachages d'un fichier selon plusieurs algorithmes
    
    Args:
        file_path (str): Chemin vers le fichier à hacher
        algorithms (list, optional): Liste des algorithmes à utiliser
                                     Valeur par défaut: ['md5', 'sha1', 'sha256', 'sha512']
    
    Returns:
        dict: Dictionnaire des hachages calculés par algorithme
    """
    if algorithms is None:
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    
    # Initialisation des objets de hachage
    hash_objects = {}
    for algorithm in algorithms:
        if hasattr(hashlib, algorithm):
            hash_objects[algorithm] = getattr(hashlib, algorithm)()
        else:
            logging.warning(f"L'algorithme de hachage {algorithm} n'est pas disponible")
    
    # Vérification que le fichier existe
    if not os.path.isfile(file_path):
        logging.error(f"Impossible de calculer le hash: le fichier {file_path} n'existe pas")
        return {}
    
    # Lecture et hachage du fichier par blocs pour économiser la mémoire
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)  # Lire par blocs de 64k
                if not data:
                    break
                
                for hash_obj in hash_objects.values():
                    hash_obj.update(data)
        
        # Générer le dictionnaire de résultats
        result = {algorithm: hash_obj.hexdigest() for algorithm, hash_obj in hash_objects.items()}
        
        # Ajouter la taille du fichier pour référence
        result['file_size'] = os.path.getsize(file_path)
        
        return result
    
    except Exception as e:
        logging.error(f"Erreur lors du calcul des hashes pour {file_path}: {str(e)}")
        return {}


def calculate_data_hash(data, algorithms=None):
    """
    Calcule les hachages d'une donnée binaire selon plusieurs algorithmes
    
    Args:
        data (bytes): Données à hacher
        algorithms (list, optional): Liste des algorithmes à utiliser
                                     Valeur par défaut: ['md5', 'sha1', 'sha256', 'sha512']
    
    Returns:
        dict: Dictionnaire des hachages calculés par algorithme
    """
    if algorithms is None:
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    
    result = {}
    
    for algorithm in algorithms:
        if hasattr(hashlib, algorithm):
            hash_obj = getattr(hashlib, algorithm)()
            hash_obj.update(data)
            result[algorithm] = hash_obj.hexdigest()
        else:
            logging.warning(f"L'algorithme de hachage {algorithm} n'est pas disponible")
    
    # Ajouter la taille des données pour référence
    result['data_size'] = len(data)
    
    return result


def batch_calculate_hashes(directory, recursive=True, algorithms=None, exclude_patterns=None):
    """
    Calcule les hachages pour tous les fichiers d'un répertoire
    
    Args:
        directory (str): Chemin vers le répertoire
        recursive (bool, optional): Rechercher récursivement dans les sous-répertoires
        algorithms (list, optional): Liste des algorithmes à utiliser
        exclude_patterns (list, optional): Liste de motifs de fichiers à exclure
    
    Returns:
        dict: Dictionnaire des hachages pour chaque fichier
    """
    if algorithms is None:
        algorithms = ['md5', 'sha256']
    
    if exclude_patterns is None:
        exclude_patterns = []
    
    result = {}
    directory_path = Path(directory)
    
    if not directory_path.exists():
        logging.error(f"Le répertoire {directory} n'existe pas")
        return result
    
    # Préparer la liste des fichiers à traiter
    files_to_process = []
    
    if recursive:
        walker = directory_path.rglob('*')
    else:
        walker = directory_path.glob('*')
    
    for file_path in walker:
        if file_path.is_file():
            # Vérifier si le fichier correspond à un motif d'exclusion
            if not any(file_path.match(pattern) for pattern in exclude_patterns):
                files_to_process.append(file_path)
    
    # Utiliser ThreadPoolExecutor pour calculer les hashes en parallèle
    with ThreadPoolExecutor() as executor:
        def process_file(file_path):
            relative_path = file_path.relative_to(directory_path)
            hash_results = calculate_file_hash(str(file_path), algorithms)
            return str(relative_path), hash_results
        
        # Exécuter le traitement en parallèle
        futures = [executor.submit(process_file, file_path) for file_path in files_to_process]
        
        # Récupérer les résultats
        for future in futures:
            try:
                relative_path, hash_results = future.result()
                result[relative_path] = hash_results
            except Exception as e:
                logging.error(f"Erreur lors du calcul de hash: {str(e)}")
    
    return result


def verify_file_hash(file_path, expected_hash, algorithm='sha256'):
    """
    Vérifie si le hachage d'un fichier correspond à une valeur attendue
    
    Args:
        file_path (str): Chemin vers le fichier à vérifier
        expected_hash (str): Valeur de hachage attendue
        algorithm (str, optional): Algorithme de hachage à utiliser. Défaut: 'sha256'
    
    Returns:
        bool: True si le hachage correspond, False sinon
    """
    try:
        calculated_hashes = calculate_file_hash(file_path, [algorithm])
        
        if algorithm not in calculated_hashes:
            logging.error(f"L'algorithme {algorithm} n'a pas pu être utilisé pour le hachage")
            return False
        
        calculated_hash = calculated_hashes[algorithm]
        matches = calculated_hash.lower() == expected_hash.lower()
        
        if matches:
            logging.info(f"Vérification du hash {algorithm} réussie pour {file_path}")
        else:
            logging.warning(
                f"Vérification du hash {algorithm} échouée pour {file_path}. "  
                f"Attendu: {expected_hash}, Calculé: {calculated_hash}"
            )
        
        return matches
    
    except Exception as e:
        logging.error(f"Erreur lors de la vérification du hash pour {file_path}: {str(e)}")
        return False


def generate_hash_report(hash_results, output_file):
    """
    Génère un rapport de hachage au format JSON
    
    Args:
        hash_results (dict): Résultats des hachages
        output_file (str): Chemin du fichier de sortie
    
    Returns:
        bool: True si le rapport a été généré avec succès, False sinon
    """
    try:
        # Créer le répertoire de sortie si nécessaire
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Ajouter des métadonnées au rapport
        report = {
            'generated_at': datetime.datetime.now().isoformat(),
            'file_count': len(hash_results),
            'hashes': hash_results
        }
        
        # Écrire le rapport JSON
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logging.info(f"Rapport de hachage généré avec succès: {output_file}")
        return True
    
    except Exception as e:
        logging.error(f"Erreur lors de la génération du rapport de hachage: {str(e)}")
        return False
