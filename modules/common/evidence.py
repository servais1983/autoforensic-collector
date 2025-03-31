#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestion des preuves forensiques

Ce module contient les classes pour gérer les preuves collectées
lors d'une investigation forensique.
"""

import os
import json
import logging
import uuid
import datetime
import shutil
from pathlib import Path

from utils.hashing import calculate_file_hash, verify_file_hash


class Evidence:
    """
    Classe représentant une preuve forensique
    """
    
    def __init__(self, evidence_id=None, evidence_type=None, source=None, description=None):
        """
        Initialise un objet preuve
        
        Args:
            evidence_id (str, optional): Identifiant unique de la preuve, généré automatiquement si non fourni
            evidence_type (str, optional): Type de preuve (memory, disk, process, etc.)
            source (str, optional): Source de la preuve (chemin, identifiant de processus, etc.)
            description (str, optional): Description de la preuve
        """
        self.evidence_id = evidence_id or str(uuid.uuid4())
        self.type = evidence_type
        self.source = source
        self.description = description
        self.file_path = None
        self.hash = {}
        self.timestamp = datetime.datetime.now().isoformat()
        self.metadata = {}
    
    def set_file_path(self, file_path):
        """
        Définit le chemin du fichier de preuve
        
        Args:
            file_path (str): Chemin vers le fichier de preuve
        """
        self.file_path = file_path
    
    def calculate_hash(self, algorithms=None):
        """
        Calcule le hachage du fichier de preuve
        
        Args:
            algorithms (list, optional): Liste des algorithmes à utiliser
        
        Returns:
            dict: Dictionnaire des hachages calculés par algorithme
        """
        if not self.file_path or not os.path.exists(self.file_path):
            logging.error(f"Impossible de calculer le hash: fichier de preuve non défini ou inexistant")
            return {}
        
        try:
            self.hash = calculate_file_hash(self.file_path, algorithms)
            return self.hash
        except Exception as e:
            logging.error(f"Erreur lors du calcul du hash pour {self.file_path}: {str(e)}")
            return {}
    
    def verify_integrity(self, algorithm='sha256'):
        """
        Vérifie l'intégrité de la preuve en comparant le hash actuel avec le hash stocké
        
        Args:
            algorithm (str, optional): Algorithme de hachage à utiliser
            
        Returns:
            bool: True si la preuve est intègre, False sinon
        """
        if not self.file_path or not os.path.exists(self.file_path):
            logging.error(f"Impossible de vérifier l'intégrité: fichier de preuve non défini ou inexistant")
            return False
        
        if algorithm not in self.hash:
            logging.error(f"Algorithme {algorithm} non disponible dans les hashes stockés")
            return False
        
        expected_hash = self.hash[algorithm]
        return verify_file_hash(self.file_path, expected_hash, algorithm)
    
    def to_dict(self):
        """
        Convertit l'objet preuve en dictionnaire
        
        Returns:
            dict: Représentation en dictionnaire de l'objet preuve
        """
        return {
            "evidence_id": self.evidence_id,
            "type": self.type,
            "source": self.source,
            "description": self.description,
            "file_path": self.file_path,
            "hash": self.hash,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data):
        """
        Crée un objet preuve à partir d'un dictionnaire
        
        Args:
            data (dict): Données de la preuve
            
        Returns:
            Evidence: Objet preuve créé
        """
        evidence = cls(
            evidence_id=data.get("evidence_id"),
            evidence_type=data.get("type"),
            source=data.get("source"),
            description=data.get("description")
        )
        
        evidence.file_path = data.get("file_path")
        evidence.hash = data.get("hash", {})
        evidence.timestamp = data.get("timestamp")
        evidence.metadata = data.get("metadata", {})
        
        return evidence


class EvidenceManager:
    """
    Classe pour gérer un ensemble de preuves
    """
    
    def __init__(self, evidence_dir, chain_of_custody=None):
        """
        Initialise le gestionnaire de preuves
        
        Args:
            evidence_dir (str): Répertoire de base pour stocker les preuves
            chain_of_custody (ChainOfCustody, optional): Objet de chaîne de preuve
        """
        self.evidence_dir = Path(evidence_dir)
        self.chain_of_custody = chain_of_custody
        self.evidence_index_file = self.evidence_dir / "evidence_index.json"
        self.evidence_items = {}
        
        # Créer le répertoire de preuves s'il n'existe pas
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Charger l'index des preuves s'il existe
        self._load_evidence_index()
    
    def add_evidence(self, evidence_type, source, description, file_path=None, metadata=None):
        """
        Ajoute une nouvelle preuve
        
        Args:
            evidence_type (str): Type de preuve (memory, disk, process, etc.)
            source (str): Source de la preuve (chemin, identifiant de processus, etc.)
            description (str): Description de la preuve
            file_path (str, optional): Chemin vers le fichier de preuve original
            metadata (dict, optional): Métadonnées supplémentaires
            
        Returns:
            str: Identifiant de la preuve ajoutée
        """
        # Créer un nouvel objet preuve
        evidence = Evidence(
            evidence_type=evidence_type,
            source=source,
            description=description
        )
        
        # Ajouter les métadonnées
        if metadata:
            evidence.metadata = metadata
        
        # Copier le fichier de preuve dans le répertoire de preuves si fourni
        if file_path:
            file_path = Path(file_path)
            if file_path.exists():
                # Créer un sous-répertoire pour le type de preuve
                type_dir = self.evidence_dir / evidence_type
                type_dir.mkdir(exist_ok=True)
                
                # Définir le chemin de destination
                dest_file = type_dir / f"{evidence.evidence_id}{file_path.suffix}"
                
                try:
                    # Copier le fichier
                    shutil.copy2(file_path, dest_file)
                    evidence.set_file_path(str(dest_file))
                    
                    # Calculer le hash
                    evidence.calculate_hash()
                    
                    logging.info(f"Fichier de preuve copié: {file_path} -> {dest_file}")
                except Exception as e:
                    logging.error(f"Erreur lors de la copie du fichier de preuve: {str(e)}")
            else:
                logging.warning(f"Fichier de preuve non trouvé: {file_path}")
        
        # Ajouter à la chaîne de preuve si disponible
        if self.chain_of_custody:
            self.chain_of_custody.add_evidence(
                evidence.evidence_id,
                evidence_type,
                source,
                description,
                evidence.metadata
            )
            
            if evidence.file_path and evidence.hash:
                # Mettre à jour la chaîne de preuve avec le hash
                self.chain_of_custody.update_evidence(
                    evidence.evidence_id,
                    "stored",
                    evidence.hash.get("sha256"),
                    evidence.file_path,
                    {"hash_algorithms": list(evidence.hash.keys())}
                )
        
        # Ajouter à notre index local
        self.evidence_items[evidence.evidence_id] = evidence
        self._save_evidence_index()
        
        logging.info(f"Preuve ajoutée: {evidence.evidence_id} ({evidence_type})")
        return evidence.evidence_id
    
    def add_memory_evidence(self, source_system, description, file_path, metadata=None):
        """
        Méthode spécialisée pour ajouter une preuve de mémoire
        
        Args:
            source_system (str): Système source de la mémoire
            description (str): Description de la preuve
            file_path (str): Chemin vers le fichier de mémoire
            metadata (dict, optional): Métadonnées supplémentaires
            
        Returns:
            str: Identifiant de la preuve ajoutée
        """
        if metadata is None:
            metadata = {}
        
        metadata.update({
            "source_system": source_system,
            "capture_time": datetime.datetime.now().isoformat(),
            "memory_format": Path(file_path).suffix.lstrip('.')
        })
        
        return self.add_evidence("memory", source_system, description, file_path, metadata)
    
    def add_disk_evidence(self, source_disk, description, file_path, metadata=None):
        """
        Méthode spécialisée pour ajouter une preuve de disque
        
        Args:
            source_disk (str): Disque source
            description (str): Description de la preuve
            file_path (str): Chemin vers le fichier d'image disque
            metadata (dict, optional): Métadonnées supplémentaires
            
        Returns:
            str: Identifiant de la preuve ajoutée
        """
        if metadata is None:
            metadata = {}
        
        metadata.update({
            "source_disk": source_disk,
            "capture_time": datetime.datetime.now().isoformat(),
            "image_format": Path(file_path).suffix.lstrip('.')
        })
        
        return self.add_evidence("disk", source_disk, description, file_path, metadata)
    
    def add_network_evidence(self, interface, description, file_path, metadata=None):
        """
        Méthode spécialisée pour ajouter une preuve réseau
        
        Args:
            interface (str): Interface réseau source
            description (str): Description de la preuve
            file_path (str): Chemin vers le fichier de capture
            metadata (dict, optional): Métadonnées supplémentaires
            
        Returns:
            str: Identifiant de la preuve ajoutée
        """
        if metadata is None:
            metadata = {}
        
        metadata.update({
            "interface": interface,
            "capture_time": datetime.datetime.now().isoformat(),
            "capture_format": Path(file_path).suffix.lstrip('.')
        })
        
        return self.add_evidence("network", interface, description, file_path, metadata)
    
    def get_evidence(self, evidence_id):
        """
        Récupère une preuve par son identifiant
        
        Args:
            evidence_id (str): Identifiant de la preuve
            
        Returns:
            Evidence: Objet preuve ou None si non trouvé
        """
        return self.evidence_items.get(evidence_id)
    
    def get_all_evidence(self):
        """
        Récupère toutes les preuves
        
        Returns:
            list: Liste de dictionnaires représentant les preuves
        """
        return [evidence.to_dict() for evidence in self.evidence_items.values()]
    
    def get_evidence_by_type(self, evidence_type):
        """
        Récupère les preuves d'un type spécifique
        
        Args:
            evidence_type (str): Type de preuve à récupérer
            
        Returns:
            list: Liste de dictionnaires représentant les preuves du type spécifié
        """
        return [
            evidence.to_dict() for evidence in self.evidence_items.values()
            if evidence.type == evidence_type
        ]
    
    def verify_evidence(self, evidence_id, algorithm='sha256'):
        """
        Vérifie l'intégrité d'une preuve
        
        Args:
            evidence_id (str): Identifiant de la preuve
            algorithm (str, optional): Algorithme de hachage à utiliser
            
        Returns:
            bool: True si la preuve est intègre, False sinon
        """
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            logging.error(f"Preuve {evidence_id} non trouvée")
            return False
        
        result = evidence.verify_integrity(algorithm)
        
        # Mettre à jour la chaîne de preuve si disponible
        if self.chain_of_custody:
            status = "verified_success" if result else "verified_failure"
            self.chain_of_custody.update_evidence(
                evidence_id,
                status,
                metadata={"verification_time": datetime.datetime.now().isoformat()}
            )
        
        return result
    
    def verify_all(self, algorithm='sha256'):
        """
        Vérifie l'intégrité de toutes les preuves
        
        Args:
            algorithm (str, optional): Algorithme de hachage à utiliser
            
        Returns:
            dict: Dictionnaire avec les identifiants de preuve comme clés et les résultats de vérification comme valeurs
        """
        results = {}
        for evidence_id in self.evidence_items:
            results[evidence_id] = self.verify_evidence(evidence_id, algorithm)
        
        return results
    
    def _load_evidence_index(self):
        """
        Charge l'index des preuves depuis le fichier JSON
        """
        if not self.evidence_index_file.exists():
            return
        
        try:
            with open(self.evidence_index_file, 'r') as f:
                data = json.load(f)
                
                if "evidence_items" in data:
                    for item_data in data["evidence_items"]:
                        evidence = Evidence.from_dict(item_data)
                        self.evidence_items[evidence.evidence_id] = evidence
            
            logging.info(f"Index des preuves chargé: {len(self.evidence_items)} preuves trouvées")
        
        except Exception as e:
            logging.error(f"Erreur lors du chargement de l'index des preuves: {str(e)}")
    
    def _save_evidence_index(self):
        """
        Sauvegarde l'index des preuves dans un fichier JSON
        """
        try:
            data = {
                "evidence_items": [evidence.to_dict() for evidence in self.evidence_items.values()],
                "generated_at": datetime.datetime.now().isoformat()
            }
            
            with open(self.evidence_index_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logging.info(f"Index des preuves sauvegardé: {len(self.evidence_items)} preuves")
        
        except Exception as e:
            logging.error(f"Erreur lors de la sauvegarde de l'index des preuves: {str(e)}")
