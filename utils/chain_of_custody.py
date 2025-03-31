#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion de la chaîne de preuve

Ce module implémente les fonctions nécessaires pour maintenir
une chaîne de preuve cryptographiquement vérifiable pour les preuves collectées.
"""

import os
import json
import datetime
import hashlib
import platform
import logging
import getpass
import uuid
from pathlib import Path


class ChainOfCustody:
    """
    Classe pour gérer la chaîne de preuve et l'intégrité des preuves collectées
    """
    
    def __init__(self, case_id, output_dir):
        """
        Initialise la chaîne de preuve
        
        Args:
            case_id (str): Identifiant unique pour le cas
            output_dir (str): Répertoire de sortie pour les preuves
        """
        self.case_id = case_id
        self.output_dir = output_dir
        self.custody_file = os.path.join(output_dir, "chain_of_custody.json")
        self.evidence_log = []
        self.start_time = datetime.datetime.now()
        self.end_time = None
        self.operator = getpass.getuser()
        self.system_info = self._get_system_info()
    
    def _get_system_info(self):
        """
        Collecte des informations sur le système utilisé pour la collecte
        
        Returns:
            dict: Informations sur le système
        """
        return {
            "hostname": platform.node(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version()
        }
    
    def init_case(self):
        """
        Initialise un nouveau cas d'investigation
        """
        self.case_data = {
            "case_id": self.case_id,
            "start_time": self.start_time.isoformat(),
            "operator": self.operator,
            "collection_system": self.system_info,
            "evidence_items": [],
            "audit_log": [self._create_audit_entry("Case initialized")]
        }
        
        # Créer le fichier initial de chaîne de preuve
        self._save_custody_file()
        logging.info(f"Chaîne de preuve initialisée pour le cas {self.case_id}")
    
    def add_evidence(self, evidence_id, evidence_type, source, description, metadata=None):
        """
        Ajoute un élément de preuve à la chaîne de preuve
        
        Args:
            evidence_id (str): Identifiant unique de la preuve
            evidence_type (str): Type de preuve (memory, disk, etc.)
            source (str): Source de la preuve (chemin, identifiant de processus, etc.)
            description (str): Description de la preuve
            metadata (dict, optional): Métadonnées supplémentaires sur la preuve
        
        Returns:
            str: Identifiant de la preuve ajoutée
        """
        if metadata is None:
            metadata = {}
        
        timestamp = datetime.datetime.now()
        
        evidence_item = {
            "evidence_id": evidence_id,
            "type": evidence_type,
            "source": source,
            "description": description,
            "metadata": metadata,
            "timestamp": timestamp.isoformat(),
            "added_by": self.operator,
        }
        
        self.case_data["evidence_items"].append(evidence_item)
        self.case_data["audit_log"].append(
            self._create_audit_entry(f"Evidence added: {evidence_id} ({evidence_type})")
        )
        
        self._save_custody_file()
        logging.info(f"Preuve {evidence_id} ajoutée à la chaîne de preuve")
        
        return evidence_id
    
    def update_evidence(self, evidence_id, status, hash_value=None, location=None, metadata=None):
        """
        Met à jour les informations sur une preuve existante
        
        Args:
            evidence_id (str): Identifiant de la preuve à mettre à jour
            status (str): Nouveau statut de la preuve
            hash_value (str, optional): Valeur de hachage de la preuve
            location (str, optional): Emplacement de stockage de la preuve
            metadata (dict, optional): Métadonnées supplémentaires
        """
        for evidence in self.case_data["evidence_items"]:
            if evidence["evidence_id"] == evidence_id:
                evidence["status"] = status
                
                if hash_value:
                    evidence["hash"] = hash_value
                
                if location:
                    evidence["location"] = location
                
                if metadata:
                    if "metadata" not in evidence:
                        evidence["metadata"] = {}
                    evidence["metadata"].update(metadata)
                
                evidence["last_updated"] = datetime.datetime.now().isoformat()
                
                self.case_data["audit_log"].append(
                    self._create_audit_entry(f"Evidence updated: {evidence_id} ({status})")
                )
                
                self._save_custody_file()
                logging.info(f"Preuve {evidence_id} mise à jour dans la chaîne de preuve")
                return True
        
        logging.warning(f"Tentative de mise à jour d'une preuve inexistante: {evidence_id}")
        return False
    
    def verify_evidence(self, evidence_id, file_path):
        """
        Vérifie l'intégrité d'une preuve par rapport à son hash enregistré
        
        Args:
            evidence_id (str): Identifiant de la preuve à vérifier
            file_path (str): Chemin vers le fichier de preuve à vérifier
            
        Returns:
            bool: True si la preuve est intègre, False sinon
        """
        for evidence in self.case_data["evidence_items"]:
            if evidence["evidence_id"] == evidence_id and "hash" in evidence:
                stored_hash = evidence["hash"]
                calculated_hash = self._calculate_file_hash(file_path)
                
                is_valid = stored_hash == calculated_hash
                
                self.case_data["audit_log"].append(
                    self._create_audit_entry(
                        f"Evidence verification: {evidence_id}, {'SUCCESS' if is_valid else 'FAILED'}"
                    )
                )
                
                self._save_custody_file()
                
                if is_valid:
                    logging.info(f"Vérification de la preuve {evidence_id} réussie")
                else:
                    logging.warning(f"Vérification de la preuve {evidence_id} échouée. Possible altération!")
                
                return is_valid
        
        logging.warning(f"Preuve {evidence_id} non trouvée ou sans hash dans la chaîne de preuve")
        return False
    
    def finalize_case(self):
        """
        Finalise le cas en ajoutant une entrée de fin dans l'audit log
        """
        self.end_time = datetime.datetime.now()
        self.case_data["end_time"] = self.end_time.isoformat()
        self.case_data["audit_log"].append(self._create_audit_entry("Case finalized"))
        self._save_custody_file()
        logging.info(f"Cas {self.case_id} finalisé")
    
    def _create_audit_entry(self, action):
        """
        Crée une entrée dans le journal d'audit
        
        Args:
            action (str): Action réalisée
            
        Returns:
            dict: Entrée d'audit
        """
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "action": action,
            "user": self.operator,
            "hostname": self.system_info["hostname"]
        }
    
    def _calculate_file_hash(self, file_path):
        """
        Calcule le hash SHA-256 d'un fichier
        
        Args:
            file_path (str): Chemin vers le fichier
            
        Returns:
            str: Hash SHA-256 du fichier
        """
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Erreur lors du calcul du hash pour {file_path}: {str(e)}")
            return None
    
    def _save_custody_file(self):
        """
        Sauvegarde le fichier de chaîne de preuve au format JSON
        """
        try:
            with open(self.custody_file, "w") as f:
                json.dump(self.case_data, f, indent=2)
        except Exception as e:
            logging.error(f"Erreur lors de l'enregistrement du fichier de chaîne de preuve: {str(e)}")
