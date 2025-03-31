#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration et gestion de la journalisation pour AutoForensic
"""

import os
import logging
import datetime
from logging.handlers import RotatingFileHandler


def setup_logging(log_level=logging.INFO, log_file=None):
    """
    Configure la journalisation pour l'application
    
    Args:
        log_level (int): Niveau de journalisation (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file (str, optional): Chemin vers le fichier de log. Si None, ne journalise que dans la console.
    """
    # Formateur pour les logs
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Configuration de la journalisation racine
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Supprime les gestionnaires existants pour éviter les doublons
    for handler in root_logger.handlers[:]: 
        root_logger.removeHandler(handler)
    
    # Ajoute un gestionnaire pour la console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)
    
    # Ajoute un gestionnaire pour le fichier si spécifié
    if log_file:
        try:
            # Crée le répertoire du fichier de log si nécessaire
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            # Utilisation d'un RotatingFileHandler pour éviter des fichiers trop volumineux
            file_handler = RotatingFileHandler(
                log_file, 
                maxBytes=10485760,  # 10 Mo maximum
                backupCount=5,      # Conserver 5 sauvegardes
                encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            root_logger.addHandler(file_handler)
            
            logging.info(f"Journalisation configurée dans le fichier: {log_file}")
        except Exception as e:
            logging.error(f"Impossible de configurer la journalisation dans le fichier {log_file}: {str(e)}")
    
    # Définit un niveau plus élevé pour certains modules externes
    # trop verbeux qui pourraient inonder les logs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)


class ForensicLogger:
    """
    Classe utilitaire pour faciliter la journalisation forensique
    avec des marquages temporels et d'audit
    """
    
    def __init__(self, module_name, operator=None, case_id=None):
        """
        Initialise un logger forensique
        
        Args:
            module_name (str): Nom du module utilisant ce logger
            operator (str, optional): Nom de l'opérateur
            case_id (str, optional): Identifiant du cas forensique
        """
        self.logger = logging.getLogger(module_name)
        self.operator = operator
        self.case_id = case_id
    
    def _format_message(self, message):
        """
        Formate un message avec les informations d'audit
        
        Args:
            message (str): Message à formater
            
        Returns:
            str: Message formaté
        """
        prefix = ""
        
        if self.case_id:
            prefix += f"[Case: {self.case_id}] "
        
        if self.operator:
            prefix += f"[Op: {self.operator}] "
        
        return f"{prefix}{message}"
    
    def debug(self, message):
        """
        Journalise un message de niveau DEBUG
        
        Args:
            message (str): Message à journaliser
        """
        self.logger.debug(self._format_message(message))
    
    def info(self, message):
        """
        Journalise un message de niveau INFO
        
        Args:
            message (str): Message à journaliser
        """
        self.logger.info(self._format_message(message))
    
    def warning(self, message):
        """
        Journalise un message de niveau WARNING
        
        Args:
            message (str): Message à journaliser
        """
        self.logger.warning(self._format_message(message))
    
    def error(self, message):
        """
        Journalise un message de niveau ERROR
        
        Args:
            message (str): Message à journaliser
        """
        self.logger.error(self._format_message(message))
    
    def critical(self, message):
        """
        Journalise un message de niveau CRITICAL
        
        Args:
            message (str): Message à journaliser
        """
        self.logger.critical(self._format_message(message))
    
    def evidence(self, evidence_id, action, status):
        """
        Journalise une action sur une preuve
        
        Args:
            evidence_id (str): Identifiant de la preuve
            action (str): Action effectuée (collect, hash, verify, etc.)
            status (str): Statut de l'action (success, failure, etc.)
        """
        self.logger.info(
            self._format_message(f"EVIDENCE - ID: {evidence_id}, Action: {action}, Status: {status}")
        )
