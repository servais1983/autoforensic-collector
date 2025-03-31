#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte de mémoire

Ce module implémente les fonctionnalités de collecte de la mémoire vive (RAM)
d'un système pour des analyses forensiques.
"""

import os
import sys
import platform
import logging
import subprocess
import datetime
import tempfile
import shutil
from pathlib import Path

from modules.common.system import check_privileges
from utils.logging import ForensicLogger


class MemoryCollector:
    """
    Classe pour la collecte de la mémoire RAM
    """
    
    def __init__(self, output_dir):
        """
        Initialise le collecteur de mémoire
        
        Args:
            output_dir (str): Répertoire de sortie pour les preuves collectées
        """
        self.name = "Memory Collector"
        self.output_dir = Path(output_dir) / "memory"
        self.output_dir.mkdir(exist_ok=True)
        self.logger = ForensicLogger("memory_collector")
        
        # Déterminer les outils disponibles
        self.available_tools = self._detect_memory_tools()
        
        if not self.available_tools:
            self.logger.warning("Aucun outil de capture mémoire n'a été détecté sur le système")
        else:
            self.logger.info(f"Outils de capture mémoire détectés: {', '.join(self.available_tools.keys())}")
    
    def collect(self, evidence_manager):
        """
        Collecte une image de la mémoire RAM
        
        Args:
            evidence_manager (EvidenceManager): Gestionnaire de preuves
            
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        # Vérifier les privilèges
        if not check_privileges():
            self.logger.error("Privilèges administrateur requis pour la capture de la mémoire")
            return False
        
        # Sélectionner l'outil approprié
        selected_tool = self._select_best_tool()
        
        if not selected_tool:
            self.logger.error("Aucun outil de capture mémoire disponible")
            return False
        
        self.logger.info(f"Utilisation de l'outil {selected_tool} pour la capture mémoire")
        
        # Exécuter la méthode de capture appropriée
        if selected_tool == "winpmem":
            return self._capture_with_winpmem(evidence_manager)
        elif selected_tool == "lime":
            return self._capture_with_lime(evidence_manager)
        elif selected_tool == "osxpmem":
            return self._capture_with_osxpmem(evidence_manager)
        elif selected_tool == "avml":
            return self._capture_with_avml(evidence_manager)
        elif selected_tool == "memdump":
            return self._capture_with_memdump(evidence_manager)
        elif selected_tool == "dd":
            return self._capture_with_dd(evidence_manager)
        else:
            self.logger.error(f"Outil de capture mémoire non supporté: {selected_tool}")
            return False
    
    def _detect_memory_tools(self):
        """
        Détecte les outils de capture mémoire disponibles sur le système
        
        Returns:
            dict: Dictionnaire des outils disponibles avec leur chemin
        """
        tools = {}
        
        # Chemins de recherche
        search_paths = os.environ.get("PATH", "").split(os.pathsep)
        extra_paths = [
            ".",
            os.path.dirname(__file__),
            os.path.join(os.path.dirname(__file__), "bin"),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "bin"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "bin")
        ]
        search_paths.extend(extra_paths)
        
        # Windows
        if platform.system() == "Windows":
            winpmem_names = ["winpmem.exe", "winpmem_x64.exe", "winpmem_x86.exe"]
            for path in search_paths:
                for name in winpmem_names:
                    full_path = os.path.join(path, name)
                    if os.path.isfile(full_path):
                        tools["winpmem"] = full_path
                        break
                if "winpmem" in tools:
                    break
        
        # Linux
        elif platform.system() == "Linux":
            # LiME
            lime_mod = "/lib/modules/{}/misc/lime.ko".format(platform.release())
            if os.path.isfile(lime_mod):
                tools["lime"] = lime_mod
            
            # AVML
            avml_names = ["avml"]
            for path in search_paths:
                for name in avml_names:
                    full_path = os.path.join(path, name)
                    if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                        tools["avml"] = full_path
                        break
                if "avml" in tools:
                    break
            
            # dd (fallback)
            for path in search_paths:
                dd_path = os.path.join(path, "dd")
                if os.path.isfile(dd_path) and os.access(dd_path, os.X_OK):
                    tools["dd"] = dd_path
                    break
        
        # macOS
        elif platform.system() == "Darwin":
            # OSXPmem
            osxpmem_names = ["osxpmem", "osxpmem.app/osxpmem"]
            for path in search_paths:
                for name in osxpmem_names:
                    full_path = os.path.join(path, name)
                    if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                        tools["osxpmem"] = full_path
                        break
                if "osxpmem" in tools:
                    break
        
        # Outils multi-plateformes
        memdump_names = ["memdump"]
        for path in search_paths:
            for name in memdump_names:
                full_path = os.path.join(path, name)
                if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                    tools["memdump"] = full_path
                    break
            if "memdump" in tools:
                break
        
        return tools
    
    def _select_best_tool(self):
        """
        Sélectionne le meilleur outil disponible
        
        Returns:
            str: Nom de l'outil sélectionné ou None si aucun n'est disponible
        """
        # Ordre de préférence par plateforme
        if platform.system() == "Windows":
            preferences = ["winpmem", "memdump"]
        elif platform.system() == "Linux":
            preferences = ["lime", "avml", "dd", "memdump"]
        elif platform.system() == "Darwin":
            preferences = ["osxpmem", "memdump"]
        else:
            preferences = ["memdump"]
        
        for tool in preferences:
            if tool in self.available_tools:
                return tool
        
        return None
    
    def _capture_with_winpmem(self, evidence_manager):
        """
        Capture la mémoire avec WinPmem
        
        Args:
            evidence_manager (EvidenceManager): Gestionnaire de preuves
            
        Returns:
            bool: True si la capture a réussi, False sinon
        """
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"memory_dump_{timestamp}.raw"
            
            # Construire la commande
            winpmem_path = self.available_tools["winpmem"]
            command = [winpmem_path, "-o", str(output_file), "--format", "raw"]
            
            self.logger.info(f"Démarrage de la capture mémoire avec WinPmem: {' '.join(command)}")
            
            # Exécuter la commande
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Erreur lors de la capture mémoire avec WinPmem: {stderr}")
                return False
            
            # Vérifier que le fichier a été créé et n'est pas vide
            if not output_file.exists() or output_file.stat().st_size == 0:
                self.logger.error(f"La capture mémoire n'a pas généré de fichier valide: {output_file}")
                return False
            
            # Ajouter la preuve au gestionnaire
            evidence_id = evidence_manager.add_memory_evidence(
                "Windows",
                f"Capture mémoire complète ({output_file.name})",
                str(output_file),
                {
                    "tool": "WinPmem",
                    "tool_version": self._get_tool_version("winpmem"),
                    "raw_stdout": stdout,
                    "raw_stderr": stderr,
                    "command": " ".join(command)
                }
            )
            
            self.logger.info(f"Capture mémoire réussie: {output_file} ({output_file.stat().st_size} octets)")
            self.logger.info(f"ID de preuve: {evidence_id}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Exception lors de la capture mémoire avec WinPmem: {str(e)}")
            return False
    
    def _capture_with_lime(self, evidence_manager):
        """
        Capture la mémoire avec LiME (Linux Memory Extractor)
        
        Args:
            evidence_manager (EvidenceManager): Gestionnaire de preuves
            
        Returns:
            bool: True si la capture a réussi, False sinon
        """
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"memory_dump_{timestamp}.lime"
            
            # Charger le module LiME
            lime_path = self.available_tools["lime"]
            format_arg = "raw"  # ou "lime" pour le format LiME
            
            command = ["insmod", lime_path, f"path={output_file}", f"format={format_arg}"]
            
            self.logger.info(f"Démarrage de la capture mémoire avec LiME: {' '.join(command)}")
            
            # Exécuter la commande
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            # Le module s'auto-décharge après la capture
            # Attendre qu'il termine
            
            if process.returncode != 0:
                self.logger.error(f"Erreur lors de la capture mémoire avec LiME: {stderr}")
                return False
            
            # Vérifier que le fichier a été créé et n'est pas vide
            if not output_file.exists() or output_file.stat().st_size == 0:
                self.logger.error(f"La capture mémoire n'a pas généré de fichier valide: {output_file}")
                return False
            
            # Ajouter la preuve au gestionnaire
            evidence_id = evidence_manager.add_memory_evidence(
                f"Linux {platform.release()}",
                f"Capture mémoire complète ({output_file.name})",
                str(output_file),
                {
                    "tool": "LiME",
                    "tool_path": lime_path,
                    "format": format_arg,
                    "raw_stdout": stdout,
                    "raw_stderr": stderr,
                    "command": " ".join(command)
                }
            )
            
            self.logger.info(f"Capture mémoire réussie: {output_file} ({output_file.stat().st_size} octets)")
            self.logger.info(f"ID de preuve: {evidence_id}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Exception lors de la capture mémoire avec LiME: {str(e)}")
            return False
    
    def _capture_with_osxpmem(self, evidence_manager):
        """
        Capture la mémoire avec OSXPmem
        
        Args:
            evidence_manager (EvidenceManager): Gestionnaire de preuves
            
        Returns:
            bool: True si la capture a réussi, False sinon
        """
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"memory_dump_{timestamp}.raw"
            
            # Construire la commande
            osxpmem_path = self.available_tools["osxpmem"]
            command = [osxpmem_path, str(output_file)]
            
            self.logger.info(f"Démarrage de la capture mémoire avec OSXPmem: {' '.join(command)}")
            
            # Exécuter la commande
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Erreur lors de la capture mémoire avec OSXPmem: {stderr}")
                return False
            
            # Vérifier que le fichier a été créé et n'est pas vide
            if not output_file.exists() or output_file.stat().st_size == 0:
                self.logger.error(f"La capture mémoire n'a pas généré de fichier valide: {output_file}")
                return False
            
            # Ajouter la preuve au gestionnaire
            evidence_id = evidence_manager.add_memory_evidence(
                f"macOS {platform.mac_ver()[0]}",
                f"Capture mémoire complète ({output_file.name})",
                str(output_file),
                {
                    "tool": "OSXPmem",
                    "tool_version": self._get_tool_version("osxpmem"),
                    "raw_stdout": stdout,
                    "raw_stderr": stderr,
                    "command": " ".join(command)
                }
            )
            
            self.logger.info(f"Capture mémoire réussie: {output_file} ({output_file.stat().st_size} octets)")
            self.logger.info(f"ID de preuve: {evidence_id}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Exception lors de la capture mémoire avec OSXPmem: {str(e)}")
            return False
    
    def _capture_with_avml(self, evidence_manager):
        """
        Capture la mémoire avec AVML (Azure VM Linux Memory)
        
        Args:
            evidence_manager (EvidenceManager): Gestionnaire de preuves
            
        Returns:
            bool: True si la capture a réussi, False sinon
        """
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"memory_dump_{timestamp}.lime"
            
            # Construire la commande
            avml_path = self.available_tools["avml"]
            command = [avml_path, str(output_file)]
            
            self.logger.info(f"Démarrage de la capture mémoire avec AVML: {' '.join(command)}")
            
            # Exécuter la commande
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Erreur lors de la capture mémoire avec AVML: {stderr}")
                return False
            
            # Vérifier que le fichier a été créé et n'est pas vide
            if not output_file.exists() or output_file.stat().st_size == 0:
                self.logger.error(f"La capture mémoire n'a pas généré de fichier valide: {output_file}")
                return False
            
            # Ajouter la preuve au gestionnaire
            evidence_id = evidence_manager.add_memory_evidence(
                f"Linux {platform.release()}",
                f"Capture mémoire complète ({output_file.name})",
                str(output_file),
                {
                    "tool": "AVML",
                    "tool_version": self._get_tool_version("avml"),
                    "raw_stdout": stdout,
                    "raw_stderr": stderr,
                    "command": " ".join(command)
                }
            )
            
            self.logger.info(f"Capture mémoire réussie: {output_file} ({output_file.stat().st_size} octets)")
            self.logger.info(f"ID de preuve: {evidence_id}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Exception lors de la capture mémoire avec AVML: {str(e)}")
            return False
    
    def _capture_with_memdump(self, evidence_manager):
        """
        Capture la mémoire avec memdump
        
        Args:
            evidence_manager (EvidenceManager): Gestionnaire de preuves
            
        Returns:
            bool: True si la capture a réussi, False sinon
        """
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"memory_dump_{timestamp}.raw"
            
            # Construire la commande
            memdump_path = self.available_tools["memdump"]
            command = [memdump_path, "-o", str(output_file)]
            
            self.logger.info(f"Démarrage de la capture mémoire avec memdump: {' '.join(command)}")
            
            # Exécuter la commande
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Erreur lors de la capture mémoire avec memdump: {stderr}")
                return False
            
            # Vérifier que le fichier a été créé et n'est pas vide
            if not output_file.exists() or output_file.stat().st_size == 0:
                self.logger.error(f"La capture mémoire n'a pas généré de fichier valide: {output_file}")
                return False
            
            # Ajouter la preuve au gestionnaire
            evidence_id = evidence_manager.add_memory_evidence(
                platform.system(),
                f"Capture mémoire complète ({output_file.name})",
                str(output_file),
                {
                    "tool": "memdump",
                    "tool_version": self._get_tool_version("memdump"),
                    "raw_stdout": stdout,
                    "raw_stderr": stderr,
                    "command": " ".join(command)
                }
            )
            
            self.logger.info(f"Capture mémoire réussie: {output_file} ({output_file.stat().st_size} octets)")
            self.logger.info(f"ID de preuve: {evidence_id}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Exception lors de la capture mémoire avec memdump: {str(e)}")
            return False
    
    def _capture_with_dd(self, evidence_manager):
        """
        Capture la mémoire avec dd (Linux uniquement)
        
        Args:
            evidence_manager (EvidenceManager): Gestionnaire de preuves
            
        Returns:
            bool: True si la capture a réussi, False sinon
        """
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"memory_dump_{timestamp}.raw"
            
            # Vérifier si /proc/kcore est disponible
            if not Path("/proc/kcore").exists():
                self.logger.error("Impossible de capturer la mémoire avec dd: /proc/kcore n'est pas disponible")
                return False
            
            # Construire la commande
            dd_path = self.available_tools["dd"]
            command = [dd_path, "if=/proc/kcore", f"of={output_file}", "bs=4M"]
            
            self.logger.info(f"Démarrage de la capture mémoire avec dd: {' '.join(command)}")
            
            # Exécuter la commande
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Erreur lors de la capture mémoire avec dd: {stderr}")
                return False
            
            # Vérifier que le fichier a été créé et n'est pas vide
            if not output_file.exists() or output_file.stat().st_size == 0:
                self.logger.error(f"La capture mémoire n'a pas généré de fichier valide: {output_file}")
                return False
            
            # Ajouter la preuve au gestionnaire
            evidence_id = evidence_manager.add_memory_evidence(
                f"Linux {platform.release()}",
                f"Capture mémoire via /proc/kcore ({output_file.name})",
                str(output_file),
                {
                    "tool": "dd",
                    "source": "/proc/kcore",
                    "raw_stdout": stdout,
                    "raw_stderr": stderr,
                    "command": " ".join(command)
                }
            )
            
            self.logger.info(f"Capture mémoire réussie: {output_file} ({output_file.stat().st_size} octets)")
            self.logger.info(f"ID de preuve: {evidence_id}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Exception lors de la capture mémoire avec dd: {str(e)}")
            return False
    
    def _get_tool_version(self, tool_name):
        """
        Obtient la version d'un outil
        
        Args:
            tool_name (str): Nom de l'outil
            
        Returns:
            str: Version de l'outil ou "Unknown" si impossible à déterminer
        """
        if tool_name not in self.available_tools:
            return "Unknown"
        
        tool_path = self.available_tools[tool_name]
        
        try:
            if tool_name == "winpmem":
                command = [tool_path, "--version"]
            elif tool_name == "avml":
                command = [tool_path, "--version"]
            elif tool_name == "osxpmem":
                command = [tool_path, "--version"]
            elif tool_name == "memdump":
                command = [tool_path, "--version"]
            else:
                return "Unknown"
            
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            
            # Extraire la version de la sortie (dépend du format de sortie de chaque outil)
            if "version" in output.lower():
                for line in output.splitlines():
                    if "version" in line.lower():
                        return line.strip()
            
            return output.strip()
        
        except Exception:
            return "Unknown"
