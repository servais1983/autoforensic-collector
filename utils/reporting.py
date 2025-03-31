#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Génération de rapports pour les preuves forensiques collectées

Ce module s'occupe de créer des rapports détaillés (HTML, PDF, JSON) 
sur les preuves collectées lors d'une investigation.
"""

import os
import json
import logging
import datetime
import shutil
from pathlib import Path
import jinja2

try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
    logging.warning("Le module markdown n'est pas disponible. Les rapports HTML auront un formatage limité.")

try:
    from xhtml2pdf import pisa
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logging.warning("Le module xhtml2pdf n'est pas disponible. La génération de PDF n'est pas possible.")


class ReportGenerator:
    """
    Classe pour la génération de rapports forensiques
    """
    
    def __init__(self, evidence_dir, chain_of_custody=None):
        """
        Initialise le générateur de rapports
        
        Args:
            evidence_dir (str): Répertoire contenant les preuves
            chain_of_custody (ChainOfCustody, optional): Objet de chaîne de preuve
        """
        self.evidence_dir = Path(evidence_dir)
        self.chain_of_custody = chain_of_custody
        self.report_dir = self.evidence_dir / "reports"
        self.report_dir.mkdir(exist_ok=True)
        
        # Configuration de Jinja2 pour les templates
        template_dir = Path(__file__).parent.parent / "templates"
        if not template_dir.exists():
            template_dir = Path(__file__).parent.parent / "templates_default"
            if not template_dir.exists():
                template_dir.mkdir(exist_ok=True)
                self._create_default_templates(template_dir)
        
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
    
    def generate_report(self, format_type, evidence_manager=None, system_info=None):
        """
        Génère un rapport selon le format spécifié
        
        Args:
            format_type (str): Type de rapport ('html', 'pdf', 'json')
            evidence_manager (EvidenceManager, optional): Gestionnaire de preuves
            system_info (dict, optional): Informations système
            
        Returns:
            str: Chemin vers le rapport généré
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"forensic_report_{timestamp}"
        
        # Collecter les données pour le rapport
        report_data = self._collect_report_data(evidence_manager, system_info)
        
        try:
            if format_type == 'html':
                report_path = self.report_dir / f"{report_filename}.html"
                self._generate_html_report(report_data, report_path)
            
            elif format_type == 'pdf':
                if not PDF_AVAILABLE:
                    logging.error("Impossible de générer un rapport PDF: module xhtml2pdf manquant")
                    return None
                
                report_path = self.report_dir / f"{report_filename}.pdf"
                self._generate_pdf_report(report_data, report_path)
            
            elif format_type == 'json':
                report_path = self.report_dir / f"{report_filename}.json"
                self._generate_json_report(report_data, report_path)
            
            else:
                logging.error(f"Format de rapport non pris en charge: {format_type}")
                return None
            
            logging.info(f"Rapport généré avec succès: {report_path}")
            return str(report_path)
        
        except Exception as e:
            logging.error(f"Erreur lors de la génération du rapport: {str(e)}")
            return None
    
    def _collect_report_data(self, evidence_manager=None, system_info=None):
        """
        Collecte les données pour le rapport
        
        Args:
            evidence_manager (EvidenceManager, optional): Gestionnaire de preuves
            system_info (dict, optional): Informations système
            
        Returns:
            dict: Données collectées pour le rapport
        """
        report_data = {
            "title": "Rapport d'Investigation Forensique",
            "generated_at": datetime.datetime.now().isoformat(),
            "case_info": {},
            "system_info": system_info if system_info else {},
            "evidence_items": [],
            "modules_summary": {}
        }
        
        # Ajouter les informations du cas si disponibles
        if self.chain_of_custody:
            report_data["case_info"] = {
                "case_id": self.chain_of_custody.case_id,
                "start_time": self.chain_of_custody.start_time.isoformat(),
                "end_time": self.chain_of_custody.end_time.isoformat() if self.chain_of_custody.end_time else None,
                "operator": self.chain_of_custody.operator,
                "evidence_count": len(self.chain_of_custody.case_data["evidence_items"]) if hasattr(self.chain_of_custody, "case_data") else 0
            }
        
        # Ajouter les preuves si un gestionnaire est fourni
        if evidence_manager and hasattr(evidence_manager, "get_all_evidence"):
            evidence_items = evidence_manager.get_all_evidence()
            report_data["evidence_items"] = evidence_items
            
            # Résumé par type de module
            module_counts = {}
            for item in evidence_items:
                module_type = item.get("type", "unknown")
                if module_type not in module_counts:
                    module_counts[module_type] = 0
                module_counts[module_type] += 1
            
            report_data["modules_summary"] = module_counts
        
        # Collecter des statistiques sur les types de fichiers
        file_stats = self._collect_file_statistics()
        report_data["file_statistics"] = file_stats
        
        return report_data
    
    def _collect_file_statistics(self):
        """
        Collecte des statistiques sur les types de fichiers
        
        Returns:
            dict: Statistiques sur les types de fichiers
        """
        stats = {
            "total_size": 0,
            "file_count": 0,
            "extensions": {},
            "directories": {}
        }
        
        try:
            # Parcourir le répertoire des preuves
            for root, dirs, files in os.walk(self.evidence_dir):
                rel_path = os.path.relpath(root, self.evidence_dir)
                if rel_path == '.':
                    rel_path = 'root'
                
                dir_stats = {
                    "file_count": len(files),
                    "total_size": 0
                }
                
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_size = os.path.getsize(file_path)
                        stats["total_size"] += file_size
                        dir_stats["total_size"] += file_size
                        stats["file_count"] += 1
                        
                        # Calculer les statistiques par extension
                        ext = os.path.splitext(file)[1].lower()
                        if not ext:
                            ext = "no_extension"
                        
                        if ext not in stats["extensions"]:
                            stats["extensions"][ext] = {
                                "count": 0,
                                "total_size": 0
                            }
                        
                        stats["extensions"][ext]["count"] += 1
                        stats["extensions"][ext]["total_size"] += file_size
                    
                    except Exception as e:
                        logging.warning(f"Erreur lors de l'analyse du fichier {file_path}: {str(e)}")
                
                stats["directories"][rel_path] = dir_stats
        
        except Exception as e:
            logging.error(f"Erreur lors de la collecte des statistiques de fichiers: {str(e)}")
        
        return stats
    
    def _generate_html_report(self, report_data, output_path):
        """
        Génère un rapport HTML
        
        Args:
            report_data (dict): Données du rapport
            output_path (Path): Chemin de sortie pour le rapport
            
        Returns:
            bool: True si la génération a réussi, False sinon
        """
        try:
            template = self.jinja_env.get_template("report_template.html")
            
            # Formater les données pour le template
            formatted_data = self._format_report_data(report_data)
            
            # Générer le HTML
            html_content = template.render(**formatted_data)
            
            # Écrire le fichier HTML
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Copier les ressources CSS/JS si elles existent
            resources_dir = Path(__file__).parent.parent / "templates" / "resources"
            if resources_dir.exists():
                output_resources = output_path.parent / "resources"
                output_resources.mkdir(exist_ok=True)
                
                for resource in resources_dir.iterdir():
                    shutil.copy(resource, output_resources)
            
            return True
        
        except Exception as e:
            logging.error(f"Erreur lors de la génération du rapport HTML: {str(e)}")
            return False
    
    def _generate_pdf_report(self, report_data, output_path):
        """
        Génère un rapport PDF
        
        Args:
            report_data (dict): Données du rapport
            output_path (Path): Chemin de sortie pour le rapport
            
        Returns:
            bool: True si la génération a réussi, False sinon
        """
        try:
            # Générer d'abord le HTML
            temp_html = self.report_dir / "temp_report.html"
            self._generate_html_report(report_data, temp_html)
            
            # Convertir le HTML en PDF
            with open(temp_html, 'r', encoding='utf-8') as html_file:
                with open(output_path, 'wb') as pdf_file:
                    pisa.CreatePDF(html_file.read(), pdf_file)
            
            # Supprimer le fichier HTML temporaire
            os.unlink(temp_html)
            
            return True
        
        except Exception as e:
            logging.error(f"Erreur lors de la génération du rapport PDF: {str(e)}")
            return False
    
    def _generate_json_report(self, report_data, output_path):
        """
        Génère un rapport JSON
        
        Args:
            report_data (dict): Données du rapport
            output_path (Path): Chemin de sortie pour le rapport
            
        Returns:
            bool: True si la génération a réussi, False sinon
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            return True
        
        except Exception as e:
            logging.error(f"Erreur lors de la génération du rapport JSON: {str(e)}")
            return False
    
    def _format_report_data(self, report_data):
        """
        Formate les données pour le template de rapport
        
        Args:
            report_data (dict): Données brutes du rapport
            
        Returns:
            dict: Données formatées pour le template
        """
        # Copier les données pour ne pas modifier l'original
        formatted = report_data.copy()
        
        # Formatages spécifiques
        if "generated_at" in formatted:
            try:
                dt = datetime.datetime.fromisoformat(formatted["generated_at"])
                formatted["generated_at_human"] = dt.strftime("%d/%m/%Y %H:%M:%S")
            except:
                formatted["generated_at_human"] = formatted["generated_at"]
        
        # Formater les tailles de fichiers pour être lisibles
        if "file_statistics" in formatted:
            stats = formatted["file_statistics"]
            stats["total_size_human"] = self._format_file_size(stats["total_size"])
            
            for ext, ext_stats in stats["extensions"].items():
                ext_stats["total_size_human"] = self._format_file_size(ext_stats["total_size"])
            
            for dir_name, dir_stats in stats["directories"].items():
                dir_stats["total_size_human"] = self._format_file_size(dir_stats["total_size"])
        
        return formatted
    
    def _format_file_size(self, size_bytes):
        """
        Formate une taille en octets en une chaîne lisible
        
        Args:
            size_bytes (int): Taille en octets
            
        Returns:
            str: Taille formatée (ex: "2.5 MB")
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
    
    def _create_default_templates(self, template_dir):
        """
        Crée les templates par défaut si aucun n'existe
        
        Args:
            template_dir (Path): Répertoire des templates
        """
        html_template = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #ddd;
        }
        
        h1, h2, h3 {
            color: #2c3e50;
        }
        
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        table, th, td {
            border: 1px solid #ddd;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
        }
        
        th {
            background-color: #2c3e50;
            color: white;
        }
        
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{ title }}</h1>
            <p>Généré le {{ generated_at_human }}</p>
        </header>
        
        {% if case_info %}
        <div class="section">
            <h2>Informations sur le Cas</h2>
            <table>
                <tr>
                    <th>ID du Cas</th>
                    <td>{{ case_info.case_id }}</td>
                </tr>
                <tr>
                    <th>Début de la Collection</th>
                    <td>{{ case_info.start_time }}</td>
                </tr>
                <tr>
                    <th>Fin de la Collection</th>
                    <td>{{ case_info.end_time or 'En cours' }}</td>
                </tr>
                <tr>
                    <th>Opérateur</th>
                    <td>{{ case_info.operator }}</td>
                </tr>
                <tr>
                    <th>Nombre de Preuves</th>
                    <td>{{ case_info.evidence_count }}</td>
                </tr>
            </table>
        </div>
        {% endif %}
        
        {% if system_info %}
        <div class="section">
            <h2>Informations Système</h2>
            <table>
                {% for key, value in system_info.items() %}
                <tr>
                    <th>{{ key }}</th>
                    <td>{{ value }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if modules_summary %}
        <div class="section">
            <h2>Résumé des Modules</h2>
            <table>
                <tr>
                    <th>Type de Module</th>
                    <th>Nombre de Preuves</th>
                </tr>
                {% for module, count in modules_summary.items() %}
                <tr>
                    <td>{{ module }}</td>
                    <td>{{ count }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if evidence_items %}
        <div class="section">
            <h2>Preuves Collectées</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Description</th>
                    <th>Horodatage</th>
                </tr>
                {% for item in evidence_items %}
                <tr>
                    <td>{{ item.evidence_id }}</td>
                    <td>{{ item.type }}</td>
                    <td>{{ item.source }}</td>
                    <td>{{ item.description }}</td>
                    <td>{{ item.timestamp }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if file_statistics %}
        <div class="section">
            <h2>Statistiques de Fichiers</h2>
            
            <h3>Résumé</h3>
            <table>
                <tr>
                    <th>Nombre Total de Fichiers</th>
                    <td>{{ file_statistics.file_count }}</td>
                </tr>
                <tr>
                    <th>Taille Totale</th>
                    <td>{{ file_statistics.total_size_human }}</td>
                </tr>
            </table>
            
            <h3>Par Extension</h3>
            <table>
                <tr>
                    <th>Extension</th>
                    <th>Nombre</th>
                    <th>Taille Totale</th>
                </tr>
                {% for ext, ext_stats in file_statistics.extensions.items() %}
                <tr>
                    <td>{{ ext }}</td>
                    <td>{{ ext_stats.count }}</td>
                    <td>{{ ext_stats.total_size_human }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h3>Par Répertoire</h3>
            <table>
                <tr>
                    <th>Répertoire</th>
                    <th>Nombre de Fichiers</th>
                    <th>Taille Totale</th>
                </tr>
                {% for dir_name, dir_stats in file_statistics.directories.items() %}
                <tr>
                    <td>{{ dir_name }}</td>
                    <td>{{ dir_stats.file_count }}</td>
                    <td>{{ dir_stats.total_size_human }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Rapport généré par AutoForensic Collector</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Créer le template HTML
        template_path = template_dir / "report_template.html"
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        logging.info(f"Template par défaut créé: {template_path}")
