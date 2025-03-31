#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilitaires de compression et chiffrement pour les preuves forensiques

Ce module fournit des fonctions pour compresser, décompresser,
chiffrer et déchiffrer les données collectées.
"""

import os
import time
import logging
import zipfile
import tarfile
import gzip
import shutil
import tempfile
import getpass
import json
from pathlib import Path
from datetime import datetime

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.warning("Le module cryptography n'est pas disponible. Le chiffrement ne sera pas disponible.")


def compress_evidence(evidence_dir, archive_format='zip', encryption_password=None, metadata=None):
    """
    Compresse un répertoire de preuves dans une archive, avec chiffrement optionnel
    
    Args:
        evidence_dir (str): Chemin vers le répertoire de preuves à compresser
        archive_format (str, optional): Format d'archive ('zip', 'tar', 'tar.gz', 'tar.bz2')
        encryption_password (str, optional): Mot de passe pour le chiffrement
        metadata (dict, optional): Métadonnées à inclure dans l'archive
        
    Returns:
        str: Chemin vers l'archive créée
    """
    evidence_path = Path(evidence_dir)
    
    if not evidence_path.exists() or not evidence_path.is_dir():
        logging.error(f"Le répertoire {evidence_dir} n'existe pas ou n'est pas un répertoire")
        return None
    
    # Créer le nom de l'archive avec un timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_name = evidence_path.name
    archive_name = f"{case_name}_{timestamp}"
    
    # Déterminer le chemin complet de l'archive et son extension
    if archive_format == 'zip':
        archive_path = f"{archive_name}.zip"
    elif archive_format == 'tar':
        archive_path = f"{archive_name}.tar"
    elif archive_format == 'tar.gz':
        archive_path = f"{archive_name}.tar.gz"
    elif archive_format == 'tar.bz2':
        archive_path = f"{archive_name}.tar.bz2"
    else:
        logging.error(f"Format d'archive non pris en charge: {archive_format}")
        return None
    
    # Chemin complet de l'archive
    archive_full_path = str(evidence_path.parent / archive_path)
    
    # Ajouter des métadonnées à l'archive si nécessaire
    if metadata is None:
        metadata = {}
    
    metadata.update({
        "compressed_at": datetime.now().isoformat(),
        "compressed_by": getpass.getuser(),
        "source_directory": str(evidence_path),
        "encrypted": bool(encryption_password),
        "format": archive_format
    })
    
    # Créer un fichier temporaire pour les métadonnées
    metadata_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
    json.dump(metadata, metadata_file, indent=2)
    metadata_file.close()
    
    try:
        # Créer l'archive selon le format demandé
        if archive_format == 'zip':
            # ZIP avec ou sans chiffrement
            if encryption_password and CRYPTO_AVAILABLE:
                # Si chiffrement demandé, nous créons d'abord une archive non chiffrée
                # puis nous la chiffrons
                temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
                temp_zip.close()
                
                with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    _add_directory_to_zip(zipf, evidence_path, evidence_path)
                    zipf.write(metadata_file.name, "metadata.json")
                
                # Chiffrer l'archive temporaire
                encrypt_file(temp_zip.name, archive_full_path, encryption_password)
                os.unlink(temp_zip.name)
            else:
                # ZIP standard sans chiffrement
                with zipfile.ZipFile(archive_full_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    _add_directory_to_zip(zipf, evidence_path, evidence_path)
                    zipf.write(metadata_file.name, "metadata.json")
        
        elif archive_format.startswith('tar'):
            # Déterminer le mode d'ouverture et la compression pour TAR
            if archive_format == 'tar':
                mode = 'w'
            elif archive_format == 'tar.gz':
                mode = 'w:gz'
            elif archive_format == 'tar.bz2':
                mode = 'w:bz2'
            
            # Créer l'archive TAR
            with tarfile.open(archive_full_path, mode) as tarf:
                tarf.add(evidence_path, arcname=evidence_path.name)
                tarf.add(metadata_file.name, arcname="metadata.json")
            
            # Si chiffrement demandé, chiffrer l'archive TAR
            if encryption_password and CRYPTO_AVAILABLE:
                encrypted_path = f"{archive_full_path}.enc"
                encrypt_file(archive_full_path, encrypted_path, encryption_password)
                os.unlink(archive_full_path)
                archive_full_path = encrypted_path
        
        logging.info(f"Archive créée avec succès: {archive_full_path}")
        return archive_full_path
    
    except Exception as e:
        logging.error(f"Erreur lors de la création de l'archive: {str(e)}")
        # Nettoyage en cas d'erreur
        if os.path.exists(archive_full_path):
            os.unlink(archive_full_path)
        return None
    
    finally:
        # Nettoyer le fichier de métadonnées temporaire
        if os.path.exists(metadata_file.name):
            os.unlink(metadata_file.name)


def _add_directory_to_zip(zipf, directory, base_dir):
    """
    Ajoute récursivement un répertoire à une archive ZIP
    
    Args:
        zipf (ZipFile): Objet ZipFile ouvert
        directory (Path): Répertoire à ajouter
        base_dir (Path): Répertoire de base pour les chemins relatifs
    """
    for item in directory.iterdir():
        if item.is_file():
            zipf.write(item, item.relative_to(base_dir.parent))
        elif item.is_dir():
            _add_directory_to_zip(zipf, item, base_dir)


def encrypt_file(input_file, output_file, password):
    """
    Chiffre un fichier avec un mot de passe
    
    Args:
        input_file (str): Chemin vers le fichier à chiffrer
        output_file (str): Chemin vers le fichier chiffré
        password (str): Mot de passe pour le chiffrement
        
    Returns:
        bool: True si le chiffrement a réussi, False sinon
    """
    if not CRYPTO_AVAILABLE:
        logging.error("Le chiffrement n'est pas disponible (module cryptography manquant)")
        return False
    
    try:
        # Générer une clé à partir du mot de passe
        password_bytes = password.encode()
        salt = b'autoforensic_salt_' + os.urandom(16)  # Sel unique
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        cipher = Fernet(key)
        
        # Lire le fichier d'entrée
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Chiffrer les données
        encrypted_data = cipher.encrypt(data)
        
        # Enregistrer les données chiffrées avec le sel en entête
        with open(output_file, 'wb') as f:
            f.write(salt)  # Écrire le sel au début du fichier
            f.write(encrypted_data)
        
        logging.info(f"Fichier {input_file} chiffré avec succès vers {output_file}")
        return True
    
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement du fichier: {str(e)}")
        return False


def decrypt_file(input_file, output_file, password):
    """
    Déchiffre un fichier avec un mot de passe
    
    Args:
        input_file (str): Chemin vers le fichier chiffré
        output_file (str): Chemin vers le fichier déchiffré
        password (str): Mot de passe pour le déchiffrement
        
    Returns:
        bool: True si le déchiffrement a réussi, False sinon
    """
    if not CRYPTO_AVAILABLE:
        logging.error("Le déchiffrement n'est pas disponible (module cryptography manquant)")
        return False
    
    try:
        # Lire le fichier chiffré
        with open(input_file, 'rb') as f:
            # Lire le sel (24 premiers octets: 'autoforensic_salt_' + 16 octets de sel)
            salt = f.read(24)
            
            # Lire les données chiffrées
            encrypted_data = f.read()
        
        # Générer la clé à partir du mot de passe et du sel
        password_bytes = password.encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        cipher = Fernet(key)
        
        # Déchiffrer les données
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Enregistrer les données déchiffrées
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        logging.info(f"Fichier {input_file} déchiffré avec succès vers {output_file}")
        return True
    
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement du fichier: {str(e)}")
        return False


def extract_archive(archive_path, output_dir, password=None):
    """
    Extrait une archive (potentiellement chiffrée)
    
    Args:
        archive_path (str): Chemin vers l'archive à extraire
        output_dir (str): Répertoire de sortie pour l'extraction
        password (str, optional): Mot de passe pour le déchiffrement
        
    Returns:
        bool: True si l'extraction a réussi, False sinon
    """
    archive_path = Path(archive_path)
    output_dir = Path(output_dir)
    
    # Créer le répertoire de sortie s'il n'existe pas
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Vérifier si l'archive est chiffrée
    is_encrypted = archive_path.suffix.lower() == '.enc'
    
    try:
        # Si l'archive est chiffrée, la déchiffrer d'abord
        if is_encrypted and password:
            if not CRYPTO_AVAILABLE:
                logging.error("Déchiffrement impossible: module cryptography manquant")
                return False
            
            temp_archive = tempfile.NamedTemporaryFile(delete=False)
            temp_archive.close()
            
            if not decrypt_file(str(archive_path), temp_archive.name, password):
                return False
            
            # Utiliser l'archive déchiffrée pour l'extraction
            extract_path = temp_archive.name
        else:
            extract_path = str(archive_path)
        
        # Déterminer le type d'archive et l'extraire
        if zipfile.is_zipfile(extract_path):
            with zipfile.ZipFile(extract_path, 'r') as zipf:
                zipf.extractall(path=str(output_dir))
        
        elif tarfile.is_tarfile(extract_path):
            with tarfile.open(extract_path, 'r:*') as tarf:
                tarf.extractall(path=str(output_dir))
        
        else:
            logging.error(f"Format d'archive non reconnu: {archive_path}")
            return False
        
        logging.info(f"Archive {archive_path} extraite avec succès dans {output_dir}")
        return True
    
    except Exception as e:
        logging.error(f"Erreur lors de l'extraction de l'archive: {str(e)}")
        return False
    
    finally:
        # Nettoyer le fichier temporaire si nécessaire
        if is_encrypted and password and 'temp_archive' in locals():
            try:
                os.unlink(temp_archive.name)
            except:
                pass
