#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilitaires pour obtenir des informations sur le système

Ce module fournit des fonctions pour obtenir des informations détaillées
sur le système sur lequel s'exécute l'outil.
"""

import os
import sys
import platform
import logging
import datetime
import socket
import uuid
import json
import tempfile
import subprocess
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("Le module psutil n'est pas disponible. Certaines informations système ne seront pas collectées.")

try:
    import cpuinfo
    CPUINFO_AVAILABLE = True
except ImportError:
    CPUINFO_AVAILABLE = False
    logging.warning("Le module py-cpuinfo n'est pas disponible. Les informations détaillées du CPU ne seront pas collectées.")


def get_system_info():
    """
    Obtient des informations détaillées sur le système

    Returns:
        dict: Informations sur le système
    """
    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "ip_addresses": _get_ip_addresses(),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "user": os.getlogin() if hasattr(os, 'getlogin') else os.getenv('USER') or os.getenv('USERNAME'),
        "timestamp": datetime.datetime.now().isoformat(),
        "mac_addresses": _get_mac_addresses(),
        "boot_time": _get_boot_time()
    }
    
    # Ajouter des informations spécifiques à la plateforme
    if platform.system() == 'Windows':
        info.update(_get_windows_info())
    elif platform.system() == 'Linux':
        info.update(_get_linux_info())
    elif platform.system() == 'Darwin':
        info.update(_get_macos_info())
    
    # Ajouter des informations détaillées si psutil est disponible
    if PSUTIL_AVAILABLE:
        info.update(_get_psutil_info())
    
    # Ajouter des informations CPU détaillées si py-cpuinfo est disponible
    if CPUINFO_AVAILABLE:
        info.update(_get_cpuinfo())
    
    return info


def check_privileges():
    """
    Vérifie si le programme a les privilèges administrateur/root

    Returns:
        bool: True si le programme a les privilèges administrateur/root, False sinon
    """
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False


def _get_ip_addresses():
    """
    Obtient les adresses IP du système

    Returns:
        dict: Adresses IP par interface
    """
    ip_addresses = {}
    
    try:
        if PSUTIL_AVAILABLE:
            # Méthode avec psutil (plus complète)
            interfaces = psutil.net_if_addrs()
            for interface_name, interface_addresses in interfaces.items():
                ip_addresses[interface_name] = []
                for addr in interface_addresses:
                    if addr.family == socket.AF_INET:  # IPv4
                        ip_addresses[interface_name].append({
                            'ip': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast,
                            'version': 'IPv4'
                        })
                    elif addr.family == socket.AF_INET6:  # IPv6
                        ip_addresses[interface_name].append({
                            'ip': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast,
                            'version': 'IPv6'
                        })
        else:
            # Méthode de secours (moins complète)
            hostname = socket.gethostname()
            ip_addresses['primary'] = [{'ip': socket.gethostbyname(hostname), 'version': 'IPv4'}]
            
            # Essayer d'obtenir toutes les adresses IP associées à l'hôte
            try:
                addresses = socket.getaddrinfo(hostname, None)
                for addr in addresses:
                    if addr[0] == socket.AF_INET:  # IPv4
                        ip_addresses['all_ipv4'] = ip_addresses.get('all_ipv4', [])
                        ip_addresses['all_ipv4'].append({'ip': addr[4][0], 'version': 'IPv4'})
                    elif addr[0] == socket.AF_INET6:  # IPv6
                        ip_addresses['all_ipv6'] = ip_addresses.get('all_ipv6', [])
                        ip_addresses['all_ipv6'].append({'ip': addr[4][0], 'version': 'IPv6'})
            except:
                pass
    
    except Exception as e:
        logging.warning(f"Erreur lors de la récupération des adresses IP: {str(e)}")
        
    return ip_addresses


def _get_mac_addresses():
    """
    Obtient les adresses MAC du système

    Returns:
        dict: Adresses MAC par interface
    """
    mac_addresses = {}
    
    try:
        if PSUTIL_AVAILABLE:
            # Méthode avec psutil
            interfaces = psutil.net_if_addrs()
            for interface_name, interface_addresses in interfaces.items():
                for addr in interface_addresses:
                    if addr.family == psutil.AF_LINK:  # Adresse MAC
                        mac_addresses[interface_name] = addr.address
        else:
            # Méthode de secours pour obtenir l'adresse MAC (moins complète)
            if platform.system() == 'Windows':
                mac_addresses = _get_mac_addresses_windows()
            elif platform.system() == 'Linux':
                mac_addresses = _get_mac_addresses_linux()
            elif platform.system() == 'Darwin':
                mac_addresses = _get_mac_addresses_macos()
    
    except Exception as e:
        logging.warning(f"Erreur lors de la récupération des adresses MAC: {str(e)}")
    
    return mac_addresses


def _get_mac_addresses_windows():
    """
    Obtient les adresses MAC sur Windows en utilisant getmac

    Returns:
        dict: Adresses MAC par interface
    """
    mac_addresses = {}
    
    try:
        # Exécuter la commande getmac
        output = subprocess.check_output("getmac /v /fo csv", shell=True).decode('utf-8')
        
        # Analyser la sortie
        for line in output.splitlines()[1:]:  # Ignorer l'en-tête
            if not line:
                continue
            
            parts = line.split('","')
            if len(parts) >= 3:
                interface = parts[0].strip('"')
                mac = parts[2].strip('"')
                mac_addresses[interface] = mac
    except:
        pass
    
    return mac_addresses


def _get_mac_addresses_linux():
    """
    Obtient les adresses MAC sur Linux en lisant /sys/class/net/*/address

    Returns:
        dict: Adresses MAC par interface
    """
    mac_addresses = {}
    
    try:
        for interface in os.listdir('/sys/class/net'):
            try:
                with open(f'/sys/class/net/{interface}/address', 'r') as f:
                    mac = f.read().strip()
                    if mac:
                        mac_addresses[interface] = mac
            except:
                pass
    except:
        pass
    
    return mac_addresses


def _get_mac_addresses_macos():
    """
    Obtient les adresses MAC sur macOS en utilisant ifconfig

    Returns:
        dict: Adresses MAC par interface
    """
    mac_addresses = {}
    
    try:
        # Exécuter la commande ifconfig
        output = subprocess.check_output("ifconfig", shell=True).decode('utf-8')
        
        # Analyser la sortie
        current_interface = None
        for line in output.splitlines():
            if not line.startswith('\t'):
                current_interface = line.split(':')[0]
            elif 'ether' in line and current_interface:
                mac = line.split('ether')[1].strip().split(' ')[0]
                mac_addresses[current_interface] = mac
    except:
        pass
    
    return mac_addresses


def _get_boot_time():
    """
    Obtient le temps de démarrage du système

    Returns:
        str: Temps de démarrage au format ISO 8601 ou None si non disponible
    """
    try:
        if PSUTIL_AVAILABLE:
            # Utiliser psutil pour obtenir le temps de démarrage
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
            return boot_time
        else:
            # Essayer d'obtenir le temps de démarrage selon la plateforme
            if platform.system() == 'Windows':
                # Utiliser le temps d'activité pour calculer le temps de démarrage
                output = subprocess.check_output('net stats srv', shell=True).decode('utf-8')
                for line in output.splitlines():
                    if 'Statistics since' in line:
                        # Extraire la date et l'heure, format peut varier selon la locale
                        dt_str = line.split('Statistics since')[1].strip()
                        boot_time = datetime.datetime.strptime(dt_str, '%d/%m/%Y %H:%M:%S')
                        return boot_time.isoformat()
            
            elif platform.system() == 'Linux':
                # Lire /proc/uptime
                with open('/proc/uptime', 'r') as f:
                    uptime_seconds = float(f.readline().split()[0])
                    boot_time = datetime.datetime.now() - datetime.timedelta(seconds=uptime_seconds)
                    return boot_time.isoformat()
            
            elif platform.system() == 'Darwin':
                # Utiliser la commande sysctl
                output = subprocess.check_output('sysctl kern.boottime', shell=True).decode('utf-8')
                if 'sec = ' in output:
                    boot_timestamp = int(output.split('sec = ')[1].split(',')[0])
                    boot_time = datetime.datetime.fromtimestamp(boot_timestamp)
                    return boot_time.isoformat()
    
    except Exception as e:
        logging.warning(f"Erreur lors de la récupération du temps de démarrage: {str(e)}")
    
    return None


def _get_windows_info():
    """
    Obtient des informations spécifiques à Windows

    Returns:
        dict: Informations spécifiques à Windows
    """
    info = {
        "windows_edition": platform.win32_edition() if hasattr(platform, 'win32_edition') else None,
        "windows_current_version": _get_windows_registry_value(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentVersion'),
        "product_name": _get_windows_registry_value(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName'),
        "install_date": _get_windows_registry_value_as_datetime(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'InstallDate')
    }
    
    # Ajouter des informations de service pack si disponibles
    if hasattr(sys, 'getwindowsversion'):
        win_ver = sys.getwindowsversion()
        info['service_pack'] = win_ver.service_pack
    
    return info


def _get_windows_registry_value(key_path, value_name):
    """
    Obtient une valeur de registre Windows

    Args:
        key_path (str): Chemin de la clé de registre
        value_name (str): Nom de la valeur

    Returns:
        str or None: Valeur du registre ou None si non disponible
    """
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return value
    except:
        return None


def _get_windows_registry_value_as_datetime(key_path, value_name):
    """
    Obtient une valeur de registre Windows et la convertit en datetime

    Args:
        key_path (str): Chemin de la clé de registre
        value_name (str): Nom de la valeur

    Returns:
        str or None: Valeur du registre au format ISO 8601 ou None si non disponible
    """
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        timestamp, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        
        if isinstance(timestamp, int):
            dt = datetime.datetime.fromtimestamp(timestamp)
            return dt.isoformat()
        return timestamp
    except:
        return None


def _get_linux_info():
    """
    Obtient des informations spécifiques à Linux

    Returns:
        dict: Informations spécifiques à Linux
    """
    info = {
        "distribution": _get_linux_distribution(),
        "kernel_version": platform.release()
    }
    
    # Ajouter des informations LSB si disponibles
    try:
        output = subprocess.check_output('lsb_release -a', shell=True).decode('utf-8')
        for line in output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                info[f"lsb_{key.strip().lower()}"] = value.strip()
    except:
        pass
    
    return info


def _get_linux_distribution():
    """
    Obtient le nom de la distribution Linux

    Returns:
        str or None: Nom de la distribution Linux ou None si non disponible
    """
    try:
        if hasattr(platform, 'linux_distribution'):
            # Pour Python < 3.8
            return ' '.join(platform.linux_distribution())
        else:
            # Pour Python >= 3.8, méthode alternative
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=')[1].strip().strip('"')
            
            # Méthodes alternatives
            for file_path in ['/etc/lsb-release', '/etc/debian_version', '/etc/redhat-release', '/etc/SuSE-release']:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        return f.readline().strip()
    except:
        pass
    
    return None


def _get_macos_info():
    """
    Obtient des informations spécifiques à macOS

    Returns:
        dict: Informations spécifiques à macOS
    """
    info = {
        "macos_version": platform.mac_ver()[0],
        "macos_version_tuple": platform.mac_ver()
    }
    
    # Obtenir des informations système supplémentaires
    try:
        # Version du système
        output = subprocess.check_output('sw_vers', shell=True).decode('utf-8')
        for line in output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                info[f"sw_{key.strip().lower()}"] = value.strip()
        
        # Informations matérielles
        output = subprocess.check_output('system_profiler SPHardwareDataType', shell=True).decode('utf-8')
        for line in output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                if key and value.strip():
                    info[f"hw_{key}"] = value.strip()
    except:
        pass
    
    return info


def _get_psutil_info():
    """
    Obtient des informations système en utilisant psutil

    Returns:
        dict: Informations système obtenues avec psutil
    """
    info = {}
    
    try:
        # Informations sur la mémoire
        memory = psutil.virtual_memory()
        info['memory'] = {
            'total': memory.total,
            'available': memory.available,
            'percent_used': memory.percent,
            'used': memory.used,
            'free': memory.free
        }
        
        # Informations sur le swap
        swap = psutil.swap_memory()
        info['swap'] = {
            'total': swap.total,
            'used': swap.used,
            'free': swap.free,
            'percent_used': swap.percent
        }
        
        # Informations sur les disques
        info['disks'] = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                info['disks'].append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent_used': usage.percent
                })
            except:
                # Certains points de montage peuvent ne pas être accessibles
                info['disks'].append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'error': 'Could not get usage information'
                })
        
        # Informations sur le CPU
        info['cpu'] = {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            'stats': {
                'ctx_switches': psutil.cpu_stats().ctx_switches,
                'interrupts': psutil.cpu_stats().interrupts,
                'soft_interrupts': psutil.cpu_stats().soft_interrupts,
                'syscalls': psutil.cpu_stats().syscalls if hasattr(psutil.cpu_stats(), 'syscalls') else None
            }
        }
        
        # Charge moyenne du CPU
        try:
            info['cpu']['load_avg'] = psutil.getloadavg()
        except:
            pass
        
        # Informations sur les utilisateurs connectés
        info['users'] = [user._asdict() for user in psutil.users()]
        
        # Informations sur les interfaces réseau
        info['network_stats'] = {iface: stats._asdict() for iface, stats in psutil.net_io_counters(pernic=True).items()}
        
    except Exception as e:
        logging.warning(f"Erreur lors de la récupération des informations psutil: {str(e)}")
    
    return info


def _get_cpuinfo():
    """
    Obtient des informations détaillées sur le CPU

    Returns:
        dict: Informations détaillées sur le CPU
    """
    info = {}
    
    try:
        cpu_info = cpuinfo.get_cpu_info()
        
        # Sélectionner les informations pertinentes
        info['cpu_details'] = {
            'brand_raw': cpu_info.get('brand_raw'),
            'vendor_id_raw': cpu_info.get('vendor_id_raw'),
            'arch': cpu_info.get('arch'),
            'bits': cpu_info.get('bits'),
            'count': cpu_info.get('count'),
            'arch_string_raw': cpu_info.get('arch_string_raw'),
            'hz_advertised_friendly': cpu_info.get('hz_advertised_friendly'),
            'hz_actual_friendly': cpu_info.get('hz_actual_friendly'),
            'l1_data_cache_size': cpu_info.get('l1_data_cache_size'),
            'l1_instruction_cache_size': cpu_info.get('l1_instruction_cache_size'),
            'l2_cache_size': cpu_info.get('l2_cache_size'),
            'l3_cache_size': cpu_info.get('l3_cache_size'),
            'stepping': cpu_info.get('stepping'),
            'model': cpu_info.get('model'),
            'family': cpu_info.get('family'),
            'flags': cpu_info.get('flags')
        }
    
    except Exception as e:
        logging.warning(f"Erreur lors de la récupération des informations CPU détaillées: {str(e)}")
    
    return info
