#!/usr/bin/env python3
"""
AI Discovery Scanner - Secure LLM Software Detection Tool
========================================================

A comprehensive security scanner for detecting Local Large Language Model software 
installations with enhanced security features, input validation, and error handling.

Supported LLM Software:
- Ollama
- LM Studio  
- GPT4All
- vLLM

Detection Methods:
- File system paths (with path traversal protection)
- Registry keys (Windows, with proper error handling)
- Environment variables (sanitized)
- Running processes (secure enumeration)
- Open network ports (timeout protection)
- Python package installations (version checking)

Security Features:
- Input validation and sanitization
- Path traversal attack prevention
- Subprocess command injection protection
- File operation security
- Comprehensive error handling
- Logging and audit trails

Author: Security Team
Version: 2.0.0
License: MIT
"""

import os
import sys
import json
import platform
import subprocess
import socket
import psutil
import yaml
import zipfile
import shutil
import logging
import re
import hashlib
from pathlib import Path, PurePath
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Union
import argparse
from datetime import datetime
import traceback

# Configure logging for security audit trail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_discovery_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Security constants
MAX_PATH_LENGTH = 4096
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'.txt', '.log', '.json', '.yml', '.yaml', '.conf', '.config', '.ini'}
BLOCKED_EXTENSIONS = {'.exe', '.dll', '.so', '.dylib', '.bat', '.cmd', '.ps1', '.sh', '.pyc', '.pyo'}
SUBPROCESS_TIMEOUT = 30  # seconds
MAX_PROCESS_COUNT = 1000  # Prevent infinite loops

class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

class InputValidationError(Exception):
    """Custom exception for input validation errors"""
    pass

@dataclass
class DetectionResult:
    """Data class for storing detection results with validation"""
    software: str
    detection_type: str
    value: str
    path: Optional[str] = None
    confidence: str = "medium"
    
    def __post_init__(self):
        """Validate detection result data"""
        if not isinstance(self.software, str) or len(self.software) > 100:
            raise InputValidationError("Invalid software name")
        if not isinstance(self.detection_type, str) or len(self.detection_type) > 50:
            raise InputValidationError("Invalid detection type")
        if not isinstance(self.value, str) or len(self.value) > 1000:
            raise InputValidationError("Invalid detection value")
        if self.confidence not in ["low", "medium", "high"]:
            raise InputValidationError("Invalid confidence level")

class SecurityValidator:
    """Security validation utilities"""
    
    @staticmethod
    def sanitize_path(path: str) -> str:
        """
        Sanitize file path to prevent path traversal attacks
        
        Args:
            path: Input path string
            
        Returns:
            Sanitized path string
            
        Raises:
            SecurityError: If path contains dangerous patterns
        """
        if not isinstance(path, str):
            raise SecurityError("Path must be a string")
        
        # Check for path traversal attempts (more specific patterns)
        dangerous_patterns = [
            '..\\', '../', '\\..', '/..', '..\\..', '../..',
            '....', '....\\', '..../', '....\\\\', '....//'
        ]
        
        # Normalize the path first
        normalized_path = os.path.normpath(path)
        
        # Check for dangerous patterns in the normalized path
        for pattern in dangerous_patterns:
            if pattern in normalized_path:
                logger.warning(f"Potential path traversal detected: {path}")
                raise SecurityError(f"Path traversal attempt detected: {pattern}")
        
        # Additional check for directory traversal attempts
        path_parts = normalized_path.split(os.sep)
        for part in path_parts:
            if part == '..' or part.startswith('..'):
                logger.warning(f"Directory traversal attempt detected: {path}")
                raise SecurityError(f"Directory traversal attempt detected: {part}")
        
        # Check path length
        if len(normalized_path) > MAX_PATH_LENGTH:
            raise SecurityError(f"Path too long: {len(normalized_path)} characters")
        
        return normalized_path
    
    @staticmethod
    def validate_filename(filename: str) -> str:
        """
        Validate and sanitize filename
        
        Args:
            filename: Input filename
            
        Returns:
            Sanitized filename
            
        Raises:
            SecurityError: If filename contains dangerous characters
        """
        if not isinstance(filename, str):
            raise SecurityError("Filename must be a string")
        
        # Remove dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\\', '/']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Check for reserved names (Windows)
        reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                         'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
                         'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
        
        name_without_ext = os.path.splitext(filename)[0].upper()
        if name_without_ext in reserved_names:
            filename = f"_{filename}"
        
        return filename
    
    @staticmethod
    def validate_command_args(args: List[str]) -> List[str]:
        """
        Validate command line arguments for subprocess calls
        
        Args:
            args: List of command arguments
            
        Returns:
            Validated arguments list
            
        Raises:
            SecurityError: If arguments contain dangerous patterns
        """
        if not isinstance(args, list):
            raise SecurityError("Command arguments must be a list")
        
        dangerous_patterns = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']']
        
        for arg in args:
            if not isinstance(arg, str):
                raise SecurityError("All command arguments must be strings")
            
            for pattern in dangerous_patterns:
                if pattern in arg:
                    logger.warning(f"Potential command injection detected: {arg}")
                    raise SecurityError(f"Command injection attempt detected: {pattern}")
        
        return args
    
    @staticmethod
    def is_safe_file_extension(filename: str) -> bool:
        """
        Check if file extension is safe for processing
        
        Args:
            filename: Filename to check
            
        Returns:
            True if extension is safe, False otherwise
        """
        if not filename:
            return False
        
        ext = Path(filename).suffix.lower()
        return ext in ALLOWED_EXTENSIONS and ext not in BLOCKED_EXTENSIONS

class LLMSoftwareDetector:
    """
    Secure LLM Software Detection Scanner
    
    This class provides comprehensive detection capabilities with enhanced security
    features including input validation, path traversal protection, and secure
    subprocess execution.
    """
    
    def __init__(self, max_file_size_mb: int = 100, verbose: bool = False):
        """
        Initialize the LLM Software Detector
        
        Args:
            max_file_size_mb: Maximum file size in MB for log collection
            verbose: Enable verbose logging
            
        Raises:
            InputValidationError: If parameters are invalid
        """
        if not isinstance(max_file_size_mb, int) or max_file_size_mb <= 0:
            raise InputValidationError("max_file_size_mb must be a positive integer")
        
        self.results = []
        self.sigma_rules_dir = Path("sigma_rules")
        self.max_file_size_mb = max_file_size_mb
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.verbose = verbose
        self.validator = SecurityValidator()
        
        # Security: Initialize with safe defaults
        self._load_sigma_rules()
        
        logger.info(f"LLM Software Detector initialized with max_file_size_mb={max_file_size_mb}")
    
    def _load_sigma_rules(self) -> None:
        """
        Load SIGMA rules from the rules directory with security validation
        
        Raises:
            SecurityError: If rule loading fails due to security issues
        """
        self.sigma_rules = []
        
        try:
            if not self.sigma_rules_dir.exists():
                logger.warning(f"SIGMA rules directory not found: {self.sigma_rules_dir}")
                return
            
            # Security: Limit number of files to prevent DoS
            rule_files = list(self.sigma_rules_dir.glob("*.yml"))
            if len(rule_files) > 100:  # Reasonable limit
                logger.warning(f"Too many SIGMA rule files found: {len(rule_files)}")
                rule_files = rule_files[:100]
            
            for rule_file in rule_files:
                try:
                    # Security: Validate file path
                    rule_path = self.validator.sanitize_path(str(rule_file))
                    
                    # Security: Check file size
                    if rule_file.stat().st_size > MAX_FILE_SIZE:
                        logger.warning(f"SIGMA rule file too large, skipping: {rule_file}")
                        continue
                    
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        rule = yaml.safe_load(f)
                        
                        # Security: Validate rule structure
                        if isinstance(rule, dict) and 'title' in rule:
                            self.sigma_rules.append(rule)
                            logger.debug(f"Loaded SIGMA rule: {rule.get('title', 'Unknown')}")
                        else:
                            logger.warning(f"Invalid SIGMA rule structure in: {rule_file}")
                            
                except (yaml.YAMLError, OSError, SecurityError) as e:
                    logger.error(f"Error loading SIGMA rule {rule_file}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Critical error loading SIGMA rules: {e}")
            raise SecurityError(f"Failed to load SIGMA rules: {e}")
        
        logger.info(f"Loaded {len(self.sigma_rules)} SIGMA rules")
    
    def _safe_subprocess_run(self, cmd: Union[str, List[str]], 
                           timeout: int = SUBPROCESS_TIMEOUT,
                           capture_output: bool = True) -> subprocess.CompletedProcess:
        """
        Execute subprocess command with security validation
        
        Args:
            cmd: Command to execute (string or list)
            timeout: Command timeout in seconds
            capture_output: Whether to capture output
            
        Returns:
            CompletedProcess object
            
        Raises:
            SecurityError: If command is unsafe
            subprocess.TimeoutExpired: If command times out
        """
        try:
            # Security: Convert string command to list if needed
            if isinstance(cmd, str):
                cmd = cmd.split()
            
            # Security: Validate command arguments
            cmd = self.validator.validate_command_args(cmd)
            
            # Security: Prevent command injection by using list format
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                shell=False,  # Security: Never use shell=True
                check=False
            )
            
            logger.debug(f"Executed command: {' '.join(cmd)}")
            return result
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            raise
        except (subprocess.SubprocessError, OSError) as e:
            logger.error(f"Subprocess error: {e}")
            raise
        except SecurityError as e:
            logger.error(f"Security validation failed: {e}")
            raise
    
    def _safe_file_operation(self, file_path: str, operation: str = 'read', 
                           content: str = None) -> Optional[str]:
        """
        Perform safe file operations with validation
        
        Args:
            file_path: Path to the file
            operation: Operation type ('read' or 'write')
            content: Content to write (for write operations)
            
        Returns:
            File content for read operations, None for write operations
            
        Raises:
            SecurityError: If file operation is unsafe
        """
        try:
            # Security: Validate and sanitize file path
            safe_path = self.validator.sanitize_path(file_path)
            
            # Security: Check file extension
            if not self.validator.is_safe_file_extension(safe_path):
                logger.warning(f"Unsafe file extension: {safe_path}")
                raise SecurityError(f"Unsafe file extension: {Path(safe_path).suffix}")
            
            # Security: Check file size for read operations
            if operation == 'read' and os.path.exists(safe_path):
                file_size = os.path.getsize(safe_path)
                if file_size > self.max_file_size_bytes:
                    logger.warning(f"File too large: {safe_path} ({file_size} bytes)")
                    raise SecurityError(f"File too large: {file_size} bytes")
            
            # Perform file operation
            if operation == 'read':
                with open(safe_path, 'r', encoding='utf-8') as f:
                    return f.read()
            elif operation == 'write' and content is not None:
                with open(safe_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return None
            else:
                raise ValueError(f"Invalid operation: {operation}")
                
        except (OSError, IOError) as e:
            logger.error(f"File operation error: {e}")
            raise SecurityError(f"File operation failed: {e}")
    
    def check_port_open(self, port: int, host: str = 'localhost') -> bool:
        """
        Check if a network port is open with timeout protection
        
        Args:
            port: Port number to check
            host: Host to check (default: localhost)
            
        Returns:
            True if port is open, False otherwise
            
        Raises:
            SecurityError: If port number is invalid
        """
        try:
            # Security: Validate port number
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise SecurityError(f"Invalid port number: {port}")
            
            # Security: Validate host
            if not isinstance(host, str) or len(host) > 255:
                raise SecurityError(f"Invalid host: {host}")
            
            # Security: Use timeout to prevent hanging
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)  # 5 second timeout
                result = sock.connect_ex((host, port))
                return result == 0
                
        except (socket.error, OSError) as e:
            logger.debug(f"Socket error checking port {port}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error checking port {port}: {e}")
            return False

    def detect_ollama(self) -> List[DetectionResult]:
        """Detect Ollama installation"""
        results = []

        # Common file paths
        ollama_paths = {
            "Windows": [
                os.path.expanduser("~/.ollama"),
                os.path.expanduser("~/AppData/Local/Programs/Ollama"),
                "C:\\Program Files\\Ollama",
                "C:\\ollama"
            ],
            "Darwin": [  # macOS
                "/Applications/Ollama.app",
                os.path.expanduser("~/.ollama"),
                "/usr/local/bin/ollama"
            ],
            "Linux": [
                "/usr/bin/ollama",
                "/usr/local/bin/ollama",
                "/usr/share/ollama",
                "/var/lib/ollama",
                os.path.expanduser("~/.ollama"),
                os.path.expanduser("~/.local/bin/ollama")
            ]
        }

        system = platform.system()
        for path in ollama_paths.get(system, []):
            if os.path.exists(path):
                results.append(DetectionResult(
                    software="Ollama",
                    detection_type="file_path",
                    value=path,
                    path=path,
                    confidence="high"
                ))

        # Environment variables
        env_vars = ["OLLAMA_MODELS", "OLLAMA_HOST", "OLLAMA_HOME"]
        for var in env_vars:
            if var in os.environ:
                results.append(DetectionResult(
                    software="Ollama",
                    detection_type="environment_variable",
                    value=f"{var}={os.environ[var]}",
                    confidence="high"
                ))

        # Process detection
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if proc.info['name'] and 'ollama' in proc.info['name'].lower():
                    results.append(DetectionResult(
                        software="Ollama",
                        detection_type="process",
                        value=f"PID: {proc.info['pid']}, Name: {proc.info['name']}",
                        path=proc.info.get('exe'),
                        confidence="high"
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Port detection (Ollama default port 11434)
        if self.check_port_open(11434):
            results.append(DetectionResult(
                software="Ollama",
                detection_type="network_port",
                value="Port 11434 (HTTP API)",
                confidence="medium"
            ))

        # Windows Registry
        if system == "Windows":
            registry_results = self.check_windows_registry_ollama()
            results.extend(registry_results)

        return results

    def detect_lmstudio(self) -> List[DetectionResult]:
        """Detect LM Studio installation"""
        results = []

        # Common file paths
        lmstudio_paths = {
            "Windows": [
                os.path.expanduser("~/AppData/Local/LMStudio"),
                os.path.expanduser("~/AppData/Roaming/LMStudio"),
                "C:\\Program Files\\LMStudio",
                os.path.expanduser("~/.cache/lm-studio"),
                os.path.expanduser("~/.lmstudio")
            ],
            "Darwin": [  # macOS
                "/Applications/LM Studio.app",
                os.path.expanduser("~/.cache/lm-studio"),
                os.path.expanduser("~/.lmstudio"),
                os.path.expanduser("~/Library/Application Support/LMStudio")
            ],
            "Linux": [
                os.path.expanduser("~/.cache/lm-studio"),
                os.path.expanduser("~/.lmstudio"),
                os.path.expanduser("~/LMStudio"),
                "/opt/lmstudio"
            ]
        }

        system = platform.system()
        for path in lmstudio_paths.get(system, []):
            if os.path.exists(path):
                results.append(DetectionResult(
                    software="LM Studio",
                    detection_type="file_path",
                    value=path,
                    path=path,
                    confidence="high"
                ))

        # Environment variables
        env_vars = ["LMSTUDIO_MODELS_DIR", "LM_STUDIO_HOME"]
        for var in env_vars:
            if var in os.environ:
                results.append(DetectionResult(
                    software="LM Studio",
                    detection_type="environment_variable",
                    value=f"{var}={os.environ[var]}",
                    confidence="high"
                ))

        # Process detection
        process_names = ['lmstudio', 'lm-studio', 'LMStudio.exe', 'LM Studio']
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if proc.info['name']:
                    for pname in process_names:
                        if pname.lower() in proc.info['name'].lower():
                            results.append(DetectionResult(
                                software="LM Studio",
                                detection_type="process",
                                value=f"PID: {proc.info['pid']}, Name: {proc.info['name']}",
                                path=proc.info.get('exe'),
                                confidence="high"
                            ))
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Port detection (LM Studio default port 1234)
        if self.check_port_open(1234):
            results.append(DetectionResult(
                software="LM Studio",
                detection_type="network_port",
                value="Port 1234 (HTTP API)",
                confidence="medium"
            ))

        # Windows Registry
        if system == "Windows":
            registry_results = self.check_windows_registry_lmstudio()
            results.extend(registry_results)

        return results

    def load_detection_rules(self) -> List[Dict]:
        """Load SIGMA rules that contain detection specifications"""
        detection_rules = []
        
        for rule in self.sigma_rules:
            # Check if this is a detection rule (contains detection specifications)
            if 'detection' in rule and isinstance(rule['detection'], dict):
                detection_spec = rule['detection']
                
                # Check if it has any of our detection specifications
                if any(key in detection_spec for key in ['file_paths', 'environment_variables', 'process_names', 'network_ports']):
                    detection_rules.append(rule)
        
        return detection_rules

    def get_software_name_from_rule(self, rule: Dict) -> str:
        """Extract software name from SIGMA rule"""
        # Try to get from title
        title = rule.get('title', '')
        if 'Ollama' in title:
            return 'Ollama'
        elif 'LM Studio' in title:
            return 'LM Studio'
        elif 'GPT4All' in title:
            return 'GPT4All'
        elif 'vLLM' in title:
            return 'vLLM'
        
        # Try to get from tags
        tags = rule.get('tags', [])
        for tag in tags:
            if tag.startswith('llm.'):
                software = tag.split('.')[1]
                if software == 'ollama':
                    return 'Ollama'
                elif software == 'lmstudio':
                    return 'LM Studio'
                elif software == 'gpt4all':
                    return 'GPT4All'
                elif software == 'vllm':
                    return 'vLLM'
        
        return 'Unknown Software'

    def detect_software_from_rule(self, rule: Dict) -> List[DetectionResult]:
        """Detect software based on SIGMA rule specifications"""
        results = []
        detection_spec = rule.get('detection', {})
        software_name = self.get_software_name_from_rule(rule)
        system = platform.system()
        
        # File path detection
        if 'file_paths' in detection_spec:
            file_paths = detection_spec['file_paths']
            platform_paths = file_paths.get(system.lower(), [])
            
            for path_template in platform_paths:
                # Expand environment variables
                path = os.path.expandvars(path_template)
                if os.path.exists(path):
                    results.append(DetectionResult(
                        software=software_name,
                        detection_type="file_path",
                        value=path,
                        path=path,
                        confidence="high"
                    ))
        
        # Environment variables detection
        if 'environment_variables' in detection_spec:
            env_vars = detection_spec['environment_variables']
            for var in env_vars:
                if var in os.environ:
                    results.append(DetectionResult(
                        software=software_name,
                        detection_type="environment_variable",
                        value=f"{var}={os.environ[var]}",
                        confidence="high"
                    ))
        
        # Process detection
        if 'process_names' in detection_spec:
            process_names = detection_spec['process_names']
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    if proc.info['name']:
                        for pname in process_names:
                            if pname.lower() in proc.info['name'].lower():
                                results.append(DetectionResult(
                                    software=software_name,
                                    detection_type="process",
                                    value=f"PID: {proc.info['pid']}, Name: {proc.info['name']}",
                                    path=proc.info.get('exe'),
                                    confidence="high"
                                ))
                                break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        # Network port detection
        if 'network_ports' in detection_spec:
            ports = detection_spec['network_ports']
            for port in ports:
                if self.check_port_open(port):
                    results.append(DetectionResult(
                        software=software_name,
                        detection_type="network_port",
                        value=f"Port {port} (HTTP API)",
                        confidence="medium"
                    ))
        
        # Registry detection (Windows only)
        if system == "Windows" and 'registry_keys' in detection_spec:
            registry_results = self.check_windows_registry_from_rule(rule)
            results.extend(registry_results)
        
        return results

    def check_windows_registry_from_rule(self, rule: Dict) -> List[DetectionResult]:
        """Check Windows registry based on SIGMA rule specifications"""
        results = []
        detection_spec = rule.get('detection', {})
        software_name = self.get_software_name_from_rule(rule)
        
        if 'registry_keys' not in detection_spec:
            return results
        
        try:
            import winreg
            registry_keys = detection_spec['registry_keys']
            
            for key_path in registry_keys:
                try:
                    # Parse registry key path
                    if '\\' in key_path:
                        hkey_name, subkey = key_path.split('\\', 1)
                        
                        # Map hkey names to constants
                        hkey_map = {
                            'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                            'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE
                        }
                        
                        if hkey_name in hkey_map:
                            hkey = hkey_map[hkey_name]
                            with winreg.OpenKey(hkey, subkey) as key:
                                i = 0
                                while True:
                                    try:
                                        name, value, _ = winreg.EnumValue(key, i)
                                        if software_name.lower() in name.lower() or software_name.lower() in str(value).lower():
                                            results.append(DetectionResult(
                                                software=software_name,
                                                detection_type="registry_key",
                                                value=f"{key_path}\\{name}={value}",
                                                confidence="high"
                                            ))
                                        i += 1
                                    except WindowsError:
                                        break
                except WindowsError:
                    continue
        except ImportError:
            pass
        
        return results

    def check_port_open(self, port: int, host: str = 'localhost') -> bool:
        """Check if a port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                return result == 0
        except:
            return False

    def check_windows_registry_ollama(self) -> List[DetectionResult]:
        """Check Windows registry for Ollama entries"""
        results = []
        if platform.system() != "Windows":
            return results

        try:
            import winreg

            # Common registry paths for Ollama
            registry_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software\Ollama"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Ollama"),
                (winreg.HKEY_CURRENT_USER, r"Environment"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
            ]

            for hkey, subkey in registry_paths:
                try:
                    with winreg.OpenKey(hkey, subkey) as key:
                        # Check for Ollama-related values
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                if 'ollama' in name.lower() or 'ollama' in str(value).lower():
                                    results.append(DetectionResult(
                                        software="Ollama",
                                        detection_type="registry_key",
                                        value=f"{subkey}\\{name}={value}",
                                        confidence="high"
                                    ))
                                i += 1
                            except WindowsError:
                                break
                except WindowsError:
                    continue
        except ImportError:
            pass

        return results

    def check_windows_registry_lmstudio(self) -> List[DetectionResult]:
        """Check Windows registry for LM Studio entries"""
        results = []
        if platform.system() != "Windows":
            return results

        try:
            import winreg

            # Common registry paths for LM Studio
            registry_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software\LMStudio"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\LMStudio"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            ]

            for hkey, subkey in registry_paths:
                try:
                    with winreg.OpenKey(hkey, subkey) as key:
                        # For uninstall keys, enumerate subkeys
                        if "Uninstall" in subkey:
                            i = 0
                            while True:
                                try:
                                    subkey_name = winreg.EnumKey(key, i)
                                    if 'lmstudio' in subkey_name.lower() or 'lm-studio' in subkey_name.lower():
                                        with winreg.OpenKey(key, subkey_name) as subkey_handle:
                                            try:
                                                display_name, _ = winreg.QueryValueEx(subkey_handle, "DisplayName")
                                                results.append(DetectionResult(
                                                    software="LM Studio",
                                                    detection_type="registry_key",
                                                    value=f"Uninstall entry: {display_name}",
                                                    confidence="high"
                                                ))
                                            except WindowsError:
                                                pass
                                    i += 1
                                except WindowsError:
                                    break
                        else:
                            # Check for LM Studio-related values
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    if 'lmstudio' in name.lower() or 'lmstudio' in str(value).lower():
                                        results.append(DetectionResult(
                                            software="LM Studio",
                                            detection_type="registry_key",
                                            value=f"{subkey}\\{name}={value}",
                                            confidence="high"
                                        ))
                                    i += 1
                                except WindowsError:
                                    break
                except WindowsError:
                    continue
        except ImportError:
            pass

        return results

    def detect_gpt4all(self) -> List[DetectionResult]:
        """Detect GPT4All installation"""
        results = []

        # Common file paths
        gpt4all_paths = {
            "Windows": [
                os.path.expanduser("~/AppData/Local/GPT4All"),
                os.path.expanduser("~/AppData/Roaming/GPT4All"),
                "C:\\Program Files\\GPT4All",
                "C:\\Program Files (x86)\\GPT4All",
                os.path.expanduser("~/.gpt4all"),
                os.path.expanduser("~/Documents/GPT4All"),
                os.path.expanduser("~/Downloads/GPT4All")
            ],
            "Darwin": [  # macOS
                "/Applications/GPT4All.app",
                os.path.expanduser("~/Applications/GPT4All.app"),
                os.path.expanduser("~/.gpt4all"),
                os.path.expanduser("~/Library/Application Support/GPT4All"),
                os.path.expanduser("~/Library/Preferences/GPT4All")
            ],
            "Linux": [
                os.path.expanduser("~/.gpt4all"),
                os.path.expanduser("~/.local/share/gpt4all"),
                os.path.expanduser("~/gpt4all"),
                "/opt/gpt4all",
                "/usr/local/gpt4all",
                os.path.expanduser("~/Downloads/gpt4all")
            ]
        }

        system = platform.system()
        for path in gpt4all_paths.get(system, []):
            if os.path.exists(path):
                results.append(DetectionResult(
                    software="GPT4All",
                    detection_type="file_path",
                    value=path,
                    path=path,
                    confidence="high"
                ))

        # Environment variables
        env_vars = ["GPT4ALL_MODEL_PATH", "GPT4ALL_HOME", "GPT4ALL_DATA_DIR"]
        for var in env_vars:
            if var in os.environ:
                results.append(DetectionResult(
                    software="GPT4All",
                    detection_type="environment_variable",
                    value=f"{var}={os.environ[var]}",
                    confidence="high"
                ))

        # Process detection
        process_names = ['gpt4all', 'GPT4All', 'gpt4all.exe', 'GPT4All.exe', 'gpt4all-app', 'gpt4all-app.exe']
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if proc.info['name']:
                    for pname in process_names:
                        if pname.lower() in proc.info['name'].lower():
                            results.append(DetectionResult(
                                software="GPT4All",
                                detection_type="process",
                                value=f"PID: {proc.info['pid']}, Name: {proc.info['name']}",
                                path=proc.info.get('exe'),
                                confidence="high"
                            ))
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Port detection (GPT4All typically uses port 4891)
        if self.check_port_open(4891):
            results.append(DetectionResult(
                software="GPT4All",
                detection_type="network_port",
                value="Port 4891 (HTTP API)",
                confidence="medium"
            ))

        # Windows Registry
        if system == "Windows":
            registry_results = self.check_windows_registry_gpt4all()
            results.extend(registry_results)

        return results

    def detect_vllm(self) -> List[DetectionResult]:
        """Detect vLLM installation"""
        results = []

        # Common file paths
        vllm_paths = {
            "Windows": [
                os.path.expanduser("~/AppData/Local/vLLM"),
                os.path.expanduser("~/AppData/Roaming/vLLM"),
                "C:\\Program Files\\vLLM",
                os.path.expanduser("~/.vllm"),
                os.path.expanduser("~/vllm"),
                os.path.expanduser("~/Documents/vllm")
            ],
            "Darwin": [  # macOS
                os.path.expanduser("~/.vllm"),
                os.path.expanduser("~/vllm"),
                os.path.expanduser("~/Library/Application Support/vLLM"),
                os.path.expanduser("~/Library/Preferences/vLLM")
            ],
            "Linux": [
                os.path.expanduser("~/.vllm"),
                os.path.expanduser("~/vllm"),
                "/opt/vllm",
                "/usr/local/vllm",
                os.path.expanduser("~/.local/share/vllm")
            ]
        }

        system = platform.system()
        for path in vllm_paths.get(system, []):
            if os.path.exists(path):
                results.append(DetectionResult(
                    software="vLLM",
                    detection_type="file_path",
                    value=path,
                    path=path,
                    confidence="high"
                ))

        # Environment variables
        env_vars = ["VLLM_HOME", "VLLM_MODEL_PATH", "VLLM_DATA_DIR", "CUDA_VISIBLE_DEVICES"]
        for var in env_vars:
            if var in os.environ:
                results.append(DetectionResult(
                    software="vLLM",
                    detection_type="environment_variable",
                    value=f"{var}={os.environ[var]}",
                    confidence="high"
                ))

        # Process detection
        process_names = ['vllm', 'vllm-engine', 'vllm-serve', 'vllm-worker', 'python.*vllm']
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if proc.info['name'] and proc.info['cmdline']:
                    proc_name = proc.info['name'].lower()
                    cmdline = ' '.join(proc.info['cmdline']).lower()
                    
                    # Check process name
                    for pname in process_names:
                        if pname.lower() in proc_name or pname.lower() in cmdline:
                            results.append(DetectionResult(
                                software="vLLM",
                                detection_type="process",
                                value=f"PID: {proc.info['pid']}, Name: {proc.info['name']}, Cmd: {' '.join(proc.info['cmdline'][:3])}",
                                path=proc.info.get('exe'),
                                confidence="high"
                            ))
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Port detection (vLLM typically uses port 8000)
        if self.check_port_open(8000):
            results.append(DetectionResult(
                software="vLLM",
                detection_type="network_port",
                value="Port 8000 (HTTP API)",
                confidence="medium"
            ))

        # Check for Python packages
        try:
            import pkg_resources
            installed_packages = [d.project_name for d in pkg_resources.working_set]
            if 'vllm' in installed_packages:
                results.append(DetectionResult(
                    software="vLLM",
                    detection_type="python_package",
                    value="vLLM Python package installed",
                    confidence="high"
                ))
        except ImportError:
            pass

        # Windows Registry
        if system == "Windows":
            registry_results = self.check_windows_registry_vllm()
            results.extend(registry_results)

        return results

    def check_windows_registry_gpt4all(self) -> List[DetectionResult]:
        """Check Windows registry for GPT4All entries"""
        results = []
        if platform.system() != "Windows":
            return results

        try:
            import winreg

            # Common registry paths for GPT4All
            registry_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software\GPT4All"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\GPT4All"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            ]

            for hkey, subkey in registry_paths:
                try:
                    with winreg.OpenKey(hkey, subkey) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                if 'gpt4all' in name.lower() or 'gpt4all' in str(value).lower():
                                    results.append(DetectionResult(
                                        software="GPT4All",
                                        detection_type="registry_key",
                                        value=f"{subkey}\\{name}={value}",
                                        confidence="high"
                                    ))
                                i += 1
                            except WindowsError:
                                break
                except WindowsError:
                    continue
        except ImportError:
            pass

        return results

    def check_windows_registry_vllm(self) -> List[DetectionResult]:
        """Check Windows registry for vLLM entries"""
        results = []
        if platform.system() != "Windows":
            return results

        try:
            import winreg

            # Common registry paths for vLLM
            registry_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software\vLLM"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\vLLM"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            ]

            for hkey, subkey in registry_paths:
                try:
                    with winreg.OpenKey(hkey, subkey) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                if 'vllm' in name.lower() or 'vllm' in str(value).lower():
                                    results.append(DetectionResult(
                                        software="vLLM",
                                        detection_type="registry_key",
                                        value=f"{subkey}\\{name}={value}",
                                        confidence="high"
                                    ))
                                i += 1
                            except WindowsError:
                                break
                except WindowsError:
                    continue
        except ImportError:
            pass

        return results

    def run_scan(self) -> Dict:
        """Run complete scan for LLM software using SIGMA rules"""
        print("Starting LLM Software Detection Scan...")
        print(f"Operating System: {platform.system()} {platform.release()}")
        print(f"Architecture: {platform.machine()}")
        print("-" * 50)

        all_results = []

        # Load and apply SIGMA rules for detection
        detection_rules = self.load_detection_rules()
        
        for rule in detection_rules:
            software_name = self.get_software_name_from_rule(rule)
            print(f"Scanning for {software_name}...")
            
            results = self.detect_software_from_rule(rule)
            all_results.extend(results)

        # Apply SIGMA rules if available
        sigma_detections = self.apply_sigma_rules(all_results)

        return {
            "scan_timestamp": self.get_timestamp(),
            "system_info": {
                "os": platform.system(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "python_version": platform.python_version()
            },
            "detections": [
                {
                    "software": result.software,
                    "detection_type": result.detection_type,
                    "value": result.value,
                    "path": result.path,
                    "confidence": result.confidence
                }
                for result in all_results
            ],
            "sigma_matches": sigma_detections,
            "summary": {
                "total_detections": len(all_results),
                "software_found": list(set([r.software for r in all_results])),
                "high_confidence": len([r for r in all_results if r.confidence == "high"]),
                "medium_confidence": len([r for r in all_results if r.confidence == "medium"])
            }
        }

    def apply_sigma_rules(self, results: List[DetectionResult]) -> List[Dict]:
        """Apply loaded SIGMA rules to detection results"""
        matches = []
        for rule in self.sigma_rules:
            # Simple matching logic for demonstration
            # In a real implementation, this would be more sophisticated
            for result in results:
                if self.rule_matches_result(rule, result):
                    matches.append({
                        "rule_id": rule.get("id", "unknown"),
                        "rule_title": rule.get("title", "Unknown Rule"),
                        "detection": {
                            "software": result.software,
                            "type": result.detection_type,
                            "value": result.value
                        },
                        "level": rule.get("level", "medium")
                    })
        return matches

    def rule_matches_result(self, rule: Dict, result: DetectionResult) -> bool:
        """Check if a SIGMA rule matches a detection result"""
        # This is a simplified matching logic
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})

        # Check if any selection criteria matches the result
        for key, value in selection.items():
            if isinstance(value, str):
                if value.lower() in result.value.lower():
                    return True
            elif isinstance(value, list):
                for v in value:
                    if str(v).lower() in result.value.lower():
                        return True

        return False

    def get_timestamp(self) -> str:
        """Get current timestamp"""
        return datetime.now().isoformat()

    def collect_logs(self, output_format: str = "zip") -> str:
        """
        Collect logs from detected LLM software installations
        
        Args:
            output_format: "zip" or "7z" (requires 7zip to be installed)
            
        Returns:
            Path to the created archive file
        """
        print("Collecting LLM software logs...")
        
        # Create temporary directory for log collection
        temp_dir = Path("llm_logs_temp")
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        temp_dir.mkdir(exist_ok=True)
        
        collected_files = []
        
        # Collect logs from detected software using SIGMA rules
        detection_rules = self.load_detection_rules()
        
        for rule in detection_rules:
            software_name = self.get_software_name_from_rule(rule)
            log_files = self._collect_logs_from_rule(rule, temp_dir, collected_files)
            collected_files.extend(log_files)
        
        # Security: Create output directory if it doesn't exist
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        # Create archive
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = output_dir / f"ai_discovery_logs_{timestamp}"
        
        if output_format.lower() == "7z":
            archive_path = self._create_7z_archive(temp_dir, archive_name)
        else:
            archive_path = self._create_zip_archive(temp_dir, archive_name)
        
        # Clean up temporary directory
        shutil.rmtree(temp_dir)
        
        print(f"Log collection complete. Archive created: {archive_path}")
        print(f"Total files collected: {len(collected_files)}")
        
        return str(archive_path)

    def _collect_ollama_logs(self, temp_dir: Path) -> List[str]:
        """Collect Ollama logs and configuration files"""
        collected_files = []
        ollama_dir = temp_dir / "ollama"
        ollama_dir.mkdir(exist_ok=True)
        
        # Common Ollama log and config locations
        ollama_paths = {
            "Windows": [
                os.path.expanduser("~/.ollama"),
                os.path.expanduser("~/AppData/Local/Programs/Ollama"),
                os.path.expanduser("~/AppData/Roaming/Ollama"),
                "C:\\Program Files\\Ollama",
                "C:\\ollama"
            ],
            "Darwin": [
                "/Applications/Ollama.app",
                os.path.expanduser("~/.ollama"),
                "/usr/local/bin/ollama",
                os.path.expanduser("~/Library/Logs/Ollama"),
                os.path.expanduser("~/Library/Application Support/Ollama")
            ],
            "Linux": [
                "/usr/bin/ollama",
                "/usr/local/bin/ollama",
                "/usr/share/ollama",
                "/var/lib/ollama",
                "/var/log/ollama",
                os.path.expanduser("~/.ollama"),
                os.path.expanduser("~/.local/bin/ollama")
            ]
        }
        
        system = platform.system()
        for base_path in ollama_paths.get(system, []):
            if os.path.exists(base_path):
                try:
                    # Copy the directory structure, excluding large model files
                    dest_path = ollama_dir / Path(base_path).name
                    if os.path.isdir(base_path):
                        self._copy_directory_filtered(base_path, dest_path, collected_files, "ollama")
                    else:
                        if self._should_include_file(base_path):
                            shutil.copy2(base_path, dest_path)
                            collected_files.append(f"ollama/{Path(base_path).name}")
                except Exception as e:
                    print(f"Warning: Could not copy {base_path}: {e}")
        
        # Collect process information
        self._collect_process_info("ollama", ollama_dir, collected_files)
        
        # Collect environment variables
        self._collect_env_vars("ollama", ollama_dir, collected_files)
        
        # Collect version information
        self._collect_version_info("ollama", ollama_dir, collected_files)
        
        return collected_files

    def _collect_logs_from_rule(self, rule: Dict, temp_dir: Path, collected_files: List[str]) -> List[str]:
        """Collect logs based on SIGMA rule specifications"""
        detection_spec = rule.get('detection', {})
        software_name = self.get_software_name_from_rule(rule)
        system = platform.system()
        
        # Create software directory
        software_dir = temp_dir / software_name.lower().replace(" ", "")
        software_dir.mkdir(exist_ok=True)
        
        # Get log collection paths from rule
        if 'log_collection_paths' in detection_spec:
            log_paths = detection_spec['log_collection_paths']
            platform_paths = log_paths.get(system.lower(), [])
            
            for path_template in platform_paths:
                # Expand environment variables
                path = os.path.expandvars(path_template)
                if os.path.exists(path):
                    try:
                        # Copy the directory structure, excluding large model files
                        dest_path = software_dir / Path(path).name
                        if os.path.isdir(path):
                            self._copy_directory_filtered(path, dest_path, collected_files, software_name.lower().replace(" ", ""))
                        else:
                            if self._should_include_file(path):
                                shutil.copy2(path, dest_path)
                                collected_files.append(f"{software_name.lower().replace(' ', '')}/{Path(path).name}")
                    except Exception as e:
                        print(f"Warning: Could not copy {path}: {e}")
        
        # Collect process information
        self._collect_process_info(software_name.lower().replace(" ", ""), software_dir, collected_files)
        
        # Collect environment variables
        self._collect_env_vars(software_name.lower().replace(" ", ""), software_dir, collected_files)
        
        # Collect version information
        self._collect_version_info(software_name.lower().replace(" ", ""), software_dir, collected_files)
        
        # Special handling for vLLM Python package info
        if software_name == "vLLM":
            self._collect_vllm_package_info(software_dir, collected_files)
        
        return collected_files

    def _collect_vllm_package_info(self, software_dir: Path, collected_files: List[str]):
        """Collect vLLM Python package information"""
        try:
            import pkg_resources
            vllm_info = {
                "package_name": "vllm",
                "installed": False,
                "version": None,
                "location": None
            }
            
            for dist in pkg_resources.working_set:
                if dist.project_name.lower() == 'vllm':
                    vllm_info.update({
                        "installed": True,
                        "version": dist.version,
                        "location": dist.location
                    })
                    break
            
            vllm_package_file = software_dir / "vllm_package_info.json"
            with open(vllm_package_file, 'w', encoding='utf-8') as f:
                json.dump(vllm_info, f, indent=2, ensure_ascii=False)
            collected_files.append("vllm/vllm_package_info.json")
        except Exception as e:
            print(f"Warning: Could not collect vLLM package info: {e}")

    def _collect_lmstudio_logs(self, temp_dir: Path) -> List[str]:
        """Collect LM Studio logs and configuration files"""
        collected_files = []
        lmstudio_dir = temp_dir / "lmstudio"
        lmstudio_dir.mkdir(exist_ok=True)
        
        # Common LM Studio log and config locations
        lmstudio_paths = {
            "Windows": [
                os.path.expanduser("~/AppData/Local/LMStudio"),
                os.path.expanduser("~/AppData/Roaming/LMStudio"),
                os.path.expanduser("~/.cache/lm-studio"),
                os.path.expanduser("~/.lmstudio"),
                "C:\\Program Files\\LMStudio"
            ],
            "Darwin": [
                "/Applications/LM Studio.app",
                os.path.expanduser("~/.cache/lm-studio"),
                os.path.expanduser("~/.lmstudio"),
                os.path.expanduser("~/Library/Application Support/LMStudio"),
                os.path.expanduser("~/Library/Logs/LMStudio")
            ],
            "Linux": [
                os.path.expanduser("~/.cache/lm-studio"),
                os.path.expanduser("~/.lmstudio"),
                os.path.expanduser("~/LMStudio"),
                "/opt/lmstudio"
            ]
        }
        
        system = platform.system()
        for base_path in lmstudio_paths.get(system, []):
            if os.path.exists(base_path):
                try:
                    # Copy the directory structure, excluding large model files
                    dest_path = lmstudio_dir / Path(base_path).name
                    if os.path.isdir(base_path):
                        self._copy_directory_filtered(base_path, dest_path, collected_files, "lmstudio")
                    else:
                        if self._should_include_file(base_path):
                            shutil.copy2(base_path, dest_path)
                            collected_files.append(f"lmstudio/{Path(base_path).name}")
                except Exception as e:
                    print(f"Warning: Could not copy {base_path}: {e}")
        
        # Collect process information
        self._collect_process_info("lmstudio", lmstudio_dir, collected_files)
        
        # Collect environment variables
        self._collect_env_vars("lmstudio", lmstudio_dir, collected_files)
        
        # Collect version information
        self._collect_version_info("lmstudio", lmstudio_dir, collected_files)
        
        return collected_files

    def _collect_gpt4all_logs(self, temp_dir: Path) -> List[str]:
        """Collect GPT4All logs and configuration files"""
        collected_files = []
        gpt4all_dir = temp_dir / "gpt4all"
        gpt4all_dir.mkdir(exist_ok=True)
        
        # Common GPT4All log and config locations
        gpt4all_paths = {
            "Windows": [
                os.path.expanduser("~/AppData/Local/GPT4All"),
                os.path.expanduser("~/AppData/Roaming/GPT4All"),
                "C:\\Program Files\\GPT4All",
                "C:\\Program Files (x86)\\GPT4All",
                os.path.expanduser("~/.gpt4all"),
                os.path.expanduser("~/Documents/GPT4All"),
                os.path.expanduser("~/Downloads/GPT4All")
            ],
            "Darwin": [
                "/Applications/GPT4All.app",
                os.path.expanduser("~/Applications/GPT4All.app"),
                os.path.expanduser("~/.gpt4all"),
                os.path.expanduser("~/Library/Application Support/GPT4All"),
                os.path.expanduser("~/Library/Preferences/GPT4All"),
                os.path.expanduser("~/Library/Logs/GPT4All")
            ],
            "Linux": [
                os.path.expanduser("~/.gpt4all"),
                os.path.expanduser("~/.local/share/gpt4all"),
                os.path.expanduser("~/gpt4all"),
                "/opt/gpt4all",
                "/usr/local/gpt4all",
                os.path.expanduser("~/Downloads/gpt4all")
            ]
        }
        
        system = platform.system()
        for base_path in gpt4all_paths.get(system, []):
            if os.path.exists(base_path):
                try:
                    # Copy the directory structure, excluding large model files
                    dest_path = gpt4all_dir / Path(base_path).name
                    if os.path.isdir(base_path):
                        self._copy_directory_filtered(base_path, dest_path, collected_files, "gpt4all")
                    else:
                        if self._should_include_file(base_path):
                            shutil.copy2(base_path, dest_path)
                            collected_files.append(f"gpt4all/{Path(base_path).name}")
                except Exception as e:
                    print(f"Warning: Could not copy {base_path}: {e}")
        
        # Collect process information
        self._collect_process_info("gpt4all", gpt4all_dir, collected_files)
        
        # Collect environment variables
        self._collect_env_vars("gpt4all", gpt4all_dir, collected_files)
        
        # Collect version information
        self._collect_version_info("gpt4all", gpt4all_dir, collected_files)
        
        return collected_files

    def _collect_vllm_logs(self, temp_dir: Path) -> List[str]:
        """Collect vLLM logs and configuration files"""
        collected_files = []
        vllm_dir = temp_dir / "vllm"
        vllm_dir.mkdir(exist_ok=True)
        
        # Common vLLM log and config locations
        vllm_paths = {
            "Windows": [
                os.path.expanduser("~/AppData/Local/vLLM"),
                os.path.expanduser("~/AppData/Roaming/vLLM"),
                "C:\\Program Files\\vLLM",
                os.path.expanduser("~/.vllm"),
                os.path.expanduser("~/vllm"),
                os.path.expanduser("~/Documents/vllm")
            ],
            "Darwin": [
                os.path.expanduser("~/.vllm"),
                os.path.expanduser("~/vllm"),
                os.path.expanduser("~/Library/Application Support/vLLM"),
                os.path.expanduser("~/Library/Preferences/vLLM"),
                os.path.expanduser("~/Library/Logs/vLLM")
            ],
            "Linux": [
                os.path.expanduser("~/.vllm"),
                os.path.expanduser("~/vllm"),
                "/opt/vllm",
                "/usr/local/vllm",
                os.path.expanduser("~/.local/share/vllm"),
                "/var/log/vllm"
            ]
        }
        
        system = platform.system()
        for base_path in vllm_paths.get(system, []):
            if os.path.exists(base_path):
                try:
                    # Copy the directory structure, excluding large model files
                    dest_path = vllm_dir / Path(base_path).name
                    if os.path.isdir(base_path):
                        self._copy_directory_filtered(base_path, dest_path, collected_files, "vllm")
                    else:
                        if self._should_include_file(base_path):
                            shutil.copy2(base_path, dest_path)
                            collected_files.append(f"vllm/{Path(base_path).name}")
                except Exception as e:
                    print(f"Warning: Could not copy {base_path}: {e}")
        
        # Collect process information
        self._collect_process_info("vllm", vllm_dir, collected_files)
        
        # Collect environment variables
        self._collect_env_vars("vllm", vllm_dir, collected_files)
        
        # Collect version information
        self._collect_version_info("vllm", vllm_dir, collected_files)
        
        # Collect Python package information for vLLM
        try:
            import pkg_resources
            vllm_info = {
                "package_name": "vllm",
                "installed": False,
                "version": None,
                "location": None
            }
            
            for dist in pkg_resources.working_set:
                if dist.project_name.lower() == 'vllm':
                    vllm_info.update({
                        "installed": True,
                        "version": dist.version,
                        "location": dist.location
                    })
                    break
            
            vllm_package_file = vllm_dir / "vllm_package_info.json"
            with open(vllm_package_file, 'w', encoding='utf-8') as f:
                json.dump(vllm_info, f, indent=2, ensure_ascii=False)
            collected_files.append("vllm/vllm_package_info.json")
        except Exception as e:
            print(f"Warning: Could not collect vLLM package info: {e}")
        
        return collected_files

    def _collect_process_info(self, software: str, target_dir: Path, collected_files: List[str]):
        """Collect information about running processes"""
        try:
            process_info = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'memory_info']):
                try:
                    if proc.info['name'] and software.lower() in proc.info['name'].lower():
                        process_info.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'exe': proc.info.get('exe'),
                            'cmdline': proc.info.get('cmdline'),
                            'create_time': proc.info.get('create_time'),
                            'memory_info': proc.info.get('memory_info')
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if process_info:
                process_file = target_dir / f"{software}_processes.json"
                with open(process_file, 'w', encoding='utf-8') as f:
                    json.dump(process_info, f, indent=2, ensure_ascii=False)
                collected_files.append(f"{software}/{software}_processes.json")
        except Exception as e:
            print(f"Warning: Could not collect process info for {software}: {e}")

    def _should_include_file(self, file_path: str) -> bool:
        """Check if a file should be included in log collection (only text files, no binaries)"""
        try:
            # Get file size in bytes
            file_size = os.path.getsize(file_path)
            
            # Skip files larger than configured threshold
            max_size = self.max_file_size_mb * 1024 * 1024
            if file_size > max_size:
                print(f"Skipping large file: {file_path} ({file_size / (1024*1024):.1f}MB)")
                return False
            
            # Only include text file extensions
            text_extensions = {
                '.txt', '.log', '.json', '.yml', '.yaml', '.xml', '.csv', '.md', '.ini', 
                '.cfg', '.conf', '.config', '.properties', '.env', '.bat', '.sh', '.ps1',
                '.py', '.js', '.html', '.css', '.sql', '.sqlite', '.db', '.sqlite3'
            }
            
            file_ext = Path(file_path).suffix.lower()
            if file_ext not in text_extensions:
                print(f"Skipping binary file: {file_path} (extension: {file_ext})")
                return False
            
            # Skip common binary and model file extensions
            binary_extensions = {
                '.exe', '.dll', '.so', '.dylib', '.bin', '.safetensors', '.gguf', '.ggml', 
                '.model', '.weights', '.pth', '.pt', '.ckpt', '.h5', '.pb', '.onnx',
                '.pkl', '.pickle', '.joblib', '.npy', '.npz', '.parquet', '.feather',
                '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.iso', '.img',
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico', '.svg',
                '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac', '.ogg',
                '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
            }
            
            if file_ext in binary_extensions:
                print(f"Skipping binary file: {file_path}")
                return False
            
            # Skip files with model-related names
            file_name = Path(file_path).name.lower()
            model_keywords = {'model', 'weights', 'checkpoint', 'tensor', 'gguf', 'ggml', 'safetensors'}
            if any(keyword in file_name for keyword in model_keywords):
                if file_size > 10 * 1024 * 1024:  # 10MB threshold for model-related files
                    print(f"Skipping large model-related file: {file_path} ({file_size / (1024*1024):.1f}MB)")
                    return False
            
            # Additional check: try to read first few bytes to detect binary files
            try:
                with open(file_path, 'rb') as f:
                    chunk = f.read(1024)  # Read first 1KB
                    # Check for null bytes (common in binary files)
                    if b'\x00' in chunk:
                        print(f"Skipping binary file (contains null bytes): {file_path}")
                        return False
                    # Check for common binary file signatures
                    binary_signatures = [
                        b'MZ',  # Windows executables
                        b'\x7fELF',  # Linux executables
                        b'\xfe\xed\xfa',  # macOS executables
                        b'PK',  # ZIP files
                        b'\x1f\x8b',  # GZIP files
                        b'BM',  # BMP images
                        b'\xff\xd8\xff',  # JPEG images
                        b'\x89PNG',  # PNG images
                        b'GIF8',  # GIF images
                        b'%PDF',  # PDF files
                    ]
                    for sig in binary_signatures:
                        if chunk.startswith(sig):
                            print(f"Skipping binary file (binary signature detected): {file_path}")
                            return False
            except (OSError, IOError):
                # If we can't read the file, skip it
                return False
            
            return True
            
        except (OSError, IOError):
            # If we can't access the file, skip it
            return False

    def _copy_directory_filtered(self, src_dir: str, dest_dir: Path, collected_files: List[str], software: str):
        """Copy directory structure while filtering out large model files"""
        try:
            # Create destination directory
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            # Walk through source directory
            for root, dirs, files in os.walk(src_dir):
                # Calculate relative path from source directory
                rel_path = os.path.relpath(root, src_dir)
                if rel_path == '.':
                    rel_path = ''
                
                # Create corresponding destination directory
                dest_subdir = dest_dir / rel_path
                dest_subdir.mkdir(parents=True, exist_ok=True)
                
                # Copy files that pass the filter
                for file in files:
                    src_file = os.path.join(root, file)
                    dest_file = dest_subdir / file
                    
                    if self._should_include_file(src_file):
                        try:
                            shutil.copy2(src_file, dest_file)
                            # Add to collected files list with relative path
                            if rel_path:
                                collected_files.append(f"{software}/{rel_path}/{file}")
                            else:
                                collected_files.append(f"{software}/{file}")
                        except Exception as e:
                            print(f"Warning: Could not copy {src_file}: {e}")
                    else:
                        # Create a placeholder file indicating what was skipped
                        placeholder_file = dest_subdir / f"{file}.skipped"
                        try:
                            with open(placeholder_file, 'w') as f:
                                f.write(f"File skipped during log collection: {file}\n")
                                f.write(f"Original path: {src_file}\n")
                                f.write(f"Reason: Binary file or large model file\n")
                                f.write(f"Skipped to keep archive size manageable\n")
                            if rel_path:
                                collected_files.append(f"{software}/{rel_path}/{file}.skipped")
                            else:
                                collected_files.append(f"{software}/{file}.skipped")
                        except Exception:
                            pass  # Ignore errors creating placeholder files
            
        except Exception as e:
            print(f"Warning: Could not copy directory {src_dir}: {e}")

    def _collect_version_info(self, software: str, target_dir: Path, collected_files: List[str]):
        """Collect version information for the software using SIGMA rules"""
        try:
            version_info = {
                "software": software,
                "collection_timestamp": datetime.now().isoformat(),
                "version_sources": {}
            }
            
            # Find the corresponding SIGMA rule for this software
            detection_rules = self.load_detection_rules()
            for rule in detection_rules:
                rule_software = self.get_software_name_from_rule(rule)
                if rule_software.lower() == software.lower():
                    self._collect_version_from_rule(rule, version_info)
                    break
            
            if version_info["version_sources"]:
                version_file = target_dir / f"{software}_version.json"
                with open(version_file, 'w', encoding='utf-8') as f:
                    json.dump(version_info, f, indent=2, ensure_ascii=False)
                collected_files.append(f"{software}/{software}_version.json")
        except Exception as e:
            print(f"Warning: Could not collect version info for {software}: {e}")

    def _collect_version_from_rule(self, rule: Dict, version_info: Dict):
        """Collect version information based on SIGMA rule specifications"""
        detection_spec = rule.get('detection', {})
        software_name = self.get_software_name_from_rule(rule)
        
        if 'version_detection' not in detection_spec:
            return
        
        version_spec = detection_spec['version_detection']
        
        # Command line version detection
        if 'command_line' in version_spec:
            for command in version_spec['command_line']:
                try:
                    result = subprocess.run(command.split(), 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        version_info["version_sources"]["command_line"] = {
                            "command": command,
                            "output": result.stdout.strip(),
                            "version": result.stdout.strip()
                        }
                        break
                except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                    pass
        
        # Config file version detection
        if 'config_files' in version_spec:
            for config_path in version_spec['config_files']:
                expanded_path = os.path.expandvars(config_path)
                if os.path.exists(expanded_path):
                    try:
                        with open(expanded_path, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                            if content:
                                version_info["version_sources"]["config_file"] = {
                                    "path": expanded_path,
                                    "content": content
                                }
                                break
                    except Exception:
                        pass
        
        # Package file version detection
        if 'package_files' in version_spec:
            for package_path in version_spec['package_files']:
                expanded_path = os.path.expandvars(package_path)
                if os.path.exists(expanded_path):
                    try:
                        with open(expanded_path, 'r', encoding='utf-8') as f:
                            package_data = json.load(f)
                            if 'version' in package_data:
                                version_info["version_sources"]["package_file"] = {
                                    "path": expanded_path,
                                    "version": package_data['version']
                                }
                                break
                    except Exception:
                        pass
        
        # Python package version detection
        if 'python_package' in version_spec:
            try:
                import pkg_resources
                for package_name in version_spec['python_package']:
                    for dist in pkg_resources.working_set:
                        if dist.project_name.lower() == package_name.lower():
                            version_info["version_sources"]["python_package"] = {
                                "package_name": dist.project_name,
                                "version": dist.version,
                                "location": dist.location
                            }
                            break
            except ImportError:
                pass
        
        # Setup file version detection
        if 'setup_files' in version_spec:
            for setup_path in version_spec['setup_files']:
                expanded_path = os.path.expandvars(setup_path)
                if os.path.exists(expanded_path):
                    try:
                        with open(expanded_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Look for version patterns
                            import re
                            version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                            if version_match:
                                version_info["version_sources"]["setup_file"] = {
                                    "path": expanded_path,
                                    "version": version_match.group(1)
                                }
                                break
                    except Exception:
                        pass

    def _collect_ollama_version(self, version_info: Dict):
        """Collect Ollama version information"""
        try:
            # Method 1: Try to run 'ollama --version' command
            try:
                result = subprocess.run(['ollama', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version_info["version_sources"]["command_line"] = {
                        "command": "ollama --version",
                        "output": result.stdout.strip(),
                        "version": result.stdout.strip()
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                pass
            
            # Method 2: Check for version in executable properties (Windows)
            if platform.system() == "Windows":
                ollama_exe_paths = [
                    os.path.expanduser("~/AppData/Local/Programs/Ollama/ollama.exe"),
                    "C:\\Program Files\\Ollama\\ollama.exe",
                    "C:\\ollama\\ollama.exe"
                ]
                
                for exe_path in ollama_exe_paths:
                    if os.path.exists(exe_path):
                        try:
                            import win32api
                            info = win32api.GetFileVersionInfo(exe_path, "\\")
                            version = f"{info['FileVersionMS'] // 65536}.{info['FileVersionMS'] % 65536}.{info['FileVersionLS'] // 65536}.{info['FileVersionLS'] % 65536}"
                            version_info["version_sources"]["executable_properties"] = {
                                "path": exe_path,
                                "version": version,
                                "file_version": info.get('FileVersion', ''),
                                "product_version": info.get('ProductVersion', '')
                            }
                            break
                        except ImportError:
                            # win32api not available, try alternative method
                            try:
                                result = subprocess.run(['powershell', '-Command', 
                                                       f'(Get-Item "{exe_path}").VersionInfo.FileVersion'], 
                                                      capture_output=True, text=True, timeout=10)
                                if result.returncode == 0 and result.stdout.strip():
                                    version_info["version_sources"]["executable_properties"] = {
                                        "path": exe_path,
                                        "version": result.stdout.strip()
                                    }
                            except:
                                pass
                        except Exception:
                            pass
            
            # Method 3: Check for version in configuration files
            config_paths = [
                os.path.expanduser("~/.ollama/config.json"),
                os.path.expanduser("~/.ollama/version"),
                os.path.expanduser("~/AppData/Local/Programs/Ollama/version.txt"),
                os.path.expanduser("~/AppData/Local/Programs/Ollama/VERSION")
            ]
            
            for config_path in config_paths:
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                            if content:
                                version_info["version_sources"]["config_file"] = {
                                    "path": config_path,
                                    "content": content
                                }
                                break
                    except Exception:
                        pass
            
            # Method 4: Check for version in package.json or similar files
            package_paths = [
                os.path.expanduser("~/AppData/Local/Programs/Ollama/package.json"),
                os.path.expanduser("~/AppData/Local/Programs/Ollama/app/package.json")
            ]
            
            for package_path in package_paths:
                if os.path.exists(package_path):
                    try:
                        with open(package_path, 'r', encoding='utf-8') as f:
                            package_data = json.load(f)
                            if 'version' in package_data:
                                version_info["version_sources"]["package_file"] = {
                                    "path": package_path,
                                    "version": package_data['version']
                                }
                                break
                    except Exception:
                        pass
                        
        except Exception as e:
            print(f"Warning: Error collecting Ollama version: {e}")

    def _collect_lmstudio_version(self, version_info: Dict):
        """Collect LM Studio version information"""
        try:
            # Method 1: Check for version in executable properties (Windows)
            if platform.system() == "Windows":
                lmstudio_exe_paths = [
                    os.path.expanduser("~/AppData/Local/LMStudio/LMStudio.exe"),
                    os.path.expanduser("~/AppData/Local/LMStudio/app/LMStudio.exe"),
                    "C:\\Program Files\\LMStudio\\LMStudio.exe"
                ]
                
                for exe_path in lmstudio_exe_paths:
                    if os.path.exists(exe_path):
                        try:
                            import win32api
                            info = win32api.GetFileVersionInfo(exe_path, "\\")
                            version = f"{info['FileVersionMS'] // 65536}.{info['FileVersionMS'] % 65536}.{info['FileVersionLS'] // 65536}.{info['FileVersionLS'] % 65536}"
                            version_info["version_sources"]["executable_properties"] = {
                                "path": exe_path,
                                "version": version,
                                "file_version": info.get('FileVersion', ''),
                                "product_version": info.get('ProductVersion', '')
                            }
                            break
                        except ImportError:
                            # win32api not available, try alternative method
                            try:
                                result = subprocess.run(['powershell', '-Command', 
                                                       f'(Get-Item "{exe_path}").VersionInfo.FileVersion'], 
                                                      capture_output=True, text=True, timeout=10)
                                if result.returncode == 0 and result.stdout.strip():
                                    version_info["version_sources"]["executable_properties"] = {
                                        "path": exe_path,
                                        "version": result.stdout.strip()
                                    }
                            except:
                                pass
                        except Exception:
                            pass
            
            # Method 2: Check for version in configuration files
            config_paths = [
                os.path.expanduser("~/AppData/Local/LMStudio/version.txt"),
                os.path.expanduser("~/AppData/Local/LMStudio/VERSION"),
                os.path.expanduser("~/AppData/Local/LMStudio/app/version.txt"),
                os.path.expanduser("~/.lmstudio/version")
            ]
            
            for config_path in config_paths:
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                            if content:
                                version_info["version_sources"]["config_file"] = {
                                    "path": config_path,
                                    "content": content
                                }
                                break
                    except Exception:
                        pass
            
            # Method 3: Check for version in package.json or similar files
            package_paths = [
                os.path.expanduser("~/AppData/Local/LMStudio/package.json"),
                os.path.expanduser("~/AppData/Local/LMStudio/app/package.json")
            ]
            
            for package_path in package_paths:
                if os.path.exists(package_path):
                    try:
                        with open(package_path, 'r', encoding='utf-8') as f:
                            package_data = json.load(f)
                            if 'version' in package_data:
                                version_info["version_sources"]["package_file"] = {
                                    "path": package_path,
                                    "version": package_data['version']
                                }
                                break
                    except Exception:
                        pass
            
            # Method 4: Check for version in app data
            app_data_paths = [
                os.path.expanduser("~/AppData/Roaming/LMStudio/settings.json"),
                os.path.expanduser("~/.lmstudio/settings.json")
            ]
            
            for app_data_path in app_data_paths:
                if os.path.exists(app_data_path):
                    try:
                        with open(app_data_path, 'r', encoding='utf-8') as f:
                            settings_data = json.load(f)
                            if 'version' in settings_data:
                                version_info["version_sources"]["settings_file"] = {
                                    "path": app_data_path,
                                    "version": settings_data['version']
                                }
                                break
                    except Exception:
                        pass
                        
        except Exception as e:
            print(f"Warning: Error collecting LM Studio version: {e}")

    def _collect_gpt4all_version(self, version_info: Dict):
        """Collect GPT4All version information"""
        try:
            # Method 1: Check for version in executable properties (Windows)
            if platform.system() == "Windows":
                gpt4all_exe_paths = [
                    os.path.expanduser("~/AppData/Local/GPT4All/GPT4All.exe"),
                    os.path.expanduser("~/AppData/Local/GPT4All/app/GPT4All.exe"),
                    "C:\\Program Files\\GPT4All\\GPT4All.exe",
                    "C:\\Program Files (x86)\\GPT4All\\GPT4All.exe"
                ]
                
                for exe_path in gpt4all_exe_paths:
                    if os.path.exists(exe_path):
                        try:
                            import win32api
                            info = win32api.GetFileVersionInfo(exe_path, "\\")
                            version = f"{info['FileVersionMS'] // 65536}.{info['FileVersionMS'] % 65536}.{info['FileVersionLS'] // 65536}.{info['FileVersionLS'] % 65536}"
                            version_info["version_sources"]["executable_properties"] = {
                                "path": exe_path,
                                "version": version,
                                "file_version": info.get('FileVersion', ''),
                                "product_version": info.get('ProductVersion', '')
                            }
                            break
                        except ImportError:
                            # win32api not available, try alternative method
                            try:
                                result = subprocess.run(['powershell', '-Command', 
                                                       f'(Get-Item "{exe_path}").VersionInfo.FileVersion'], 
                                                      capture_output=True, text=True, timeout=10)
                                if result.returncode == 0 and result.stdout.strip():
                                    version_info["version_sources"]["executable_properties"] = {
                                        "path": exe_path,
                                        "version": result.stdout.strip()
                                    }
                            except:
                                pass
                        except Exception:
                            pass
            
            # Method 2: Check for version in configuration files
            config_paths = [
                os.path.expanduser("~/AppData/Local/GPT4All/version.txt"),
                os.path.expanduser("~/AppData/Local/GPT4All/VERSION"),
                os.path.expanduser("~/AppData/Local/GPT4All/app/version.txt"),
                os.path.expanduser("~/.gpt4all/version"),
                os.path.expanduser("~/Library/Application Support/GPT4All/version.txt")
            ]
            
            for config_path in config_paths:
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                            if content:
                                version_info["version_sources"]["config_file"] = {
                                    "path": config_path,
                                    "content": content
                                }
                                break
                    except Exception:
                        pass
            
            # Method 3: Check for version in package.json or similar files
            package_paths = [
                os.path.expanduser("~/AppData/Local/GPT4All/package.json"),
                os.path.expanduser("~/AppData/Local/GPT4All/app/package.json"),
                os.path.expanduser("~/Library/Application Support/GPT4All/package.json")
            ]
            
            for package_path in package_paths:
                if os.path.exists(package_path):
                    try:
                        with open(package_path, 'r', encoding='utf-8') as f:
                            package_data = json.load(f)
                            if 'version' in package_data:
                                version_info["version_sources"]["package_file"] = {
                                    "path": package_path,
                                    "version": package_data['version']
                                }
                                break
                    except Exception:
                        pass
            
            # Method 4: Check for Python package (if installed via pip)
            try:
                import pkg_resources
                for dist in pkg_resources.working_set:
                    if dist.project_name.lower() == 'gpt4all':
                        version_info["version_sources"]["python_package"] = {
                            "package_name": dist.project_name,
                            "version": dist.version,
                            "location": dist.location
                        }
                        break
            except ImportError:
                pass
                        
        except Exception as e:
            print(f"Warning: Error collecting GPT4All version: {e}")

    def _collect_vllm_version(self, version_info: Dict):
        """Collect vLLM version information"""
        try:
            # Method 1: Check for Python package (primary method for vLLM)
            try:
                import pkg_resources
                for dist in pkg_resources.working_set:
                    if dist.project_name.lower() == 'vllm':
                        version_info["version_sources"]["python_package"] = {
                            "package_name": dist.project_name,
                            "version": dist.version,
                            "location": dist.location
                        }
                        break
            except ImportError:
                pass
            
            # Method 2: Try to run 'vllm --version' command
            try:
                result = subprocess.run(['vllm', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version_info["version_sources"]["command_line"] = {
                        "command": "vllm --version",
                        "output": result.stdout.strip(),
                        "version": result.stdout.strip()
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                pass
            
            # Method 3: Check for version in configuration files
            config_paths = [
                os.path.expanduser("~/.vllm/version"),
                os.path.expanduser("~/.vllm/VERSION"),
                os.path.expanduser("~/vllm/version.txt"),
                os.path.expanduser("~/Library/Application Support/vLLM/version.txt")
            ]
            
            for config_path in config_paths:
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                            if content:
                                version_info["version_sources"]["config_file"] = {
                                    "path": config_path,
                                    "content": content
                                }
                                break
                    except Exception:
                        pass
            
            # Method 4: Check for version in requirements.txt or setup.py
            setup_paths = [
                os.path.expanduser("~/.vllm/setup.py"),
                os.path.expanduser("~/.vllm/requirements.txt"),
                os.path.expanduser("~/vllm/setup.py"),
                os.path.expanduser("~/vllm/requirements.txt")
            ]
            
            for setup_path in setup_paths:
                if os.path.exists(setup_path):
                    try:
                        with open(setup_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Look for version patterns
                            import re
                            version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                            if version_match:
                                version_info["version_sources"]["setup_file"] = {
                                    "path": setup_path,
                                    "version": version_match.group(1)
                                }
                                break
                    except Exception:
                        pass
                        
        except Exception as e:
            print(f"Warning: Error collecting vLLM version: {e}")

    def _collect_env_vars(self, software: str, target_dir: Path, collected_files: List[str]):
        """Collect relevant environment variables"""
        try:
            env_vars = {}
            for key, value in os.environ.items():
                if software.lower() in key.lower() or software.lower() in value.lower():
                    env_vars[key] = value
            
            if env_vars:
                env_file = target_dir / f"{software}_environment.json"
                with open(env_file, 'w', encoding='utf-8') as f:
                    json.dump(env_vars, f, indent=2, ensure_ascii=False)
                collected_files.append(f"{software}/{software}_environment.json")
        except Exception as e:
            print(f"Warning: Could not collect environment variables for {software}: {e}")

    def _create_zip_archive(self, source_dir: Path, archive_name: str) -> Path:
        """Create a ZIP archive of the collected logs"""
        archive_path = Path(f"{archive_name}.zip")
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in source_dir.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(source_dir)
                    zipf.write(file_path, arcname)
        
        return archive_path

    def _create_7z_archive(self, source_dir: Path, archive_name: str) -> Path:
        """Create a 7z archive of the collected logs (requires 7zip to be installed)"""
        archive_path = Path(f"{archive_name}.7z")
        
        try:
            # Try to use 7zip command line tool
            cmd = ['7z', 'a', str(archive_path), f"{source_dir}/*"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return archive_path
            else:
                print("Warning: 7zip command failed, falling back to ZIP format")
                return self._create_zip_archive(source_dir, archive_name)
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("Warning: 7zip not found or command timed out, falling back to ZIP format")
            return self._create_zip_archive(source_dir, archive_name)

    def save_results(self, results: Dict, filename: str = None) -> str:
        """
        Save scan results to JSON file with timestamp and machine name
        
        Args:
            results: Scan results dictionary
            filename: Optional custom filename
            
        Returns:
            Path to saved file
            
        Raises:
            SecurityError: If filename is unsafe
            OSError: If file operation fails
        """
        try:
            # Security: Create output directory if it doesn't exist
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)
            
            if filename is None:
                # Generate filename with timestamp and machine name
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                machine_name = platform.node().replace(" ", "_").replace("-", "_")
                filename = f"ai_discovery_results_{machine_name}_{timestamp}.json"
            else:
                # Security: Validate custom filename
                filename = self.validator.validate_filename(filename)
            
            # Security: Ensure filename has .json extension
            if not filename.endswith('.json'):
                filename += '.json'
            
            # Security: Create full path in output directory
            file_path = output_dir / filename
            
            # Security: Validate final path
            safe_path = self.validator.sanitize_path(str(file_path))
            
            with open(safe_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Results saved to {safe_path}")
            return str(safe_path)
            
        except (SecurityError, OSError) as e:
            logger.error(f"Failed to save results: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error saving results: {e}")
            raise OSError(f"Failed to save results: {e}")

    def generate_human_readable_summary(self, results: Dict) -> str:
        """Generate a human-readable summary of scan results"""
        summary = []
        summary.append("=" * 80)
        summary.append("LLM SOFTWARE DETECTION SCAN REPORT")
        summary.append("=" * 80)
        summary.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"Machine Name: {platform.node()}")
        summary.append(f"Operating System: {platform.system()} {platform.release()}")
        summary.append("")
        
        # Summary statistics
        summary.append("SCAN SUMMARY:")
        summary.append("-" * 40)
        summary.append(f"Total Detections: {results['summary'].get('total_detections', 0)}")
        summary.append(f"Software Found: {', '.join(results['summary'].get('software_found', [])) if results['summary'].get('software_found') else 'None'}")
        summary.append(f"High Confidence Detections: {results['summary'].get('high_confidence', 0)}")
        summary.append(f"Medium Confidence Detections: {results['summary'].get('medium_confidence', 0)}")
        summary.append(f"Low Confidence Detections: {results['summary'].get('low_confidence', 0)}")
        summary.append("")
        
        # Detailed detections
        if results['detections']:
            summary.append("DETAILED DETECTIONS:")
            summary.append("-" * 40)
            for detection in results['detections']:
                confidence = detection.get('confidence', 'unknown')
                summary.append(f"• {detection['software'].upper()}")
                summary.append(f"  - Type: {detection['detection_type']}")
                summary.append(f"  - Value: {detection['value']}")
                summary.append(f"  - Confidence: {confidence}")
                summary.append("")
        
        # SIGMA rule matches
        if results['sigma_matches']:
            summary.append("SIGMA RULE MATCHES:")
            summary.append("-" * 40)
            for match in results['sigma_matches']:
                summary.append(f"• {match['rule_title']}")
                summary.append(f"  - Level: {match['level']}")
                summary.append(f"  - Description: {match.get('description', 'No description available')}")
                summary.append("")
        
        # Recommendations
        summary.append("RECOMMENDATIONS:")
        summary.append("-" * 40)
        if results['summary']['software_found']:
            summary.append("• LLM software detected on this system")
            summary.append("• Review security policies for LLM software usage")
            summary.append("• Consider implementing access controls and monitoring")
            summary.append("• Verify software versions for known vulnerabilities")
            summary.append("• Review collected logs for suspicious activity")
        else:
            summary.append("• No LLM software detected on this system")
            summary.append("• System appears to be free of LLM software installations")
        
        summary.append("")
        summary.append("=" * 80)
        summary.append("End of Report")
        summary.append("=" * 80)
        
        return "\n".join(summary)

def main():
    """
    Main entry point for the AI Discovery Scanner
    
    This function handles command-line argument parsing, input validation,
    and orchestrates the scanning process with comprehensive error handling.
    """
    try:
        # Security: Set up argument parser with input validation
        parser = argparse.ArgumentParser(
            description="AI Discovery Scanner - Secure LLM Software Detection Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Security Features:
  - Input validation and sanitization
  - Path traversal attack prevention  
  - Subprocess command injection protection
  - File operation security
  - Comprehensive error handling
  - Logging and audit trails

Examples:
  %(prog)s                           # Basic scan
  %(prog)s --verbose                 # Verbose output
  %(prog)s --collect-logs            # Collect logs from detected software
  %(prog)s --logs-only               # Only collect logs without scanning
  %(prog)s --max-file-size 50        # Set 50MB file size limit
            """
        )
        
        parser.add_argument("--output", "-o", default="ai_discovery_results.json", 
                           help="Output file for results (JSON format)")
        parser.add_argument("--verbose", "-v", action="store_true", 
                           help="Verbose output with detailed logging")
        parser.add_argument("--sigma-dir", default="sigma_rules", 
                           help="Directory containing SIGMA rules")
        parser.add_argument("--collect-logs", action="store_true",
                           help="Collect logs from detected LLM software")
        parser.add_argument("--log-format", choices=["zip", "7z"], default="zip",
                           help="Archive format for log collection (default: zip)")
        parser.add_argument("--logs-only", action="store_true",
                           help="Only collect logs without running detection scan")
        parser.add_argument("--max-file-size", type=int, default=100,
                           help="Maximum file size in MB to include in log collection (default: 100)")

        args = parser.parse_args()

        # Security: Validate command-line arguments
        if args.max_file_size <= 0 or args.max_file_size > 1000:
            logger.error("max-file-size must be between 1 and 1000 MB")
            sys.exit(1)
        
        if not isinstance(args.sigma_dir, str) or len(args.sigma_dir) > 500:
            logger.error("Invalid sigma-dir parameter")
            sys.exit(1)
        
        if not isinstance(args.output, str) or len(args.output) > 200:
            logger.error("Invalid output filename")
            sys.exit(1)

        # Security: Initialize detector with error handling
        try:
            detector = LLMSoftwareDetector(
                max_file_size_mb=args.max_file_size,
                verbose=args.verbose
            )
            detector.sigma_rules_dir = Path(args.sigma_dir)
            detector._load_sigma_rules()
        except (InputValidationError, SecurityError) as e:
            logger.error(f"Failed to initialize detector: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            sys.exit(1)

        # Security: Handle logs-only mode with error handling
        if args.logs_only:
            try:
                logger.info("Starting log collection mode...")
                print("Collecting logs from LLM software installations...")
                archive_path = detector.collect_logs(args.log_format)
                print(f"Log archive created: {archive_path}")
                logger.info(f"Log collection completed successfully: {archive_path}")
                return
            except (SecurityError, OSError) as e:
                logger.error(f"Log collection failed: {e}")
                print(f"Error: Log collection failed - {e}")
                sys.exit(1)
            except Exception as e:
                logger.error(f"Unexpected error during log collection: {e}")
                logger.debug(f"Traceback: {traceback.format_exc()}")
                print(f"Error: Unexpected error during log collection - {e}")
                sys.exit(1)

        # Security: Run main scan with comprehensive error handling
        try:
            logger.info("Starting LLM software detection scan...")
            results = detector.run_scan()
            logger.info("Scan completed successfully")
        except (SecurityError, InputValidationError) as e:
            logger.error(f"Scan failed due to security/validation error: {e}")
            print(f"Error: Scan failed - {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            print(f"Error: Unexpected error during scan - {e}")
            sys.exit(1)

        # Security: Generate summary with error handling
        try:
            summary = detector.generate_human_readable_summary(results)
            print(summary)
        except Exception as e:
            logger.error(f"Failed to generate summary: {e}")
            print(f"Warning: Could not generate summary - {e}")

        # Security: Save results with proper error handling
        try:
            if args.output == "ai_discovery_results.json":
                # Use auto-generated filename
                saved_file = detector.save_results(results)
            else:
                # Security: Validate custom filename
                safe_filename = detector.validator.validate_filename(args.output)
                saved_file = detector.save_results(results, safe_filename)
            
            logger.info(f"Results saved to: {saved_file}")
        except (SecurityError, OSError) as e:
            logger.error(f"Failed to save results: {e}")
            print(f"Error: Could not save results - {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error saving results: {e}")
            print(f"Error: Unexpected error saving results - {e}")
            sys.exit(1)

        # Security: Save human-readable summary with error handling
        if saved_file:
            try:
                # Create output directory if it doesn't exist
                output_dir = Path("output")
                output_dir.mkdir(exist_ok=True)
                
                # Extract the filename from the saved_file path and create summary filename
                saved_filename = Path(saved_file).name
                summary_filename = output_dir / saved_filename.replace('.json', '_summary.txt')
                
                with open(summary_filename, 'w', encoding='utf-8') as f:
                    f.write(summary)
                print(f"Human-readable summary saved to: {summary_filename}")
                logger.info(f"Summary saved to: {summary_filename}")
            except (OSError, IOError) as e:
                logger.error(f"Failed to save summary file: {e}")
                print(f"Warning: Could not save summary file - {e}")
            except Exception as e:
                logger.error(f"Unexpected error saving summary: {e}")
                print(f"Warning: Unexpected error saving summary - {e}")
                

        # Security: Collect logs if requested with error handling
        if args.collect_logs:
            try:
                if results['summary']['software_found']:
                    print("\n" + "=" * 50)
                    logger.info("Starting log collection from detected software...")
                    archive_path = detector.collect_logs(args.log_format)
                    print(f"Log archive created: {archive_path}")
                    logger.info(f"Log collection completed: {archive_path}")
                else:
                    print("\nNo LLM software detected. Skipping log collection.")
                    logger.info("No software detected, skipping log collection")
            except (SecurityError, OSError) as e:
                logger.error(f"Log collection failed: {e}")
                print(f"Error: Log collection failed - {e}")
            except Exception as e:
                logger.error(f"Unexpected error during log collection: {e}")
                print(f"Error: Unexpected error during log collection - {e}")

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Critical error in main function: {e}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        print(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
