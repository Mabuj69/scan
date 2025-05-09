"""
Heuristic-based virus detection functionality.
"""
import os
import re
import logging
from utils import is_binary_file, get_file_extension

logger = logging.getLogger('antivirus')

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.scr', '.pif', '.com',
    '.vbs', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi',
    '.hta', '.jar'
}

# Suspicious patterns in files
SUSPICIOUS_PATTERNS = [
    # Shell commands
    rb'cmd\.exe',
    rb'powershell\.exe',
    rb'wscript\.exe',
    rb'cscript\.exe',
    
    # Registry manipulation
    rb'RegCreateKeyEx',
    rb'RegSetValueEx',
    rb'HKEY_LOCAL_MACHINE',
    rb'HKEY_CURRENT_USER',
    
    # Process manipulation
    rb'CreateProcess',
    rb'ShellExecute',
    rb'WinExec',
    
    # Network activity
    rb'WSAStartup',
    rb'connect\(',
    rb'InternetOpen',
    rb'URLDownloadToFile',
    
    # File operations
    rb'CreateFile',
    rb'WriteFile',
    rb'CopyFile',
    rb'MoveFile',
    
    # Encryption/Obfuscation
    rb'CryptEncrypt',
    rb'CryptDecrypt',
    rb'base64',
    
    # Anti-debugging
    rb'IsDebuggerPresent',
    rb'CheckRemoteDebuggerPresent',
    
    # Auto-start mechanisms
    rb'Run\s*=',
    rb'RunOnce\s*=',
    rb'STARTUP',
    
    # Script obfuscation
    rb'eval\(',
    rb'String\.fromCharCode',
    rb'escape\(',
    rb'unescape\(',
    
    # Ransomware indicators
    rb'\.encrypted',
    rb'ransom',
    rb'bitcoin',
    rb'payment',
    rb'decrypt',
]

class HeuristicScanner:
    """Performs heuristic-based scanning for potentially malicious files."""
    
    def __init__(self, sensitivity=5):
        """
        Initialize the heuristic scanner.
        
        Args:
            sensitivity (int): Sensitivity level (1-10), higher means more aggressive detection
        """
        self.sensitivity = min(max(1, sensitivity), 10)
        logger.info(f"Heuristic scanner initialized with sensitivity level {self.sensitivity}")
    
    def scan_file(self, file_path):
        """
        Scan a file using heuristic techniques.
        
        Args:
            file_path (str): Path to the file to scan
            
        Returns:
            tuple: (is_suspicious, score, reasons)
        """
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return False, 0, []
        
        score = 0
        reasons = []
        
        # Check file extension
        extension = get_file_extension(file_path)
        if extension in SUSPICIOUS_EXTENSIONS:
            score += 2
            reasons.append(f"Suspicious file extension: {extension}")
        
        # Skip very large files
        file_size = os.path.getsize(file_path)
        if file_size > 10 * 1024 * 1024:  # 10 MB
            logger.debug(f"Skipping large file for heuristic scan: {file_path}")
            return score >= self.sensitivity, score, reasons
        
        # Only scan binary files or script files
        if not is_binary_file(file_path) and extension not in {'.bat', '.ps1', '.vbs', '.js', '.py', '.sh'}:
            return score >= self.sensitivity, score, reasons
        
        # Check for suspicious patterns
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
                for pattern in SUSPICIOUS_PATTERNS:
                    matches = re.findall(pattern, content)
                    if matches:
                        score += 1
                        reasons.append(f"Found suspicious pattern: {pattern.decode('utf-8', errors='ignore')}")
                        
                        # Stop if we've already reached the threshold
                        if score >= self.sensitivity:
                            break
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
        
        # Additional heuristics for executable files
        if extension == '.exe':
            # Check for packed executables (simplified check)
            if b'UPX' in content or b'PEC2' in content:
                score += 2
                reasons.append("Potentially packed executable")
            
            # Check for unusual section names
            if b'.text' not in content and b'.data' not in content:
                score += 1
                reasons.append("Unusual executable structure")
        
        is_suspicious = score >= self.sensitivity
        if is_suspicious:
            logger.warning(f"Heuristic detection triggered for {file_path} with score {score}")
        
        return is_suspicious, score, reasons
