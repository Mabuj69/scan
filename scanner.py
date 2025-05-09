"""
Core scanning functionality for the antivirus tool.
"""
import os
import logging
import time
from signatures import SignatureDatabase
from heuristics import HeuristicScanner
from report import ScanReport
from utils import get_file_extension, get_file_size

logger = logging.getLogger('antivirus')

# File extensions to skip (common non-executable files)
SKIP_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico',
    '.mp3', '.wav', '.ogg', '.flac', '.aac',
    '.mp4', '.avi', '.mkv', '.mov', '.wmv',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.ttf', '.otf', '.woff', '.woff2',
    '.svg', '.webp'
}

# Maximum file size to scan (100 MB by default)
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024

class Scanner:
    """Main scanner class that coordinates the scanning process."""
    
    def __init__(self, signature_db_path=None, heuristic_sensitivity=5, 
                 max_file_size=DEFAULT_MAX_FILE_SIZE, skip_extensions=None):
        """
        Initialize the scanner.
        
        Args:
            signature_db_path (str, optional): Path to a custom signature database
            heuristic_sensitivity (int): Sensitivity level for heuristic scanning (1-10)
            max_file_size (int): Maximum file size to scan in bytes
            skip_extensions (set, optional): Set of file extensions to skip
        """
        self.signature_db = SignatureDatabase(signature_db_path)
        self.heuristic_scanner = HeuristicScanner(heuristic_sensitivity)
        self.max_file_size = max_file_size
        self.skip_extensions = SKIP_EXTENSIONS.copy()
        
        if skip_extensions:
            self.skip_extensions.update(skip_extensions)
        
        logger.info(f"Scanner initialized with {self.signature_db.get_signature_count()} signatures")
        logger.info(f"Heuristic sensitivity: {heuristic_sensitivity}")
        logger.info(f"Max file size: {self.max_file_size} bytes")
    
    def should_scan_file(self, file_path):
        """
        Determine if a file should be scanned based on extension and size.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            bool: True if the file should be scanned, False otherwise
        """
        # Skip files with certain extensions
        extension = get_file_extension(file_path)
        if extension in self.skip_extensions:
            logger.debug(f"Skipping file with extension {extension}: {file_path}")
            return False
        
        # Skip files that are too large
        try:
            file_size = get_file_size(file_path)
            if file_size > self.max_file_size:
                logger.debug(f"Skipping large file ({file_size} bytes): {file_path}")
                return False
        except Exception as e:
            logger.error(f"Error checking file size for {file_path}: {e}")
            return False
        
        return True
    
    def scan_file(self, file_path, report):
        """
        Scan a single file for viruses.
        
        Args:
            file_path (str): Path to the file to scan
            report (ScanReport): Report object to update with results
            
        Returns:
            bool: True if the file is infected or suspicious, False otherwise
        """
        logger.debug(f"Scanning file: {file_path}")
        
        try:
            # Check if the file should be scanned
            if not self.should_scan_file(file_path):
                report.skipped_files += 1
                return False
            
            report.scanned_files += 1
            
            # Signature-based scan
            is_infected, virus_name = self.signature_db.check_file(file_path)
            if is_infected:
                report.add_infected_file(file_path, virus_name, "signature")
                return True
            
            # Heuristic scan
            is_suspicious, score, reasons = self.heuristic_scanner.scan_file(file_path)
            if is_suspicious:
                report.add_suspicious_file(file_path, score, reasons)
                return True
            
            return False
        
        except Exception as e:
            error_msg = f"Error scanning file {file_path}: {str(e)}"
            logger.error(error_msg)
            report.add_error(file_path, error_msg)
            return False
    
    def scan_directory(self, directory_path, recursive=True, report=None):
        """
        Scan a directory for viruses.
        
        Args:
            directory_path (str): Path to the directory to scan
            recursive (bool): Whether to scan subdirectories
            report (ScanReport, optional): Existing report to update
            
        Returns:
            ScanReport: Report of the scan results
        """
        if report is None:
            report = ScanReport(directory_path)
        
        logger.info(f"Starting scan of directory: {directory_path}")
        
        try:
            # Walk through the directory
            for root, dirs, files in os.walk(directory_path):
                report.total_directories += 1
                
                # Scan each file in the directory
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    report.total_files += 1
                    
                    # Print progress every 100 files
                    if report.total_files % 100 == 0:
                        logger.info(f"Scanned {report.scanned_files} of {report.total_files} files...")
                    
                    self.scan_file(file_path, report)
                
                # If not recursive, break after the first iteration
                if not recursive:
                    break
        
        except Exception as e:
            error_msg = f"Error scanning directory {directory_path}: {str(e)}"
            logger.error(error_msg)
            report.add_error(directory_path, error_msg)
        
        report.finalize()
        logger.info(f"Scan completed: {report.scanned_files} files scanned, "
                   f"{len(report.infected_files)} infected, "
                   f"{len(report.suspicious_files)} suspicious")
        
        return report
    
    def scan_path(self, path, recursive=True):
        """
        Scan a file or directory.
        
        Args:
            path (str): Path to scan
            recursive (bool): Whether to scan subdirectories
            
        Returns:
            ScanReport: Report of the scan results
        """
        report = ScanReport(path)
        
        if os.path.isfile(path):
            report.total_files = 1
            self.scan_file(path, report)
            report.finalize()
        elif os.path.isdir(path):
            self.scan_directory(path, recursive, report)
        else:
            error_msg = f"Path does not exist: {path}"
            logger.error(error_msg)
            report.add_error(path, error_msg)
            report.finalize()
        
        return report
