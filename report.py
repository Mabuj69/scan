"""
Report generation functionality for scan results.
"""
import os
import json
import logging
from datetime import datetime
from utils import get_timestamp, format_bytes

logger = logging.getLogger('antivirus')

class ScanReport:
    """Generates and manages scan reports."""
    
    def __init__(self, scan_path):
        """
        Initialize a new scan report.
        
        Args:
            scan_path (str): The path that was scanned
        """
        self.scan_path = scan_path
        self.start_time = datetime.now()
        self.end_time = None
        self.total_files = 0
        self.total_directories = 0
        self.scanned_files = 0
        self.skipped_files = 0
        self.infected_files = []
        self.suspicious_files = []
        self.errors = []
        self.signature_detections = 0
        self.heuristic_detections = 0
    
    def add_infected_file(self, file_path, virus_name, detection_type="signature"):
        """
        Add an infected file to the report.
        
        Args:
            file_path (str): Path to the infected file
            virus_name (str): Name of the detected virus
            detection_type (str): Type of detection ("signature" or "heuristic")
        """
        self.infected_files.append({
            'path': file_path,
            'virus_name': virus_name,
            'detection_type': detection_type,
            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
        })
        
        if detection_type == "signature":
            self.signature_detections += 1
        elif detection_type == "heuristic":
            self.heuristic_detections += 1
    
    def add_suspicious_file(self, file_path, score, reasons):
        """
        Add a suspicious file to the report.
        
        Args:
            file_path (str): Path to the suspicious file
            score (int): Heuristic score
            reasons (list): List of reasons why the file is suspicious
        """
        self.suspicious_files.append({
            'path': file_path,
            'score': score,
            'reasons': reasons,
            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
        })
    
    def add_error(self, file_path, error_message):
        """
        Add an error to the report.
        
        Args:
            file_path (str): Path to the file that caused the error
            error_message (str): Error message
        """
        self.errors.append({
            'path': file_path,
            'error': error_message
        })
    
    def finalize(self):
        """Finalize the report by setting the end time."""
        self.end_time = datetime.now()
    
    def get_scan_duration(self):
        """Get the duration of the scan in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()
    
    def get_summary(self):
        """Get a summary of the scan results."""
        return {
            'scan_path': self.scan_path,
            'start_time': self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': self.end_time.strftime("%Y-%m-%d %H:%M:%S") if self.end_time else None,
            'duration': self.get_scan_duration(),
            'total_files': self.total_files,
            'total_directories': self.total_directories,
            'scanned_files': self.scanned_files,
            'skipped_files': self.skipped_files,
            'infected_files_count': len(self.infected_files),
            'suspicious_files_count': len(self.suspicious_files),
            'errors_count': len(self.errors),
            'signature_detections': self.signature_detections,
            'heuristic_detections': self.heuristic_detections
        }
    
    def generate_text_report(self):
        """
        Generate a text report of the scan results.
        
        Returns:
            str: Text report
        """
        summary = self.get_summary()
        
        report = [
            "=" * 60,
            f"ANTIVIRUS SCAN REPORT",
            "=" * 60,
            f"Scan path: {summary['scan_path']}",
            f"Start time: {summary['start_time']}",
            f"End time: {summary['end_time']}",
            f"Duration: {summary['duration']:.2f} seconds",
            f"Total files: {summary['total_files']}",
            f"Total directories: {summary['total_directories']}",
            f"Scanned files: {summary['scanned_files']}",
            f"Skipped files: {summary['skipped_files']}",
            "-" * 60,
            f"RESULTS SUMMARY:",
            f"Infected files: {summary['infected_files_count']}",
            f"Suspicious files: {summary['suspicious_files_count']}",
            f"Errors: {summary['errors_count']}",
            f"Signature detections: {summary['signature_detections']}",
            f"Heuristic detections: {summary['heuristic_detections']}",
            "-" * 60
        ]
        
        if self.infected_files:
            report.append("INFECTED FILES:")
            for idx, file in enumerate(self.infected_files, 1):
                report.append(f"{idx}. {file['path']}")
                report.append(f"   Virus: {file['virus_name']}")
                report.append(f"   Detection: {file['detection_type']}")
                report.append(f"   Size: {format_bytes(file['size'])}")
            report.append("-" * 60)
        
        if self.suspicious_files:
            report.append("SUSPICIOUS FILES:")
            for idx, file in enumerate(self.suspicious_files, 1):
                report.append(f"{idx}. {file['path']}")
                report.append(f"   Score: {file['score']}")
                report.append(f"   Size: {format_bytes(file['size'])}")
                report.append(f"   Reasons:")
                for reason in file['reasons']:
                    report.append(f"     - {reason}")
            report.append("-" * 60)
        
        if self.errors:
            report.append("ERRORS:")
            for idx, error in enumerate(self.errors, 1):
                report.append(f"{idx}. {error['path']}")
                report.append(f"   Error: {error['error']}")
            report.append("-" * 60)
        
        report.append("END OF REPORT")
        
        return "\n".join(report)
    
    def save_report(self, output_path, format='text'):
        """
        Save the report to a file.
        
        Args:
            output_path (str): Path to save the report
            format (str): Format of the report ('text' or 'json')
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if format == 'json':
                data = {
                    'summary': self.get_summary(),
                    'infected_files': self.infected_files,
                    'suspicious_files': self.suspicious_files,
                    'errors': self.errors
                }
                
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            else:
                with open(output_path, 'w') as f:
                    f.write(self.generate_text_report())
            
            logger.info(f"Report saved to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving report to {output_path}: {e}")
            return False
