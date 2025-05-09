#!/usr/bin/env python3
"""
Command-line antivirus scanning tool.
"""
import os
import sys
import argparse
import logging
import time
from datetime import datetime

from scanner import Scanner
from utils import setup_logger
from report import ScanReport

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Python Antivirus Scanner - Scan files and directories for viruses",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Required arguments
    parser.add_argument(
        "path",
        help="File or directory to scan"
    )
    
    # Optional arguments
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Scan directories recursively"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file for the scan report"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="Format of the scan report"
    )
    
    parser.add_argument(
        "-s", "--signatures",
        help="Path to custom signature database"
    )
    
    parser.add_argument(
        "--heuristic-level",
        type=int,
        choices=range(1, 11),
        default=5,
        help="Heuristic detection sensitivity (1-10)"
    )
    
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=100,
        help="Maximum file size to scan in MB"
    )
    
    parser.add_argument(
        "--skip-extensions",
        help="Comma-separated list of additional file extensions to skip"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress all output except errors"
    )
    
    return parser.parse_args()

def main():
    """Main entry point for the antivirus scanner."""
    args = parse_arguments()
    
    # Set up logging
    log_level = logging.ERROR if args.quiet else (logging.DEBUG if args.verbose else logging.INFO)
    logger = setup_logger(args.verbose)
    
    # Parse skip extensions
    skip_extensions = None
    if args.skip_extensions:
        skip_extensions = set(ext.strip().lower() for ext in args.skip_extensions.split(','))
    
    # Create scanner
    scanner = Scanner(
        signature_db_path=args.signatures,
        heuristic_sensitivity=args.heuristic_level,
        max_file_size=args.max_file_size * 1024 * 1024,  # Convert MB to bytes
        skip_extensions=skip_extensions
    )
    
    # Validate path
    if not os.path.exists(args.path):
        logger.error(f"Path does not exist: {args.path}")
        return 1
    
    # Start scan
    start_time = time.time()
    logger.info(f"Starting scan of {args.path}")
    
    try:
        # Perform scan
        report = scanner.scan_path(args.path, args.recursive)
        
        # Print report to console
        if not args.quiet:
            print(report.generate_text_report())
        
        # Save report to file if requested
        if args.output:
            report.save_report(args.output, args.format)
            logger.info(f"Report saved to {args.output}")
        
        # Return exit code based on scan results
        if report.infected_files:
            return 2  # Infected files found
        elif report.suspicious_files:
            return 3  # Suspicious files found
        elif report.errors:
            return 4  # Errors occurred during scan
        else:
            return 0  # No issues found
    
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 5
    except Exception as e:
        logger.error(f"An error occurred during the scan: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
