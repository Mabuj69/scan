"""
Utility functions for the antivirus scanner.
"""
import os
import hashlib
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('antivirus')

def setup_logger(verbose=False):
    """Configure the logger based on verbosity level."""
    if verbose:
        logger.setLevel(logging.DEBUG)
    return logger

def calculate_file_hash(file_path, hash_type='md5'):
    """
    Calculate the hash of a file.
    
    Args:
        file_path (str): Path to the file
        hash_type (str): Type of hash to calculate ('md5', 'sha1', 'sha256')
        
    Returns:
        str: Hexadecimal digest of the hash
    """
    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256
    }
    
    if hash_type not in hash_functions:
        raise ValueError(f"Unsupported hash type: {hash_type}")
    
    hash_obj = hash_functions[hash_type]()
    
    try:
        with open(file_path, 'rb') as f:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None

def get_file_size(file_path):
    """Get the size of a file in bytes."""
    try:
        return os.path.getsize(file_path)
    except Exception as e:
        logger.error(f"Error getting size for {file_path}: {e}")
        return 0

def get_file_extension(file_path):
    """Get the extension of a file."""
    return os.path.splitext(file_path)[1].lower()

def is_binary_file(file_path):
    """
    Check if a file is binary by reading the first few bytes.
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        bool: True if the file appears to be binary, False otherwise
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk  # Simple heuristic: contains null bytes
    except Exception as e:
        logger.error(f"Error checking if {file_path} is binary: {e}")
        return False

def get_timestamp():
    """Get current timestamp in a formatted string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def format_bytes(size):
    """Format bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"
