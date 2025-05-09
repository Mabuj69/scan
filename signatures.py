"""
Virus signature database and matching functionality.
"""
import os
import json
import logging
from utils import calculate_file_hash

logger = logging.getLogger('antivirus')

# Sample virus signatures (MD5 hashes)
# In a real implementation, these would be loaded from a database file
DEFAULT_SIGNATURES = {
    # EICAR test file signature
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",

    # Some example malware signatures (these are fictional)
    "e1112134b6dcc8bed54e0e34d8ac272795e73d74": "Trojan.Generic.123456",
    "3a52ce780950d4d969792a2559cd519d7ee8c727": "Backdoor.Win32.BlackEnergy",
    "5c1f4f69c45cff9725d9969f9ffcf79d07bd0f54": "Worm.Win32.Conficker.A",
    "f273d1283364625f986050bdf7dec8bb408a255b": "Ransomware.Cryptolocker",
    "a3aca2964e6194f1bd5b4ca7585557c09d24d12f": "Trojan.Downloader.Upatre",
}

class SignatureDatabase:
    """Manages virus signatures and performs signature-based scanning."""

    def __init__(self, custom_db_path=None):
        """
        Initialize the signature database.

        Args:
            custom_db_path (str, optional): Path to a custom signature database file
        """
        self.signatures = {}
        self.load_default_signatures()

        if custom_db_path and os.path.exists(custom_db_path):
            self.load_custom_signatures(custom_db_path)

    def load_default_signatures(self):
        """Load the default signatures."""
        self.signatures.update(DEFAULT_SIGNATURES)
        logger.info(f"Loaded {len(DEFAULT_SIGNATURES)} default signatures")

    def load_custom_signatures(self, db_path):
        """
        Load custom signatures from a JSON file.

        Args:
            db_path (str): Path to the signature database file
        """
        try:
            with open(db_path, 'r') as f:
                custom_signatures = json.load(f)
                self.signatures.update(custom_signatures)
                logger.info(f"Loaded {len(custom_signatures)} custom signatures from {db_path}")
        except Exception as e:
            logger.error(f"Error loading custom signatures from {db_path}: {e}")

    def save_signatures(self, db_path):
        """
        Save the current signatures to a JSON file.

        Args:
            db_path (str): Path to save the signature database
        """
        try:
            with open(db_path, 'w') as f:
                json.dump(self.signatures, f, indent=2)
                logger.info(f"Saved {len(self.signatures)} signatures to {db_path}")
        except Exception as e:
            logger.error(f"Error saving signatures to {db_path}: {e}")

    def add_signature(self, file_hash, virus_name):
        """
        Add a new signature to the database.

        Args:
            file_hash (str): Hash of the virus file
            virus_name (str): Name of the virus
        """
        self.signatures[file_hash] = virus_name
        logger.debug(f"Added signature for {virus_name}: {file_hash}")

    def check_file(self, file_path, hash_types=None):
        """
        Check if a file matches any known virus signatures.

        Args:
            file_path (str): Path to the file to check
            hash_types (list, optional): List of hash types to check

        Returns:
            tuple: (is_infected, virus_name)
        """
        if hash_types is None:
            hash_types = ['md5', 'sha1']

        # Special case for EICAR test file
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read().strip()
                if "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
                    logger.warning(f"Found EICAR test file: {file_path}")
                    return True, "EICAR-Test-File"
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")

        # Regular signature check
        for hash_type in hash_types:
            file_hash = calculate_file_hash(file_path, hash_type)
            if not file_hash:
                continue

            if file_hash in self.signatures:
                virus_name = self.signatures[file_hash]
                logger.warning(f"Found virus signature match in {file_path}: {virus_name}")
                return True, virus_name

        return False, None

    def get_signature_count(self):
        """Get the number of signatures in the database."""
        return len(self.signatures)
