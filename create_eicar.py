#!/usr/bin/env python3
"""
Create an EICAR test file for testing the antivirus scanner.
"""
import os

# EICAR test file content
# This is a standard test file recognized by all antivirus software
# It's not actually harmful, but it's designed to be detected as a virus
EICAR_CONTENT = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

def create_eicar_file(output_path='eicar.txt'):
    """Create an EICAR test file."""
    try:
        with open(output_path, 'w') as f:
            f.write(EICAR_CONTENT)
        print(f"EICAR test file created at: {output_path}")
        print("This file is harmless but will be detected as a virus by the scanner.")
    except Exception as e:
        print(f"Error creating EICAR test file: {e}")

if __name__ == "__main__":
    create_eicar_file()
