<<<<<<< HEAD
# scan
=======
# Python Antivirus Scanner

A command-line antivirus scanning tool written in Python that can scan files and directories for potential threats.

## Features

- **File and Directory Scanning**: Scan individual files or entire directories recursively
- **Signature-based Detection**: Detect known viruses using a signature database
- **Heuristic Analysis**: Identify potentially malicious files based on suspicious patterns
- **Detailed Reports**: Generate comprehensive scan reports in text or JSON format
- **Customizable**: Configure scan sensitivity, file size limits, and more

## Installation

No installation is required. Simply clone the repository and run the script:

```bash
git clone https://github.com/yourusername/python-antivirus-scanner.git
cd python-antivirus-scanner
```

## Requirements

- Python 3.6 or higher

## Usage

Basic usage:

```bash
python antivirus.py /path/to/scan
```

### Command-line Options

```
usage: antivirus.py [-h] [-r] [-o OUTPUT] [-f {text,json}] [-s SIGNATURES]
                   [--heuristic-level {1,2,3,4,5,6,7,8,9,10}]
                   [--max-file-size MAX_FILE_SIZE]
                   [--skip-extensions SKIP_EXTENSIONS] [-v] [-q]
                   path

Python Antivirus Scanner - Scan files and directories for viruses

positional arguments:
  path                  File or directory to scan

optional arguments:
  -h, --help            show this help message and exit
  -r, --recursive       Scan directories recursively (default: False)
  -o OUTPUT, --output OUTPUT
                        Output file for the scan report (default: None)
  -f {text,json}, --format {text,json}
                        Format of the scan report (default: text)
  -s SIGNATURES, --signatures SIGNATURES
                        Path to custom signature database (default: None)
  --heuristic-level {1,2,3,4,5,6,7,8,9,10}
                        Heuristic detection sensitivity (1-10) (default: 5)
  --max-file-size MAX_FILE_SIZE
                        Maximum file size to scan in MB (default: 100)
  --skip-extensions SKIP_EXTENSIONS
                        Comma-separated list of additional file extensions to
                        skip (default: None)
  -v, --verbose         Enable verbose output (default: False)
  -q, --quiet           Suppress all output except errors (default: False)
```

### Examples

Scan a directory recursively:
```bash
python antivirus.py /path/to/directory -r
```

Scan a file and save the report:
```bash
python antivirus.py /path/to/file.exe -o report.txt
```

Scan with high heuristic sensitivity:
```bash
python antivirus.py /path/to/scan --heuristic-level 8
```

Save report in JSON format:
```bash
python antivirus.py /path/to/scan -o report.json -f json
```

## Exit Codes

The scanner returns the following exit codes:

- `0`: No issues found
- `1`: Error occurred during scan
- `2`: Infected files found
- `3`: Suspicious files found
- `4`: Errors occurred during scan
- `5`: Scan interrupted by user

## Custom Virus Signatures

You can create a custom signature database in JSON format:

```json
{
  "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
  "e1112134b6dcc8bed54e0e34d8ac272795e73d74": "Trojan.Generic.123456"
}
```

Then use it with the `-s` option:

```bash
python antivirus.py /path/to/scan -s custom_signatures.json
```

## Limitations

- This is a basic antivirus scanner for educational purposes
- The default signature database contains only sample signatures
- No real-time protection or advanced heuristics
- Limited to static file analysis

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational purposes only. It is not intended to be a replacement for commercial antivirus software. The authors are not responsible for any damage caused by the use or misuse of this tool.
>>>>>>> d5d8029 (test)
