print("Scanner started")
#!/usr/bin/env python3
"""
ML Security Scanner
Scans Python ML/AI projects for security vulnerabilities specific to machine learning.
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class SecurityFinding:
    """Represents a security vulnerability found in code"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    cwe_id: str = ""

class MLSecurityScanner:
    """Main scanner class for detecting ML-specific security issues"""
    
    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[94m",    # Blue
        "LOW": "\033[92m",       # Green
        "RESET": "\033[0m"
    }
    
    def __init__(self, target_path: str, verbose: bool = False):
        self.target_path = Path(target_path)
        self.verbose = verbose
        self.findings: List[SecurityFinding] = []
        
    def scan(self) -> List[SecurityFinding]:
        """Run all security checks"""
        print(f"🔍 Scanning: {self.target_path}")
        print("=" * 60)
        
        if self.target_path.is_file():
            self._scan_file(self.target_path)
        else:
            for py_file in self.target_path.rglob("*.py"):
                if "venv" not in str(py_file) and ".venv" not in str(py_file):
                    self._scan_file(py_file)
        
        self._print_summary()
        return self.findings
    
    def _scan_file(self, file_path: Path):
        """Scan a single Python file"""
        if self.verbose:
            print(f"📄 Scanning: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Run all checks
            self._check_pickle_usage(file_path, lines)
            self._check_hardcoded_credentials(file_path, lines)
            self._check_unsafe_deserialization(file_path, lines)
            self._check_model_input_validation(file_path, lines)
            self._check_unsafe_eval(file_path, lines)
            self._check_path_traversal(file_path, lines)
            self._check_model_integrity(file_path, lines)
            self._check_data_poisoning_risks(file_path, lines)
            
        except Exception as e:
            print(f"⚠️  Error scanning {file_path}: {e}")
    
    def _check_pickle_usage(self, file_path: Path, lines: List[str]):
        """Detect unsafe pickle usage (CWE-502: Deserialization of Untrusted Data)"""
        dangerous_patterns = [
            (r'pickle\.load\(', 'pickle.load()'),
            (r'pickle\.loads\(', 'pickle.loads()'),
            (r'torch\.load\([^,]+\)', 'torch.load() without weights_only=True'),
            (r'joblib\.load\(', 'joblib.load()'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line):
                    # Check if torch.load has weights_only=True
                    if 'torch.load' in line and 'weights_only=True' in line:
                        continue
                    
                    self.findings.append(SecurityFinding(
                        severity="CRITICAL",
                        category="Insecure Deserialization",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        description=f"Unsafe deserialization detected: {desc}. Attackers can execute arbitrary code by crafting malicious serialized objects.",
                        recommendation="Use safer alternatives: torch.load(path, weights_only=True), validate file sources, or use JSON/protobuf for data serialization.",
                        cwe_id="CWE-502"
                    ))
    
    def _check_hardcoded_credentials(self, file_path: Path, lines: List[str]):
        """Detect hardcoded API keys, tokens, passwords (CWE-798)"""
        patterns = [
            (r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']', 'API key'),
            (r'secret[_-]?key\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']', 'Secret key'),
            (r'password\s*=\s*["\'].+["\']', 'Password'),
            (r'token\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']', 'Token'),
            (r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\'][A-Z0-9]{20}["\']', 'AWS Access Key'),
            (r'OPENAI_API_KEY\s*=\s*["\']sk-[a-zA-Z0-9]{48}["\']', 'OpenAI API Key'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and common false positives
            if line.strip().startswith('#') or 'os.environ' in line or 'getenv' in line:
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.findings.append(SecurityFinding(
                        severity="CRITICAL",
                        category="Hardcoded Credentials",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip()[:100] + "...",
                        description=f"Hardcoded {desc} detected. Credentials in source code can be exposed via version control.",
                        recommendation="Use environment variables (os.getenv()), secrets management (AWS Secrets Manager, Azure Key Vault), or .env files with proper .gitignore.",
                        cwe_id="CWE-798"
                    ))
    
    def _check_unsafe_deserialization(self, file_path: Path, lines: List[str]):
        """Check for unsafe YAML/JSON loading (CWE-502)"""
        patterns = [
            (r'yaml\.load\([^,)]+\)', 'yaml.load() without safe loader'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    if 'Loader=yaml.SafeLoader' in line or 'yaml.safe_load' in line:
                        continue
                    
                    self.findings.append(SecurityFinding(
                        severity="HIGH",
                        category="Insecure Deserialization",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        description=f"{desc} can execute arbitrary Python code.",
                        recommendation="Use yaml.safe_load() instead of yaml.load().",
                        cwe_id="CWE-502"
                    ))
    
    def _check_model_input_validation(self, file_path: Path, lines: List[str]):
        """Check for missing input validation before model inference"""
        model_predict_patterns = [
            r'\.predict\(',
            r'\.predict_proba\(',
            r'model\([^)]+\)',
            r'inference\(',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in model_predict_patterns:
                if re.search(pattern, line):
                    # Look back 5 lines for validation
                    validation_found = False
                    search_start = max(0, line_num - 6)
                    search_lines = lines[search_start:line_num]
                    
                    validation_keywords = ['shape', 'dtype', 'assert', 'validate', 'check', 'isinstance', 'len(']
                    if any(kw in '\n'.join(search_lines) for kw in validation_keywords):
                        validation_found = True
                    
                    if not validation_found:
                        self.findings.append(SecurityFinding(
                            severity="MEDIUM",
                            category="Missing Input Validation",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            description="Model inference without input validation. Malformed inputs can cause crashes or adversarial attacks.",
                            recommendation="Validate input shape, dtype, and ranges before passing to model. Implement input sanitization and bounds checking.",
                            cwe_id="CWE-20"
                        ))
                    break
    
    def _check_unsafe_eval(self, file_path: Path, lines: List[str]):
        """Detect use of eval() and exec() (CWE-95)"""
        for line_num, line in enumerate(lines, 1):
            if re.search(r'\beval\(|\\bexec\(', line):
                if line.strip().startswith('#'):
                    continue
                
                self.findings.append(SecurityFinding(
                    severity="CRITICAL",
                    category="Code Injection",
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=line.strip(),
                    description="Use of eval()/exec() allows arbitrary code execution if user input is involved.",
                    recommendation="Avoid eval()/exec() entirely. Use ast.literal_eval() for safe evaluation of literals, or use proper parsing.",
                    cwe_id="CWE-95"
                ))
    
    def _check_path_traversal(self, file_path: Path, lines: List[str]):
        """Check for path traversal vulnerabilities (CWE-22)"""
        patterns = [
            r'open\([^)]*input[^)]*\)',
            r'open\([^)]*request\.[^)]*\)',
            r'Path\([^)]*input[^)]*\)',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.findings.append(SecurityFinding(
                        severity="HIGH",
                        category="Path Traversal",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        description="File operations with user-controlled paths can lead to unauthorized file access (e.g., '../../../etc/passwd').",
                        recommendation="Validate and sanitize file paths. Use Path().resolve() to normalize paths and check they're within allowed directories.",
                        cwe_id="CWE-22"
                    ))
    
    def _check_model_integrity(self, file_path: Path, lines: List[str]):
        """Check for model integrity verification"""
        load_patterns = [r'torch\.load\(', r'tf\.saved_model\.load\(', r'keras\.models\.load_model\(']
        
        for line_num, line in enumerate(lines, 1):
            for pattern in load_patterns:
                if re.search(pattern, line):
                    # Check for hash/signature verification in surrounding lines
                    search_start = max(0, line_num - 10)
                    search_end = min(len(lines), line_num + 5)
                    context = '\n'.join(lines[search_start:search_end])
                    
                    integrity_keywords = ['hash', 'sha256', 'checksum', 'signature', 'verify']
                    if not any(kw in context.lower() for kw in integrity_keywords):
                        self.findings.append(SecurityFinding(
                            severity="MEDIUM",
                            category="Model Integrity",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            description="Loading model without integrity verification. Attackers can replace models with backdoored versions.",
                            recommendation="Verify model checksums (SHA-256) or use signed models. Store hashes separately from model files.",
                            cwe_id="CWE-353"
                        ))
                    break
    
    def _check_data_poisoning_risks(self, file_path: Path, lines: List[str]):
        """Check for data poisoning vulnerabilities in training pipelines"""
        training_patterns = [r'\.fit\(', r'\.train\(', r'DataLoader\(']
        
        for line_num, line in enumerate(lines, 1):
            for pattern in training_patterns:
                if re.search(pattern, line):
                    # Check for data validation in preceding lines
                    search_start = max(0, line_num - 15)
                    context = '\n'.join(lines[search_start:line_num])
                    
                    validation_keywords = ['validate', 'sanitize', 'filter', 'outlier', 'anomaly']
                    if not any(kw in context.lower() for kw in validation_keywords):
                        self.findings.append(SecurityFinding(
                            severity="MEDIUM",
                            category="Data Poisoning Risk",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            description="Training on unvalidated data without outlier/anomaly detection. Poisoned samples can compromise model behavior.",
                            recommendation="Implement data validation: outlier detection, statistical checks, label verification. Monitor training metrics for anomalies.",
                            cwe_id="CWE-1287"
                        ))
                    break
    
    def _print_summary(self):
        """Print scan results summary"""
        if not self.findings:
            print(f"\n{self.SEVERITY_COLORS['LOW']}✅ No security issues found!{self.SEVERITY_COLORS['RESET']}\n")
            return
        
        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        print(f"\n{'='*60}")
        print(f"📊 SECURITY SCAN RESULTS")
        print(f"{'='*60}\n")
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = self.SEVERITY_COLORS[severity]
                print(f"{color}  {severity:10} {count:3} issue(s){self.SEVERITY_COLORS['RESET']}")
        
        print(f"\n{'='*60}\n")
        
        # Print detailed findings
        for i, finding in enumerate(self.findings, 1):
            color = self.SEVERITY_COLORS[finding.severity]
            print(f"{color}[{finding.severity}] {finding.category}{self.SEVERITY_COLORS['RESET']}")
            print(f"📁 File: {finding.file_path}:{finding.line_number}")
            print(f"💡 {finding.description}")
            print(f"🔧 Recommendation: {finding.recommendation}")
            if finding.cwe_id:
                print(f"🔗 {finding.cwe_id}")
            print(f"📝 Code: {finding.code_snippet}")
            print()
    
    def export_json(self, output_file: str):
        """Export findings to JSON"""
        report = {
            "scan_date": datetime.now().isoformat(),
            "target": str(self.target_path),
            "total_findings": len(self.findings),
            "severity_counts": {},
            "findings": [asdict(f) for f in self.findings]
        }
        
        for finding in self.findings:
            report["severity_counts"][finding.severity] = report["severity_counts"].get(finding.severity, 0) + 1
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Report exported to: {output_file}")
    
    def export_sarif(self, output_file: str):
        """Export findings to SARIF format (for GitHub Security tab)"""
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ML Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/cybergitengineer/ml-security-scanner"
                    }
                },
                "results": []
            }]
        }
        
        severity_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        
        for finding in self.findings:
            sarif_report["runs"][0]["results"].append({
                "ruleId": finding.cwe_id or finding.category.replace(" ", "-"),
                "level": severity_map.get(finding.severity, "warning"),
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {"startLine": finding.line_number}
                    }
                }]
            })
        
        with open(output_file, 'w') as f:
            json.dump(sarif_report, f, indent=2)
        
        print(f"📄 SARIF report exported to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="ML Security Scanner - Detect security vulnerabilities in ML/AI Python code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py /path/to/project
  python scanner.py script.py --json report.json
  python scanner.py . --sarif results.sarif --verbose
        """
    )
    parser.add_argument("target", help="Path to Python file or directory to scan")
    parser.add_argument("--json", help="Export findings to JSON file")
    parser.add_argument("--sarif", help="Export findings to SARIF format (for GitHub)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"❌ Error: {args.target} does not exist")
        sys.exit(1)
    
    scanner = MLSecurityScanner(args.target, verbose=args.verbose)
    findings = scanner.scan()
    
    if args.json:
        scanner.export_json(args.json)
    
    if args.sarif:
        scanner.export_sarif(args.sarif)
    
    # Exit with error code if critical/high findings
    critical_count = sum(1 for f in findings if f.severity in ["CRITICAL", "HIGH"])
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()