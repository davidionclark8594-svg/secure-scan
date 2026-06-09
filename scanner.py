import logging
import json
from pathlib import Path
import re
import time
from patterns import PATTERNS
from severity import classify_severity
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)
from confidence import classify_confidence
from owasp import get_owasp_category
from cvss import get_cvss
from remediation import get_remediation
from html_report import write_html_report

class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

KEYWORDS = [
    "password",
    "token",
    "sql",
    "injection",
    "xss",
    "admin",
    "secret",
    "apikey",
    "api key",
]

SEVERITY_MAP = {
    "password": "HIGH",
    "token": "HIGH",
    "apikey": "HIGH",
    "api key": "HIGH",
    "sql": "MEDIUM",
    "injection": "MEDIUM",
    "xss": "MEDIUM",
    "admin": "MEDIUM",
    "secret": "HIGH",
}

ALLOWED_EXTENSIONS = [
    ".log",
    ".txt",
    ".env",
    ".config",
    ".json",
    ".yaml"
]

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".js",
    ".php"
]

SUSPICIOUS_NAMES = [
    "password",
    "bank",
    "login",
    "urgent",
    "payroll",
    "invoice"
]

severity_counts = {
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
}

def main():
    print ("Directory Log Scanner")

def scan_file(input_path: Path):
    """Return a list of matches: (line_no, keyword, severity, line_text)."""
    if not input_path.exists() or not input_path.is_file():
        return []

    try:
        lines = input_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    matches = []
    for line_no, line in enumerate(lines, start=1):
        lower = line.lower()
        pattern_matched = False

        for pattern_name, pattern in PATTERNS.items():
            if re.search(pattern, lower):
                severity = classify_severity(pattern_name)
                matches.append((line_no, pattern_name, severity, line.strip()))
                pattern_matched = True
                break

        if pattern_matched:
            continue

        for kw in KEYWORDS:
            if kw in lower:
                severity = SEVERITY_MAP.get(kw, "UNKNOWN")
                matches.append((line_no, kw, severity, line.strip()))
                break 
                

    return matches

def write_text_report(report_path, matches):
    with open(report_path, "a", encoding="utf-8") as report:
        for line_no, keyword, severity, line_text in matches:
            report.write(
                f"Line {line_no} | {severity} |{keyword} | {line_text}\n"
            )

def main():
    print("🧠 Directory Log Scanner")
    start_time = time.time()

    # Base dir = Week1 (because this file is Week1/src/file_scan.py)
    base_dir = Path(__file__).resolve().parent

    folder = input("Enter folder to scan (blank = data): ").strip()
    folder = folder if folder else "data"

    folder_path = (base_dir / folder).resolve()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = (base_dir / "reports" / f"scan_report_{timestamp}.txt").resolve()

    if not folder_path.exists() or not folder_path.is_dir():
        print(f"❌ Not a folder: {folder_path}")
        return

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("", encoding="utf-8")  # clear report

    json_report_path = (base_dir / "reports" / f"scan_report_{timestamp}.json").resolve()
    
    html_report_path = (base_dir / "reports" / f"scan_report_{timestamp}.html").resolve()

    json_findings = []

    total_matches = 0
    files_scanned = 0
    files_skipped = 0
    
    logging.info(f"Scanning folder: {folder_path}")

    for file_path in folder_path.rglob("*"):
        
        if not file_path.is_file():
            files_skipped += 1
            continue
        files_scanned += 1

        matches = scan_file(file_path)
        total_matches += len(matches)

        for word in SUSPICIOUS_NAMES:
            if word in file_path.name.lower():
                suspicious_match = (
                    0,
                    "suspicious_filename",
                    "MEDIUM",
                    f"Suspicious filename: {file_path.name}"
                )

                matches.append(suspicious_match)
                total_matches += 1

                json_findings.append({
                    "file": str(file_path),
                    "line": 0,
                    "keyword": "suspicious_filename",
                    "severity": "MEDIUM",
                    "confidence": classify_confidence("suspicious_filename"),
                    "owasp": get_owasp_category("suspicious_filename"),
                    "cvss": get_cvss("suspicious_filename"),
                    "remediation": get_remediation("suspicious_filename"),
                    "content": f"Suspicious filename: {file_path.name}"
                })

                print(f"Suspicious filename: {file_path.name}")
                break


        if file_path.suffix.lower() in DANGEROUS_EXTENSIONS:
            dangerous_match = (
                0,
                "dangerous_file_type",
                "HIGH",
                f"Dangerous file detected: {file_path.name}"
            )

            matches.append(dangerous_match)
            total_matches += 1

            print(f"Dangerous file type: {file_path.name}")

        if "." in file_path.stem and not file_path.name.startswith("."):

            print(f" Suspicious double extension: {file_path.name}"
            )
                
            double_ext_match = (
                    0,
                    "double_extension",
                    "HIGH",
                    f"Suspicious file name: {file_path.name}"
                )

            matches.append(double_ext_match)
            
            json_findings.append({
                "file" : str(file_path),
                "line" : 0,
                "keyword": "double_extension",
                "severity": "HIGH",
                "confidence": classify_confidence("double_extension"),
                "cvss": get_cvss("double_extension"),
                "remediation": get_remediation("double_extension"),
                "content": f"Dangerous file detected: {file_path.name}"
            })

            total_matches += 1
            
            print(f" Dangerous file type: {file_path.name}")

        if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
            continue

        with report_path.open("a", encoding="utf-8") as f:
            f.write(f"Scan report for: {file_path}\n")
            
            f.write(f"Keywords: {', '.join(KEYWORDS)}\n")
            f.write("-" * 60 + "\n")

            if not matches:
                f.write("✅ No matches found.\n\n")

            else:
                high_count = sum(1 for _, _, severity, _ in matches if severity == "HIGH")
                medium_count = sum(1 for _, _, severity, _ in matches if severity == "MEDIUM")
                low_count = sum(1 for _, _, severity, _ in matches if severity == "LOW")

                f.write(f"Total Matches: {len(matches)}\n")
                f.write(f"HIGH: {high_count}\n")
                f.write(f"MEDIUM: {medium_count}\n")
                f.write(f"LOW: {low_count}\n\n")

                SEVERITY_ORDER = {
                    "HIGH": 0,
                    "MEDIUM": 1,
                    "LOW": 2,
                    "UNKNOWN": 3
                }
                
                matches.sort(key=lambda x: SEVERITY_ORDER.get(x[2], 3))

                for line_no, kw, severity, text in matches:
                    if severity in severity_counts:
                        severity_counts[severity] +=1
                    
                    json_findings.append({
                        "file": str(file_path),
                        "line": line_no,
                        "keyword": kw,
                        "severity": severity,
                        "confidence": classify_confidence(kw),
                        "owasp": get_owasp_category(kw),
                        "owasp": get_owasp_category("suspicious_filename"),
                        "owasp": get_owasp_category("double_extension"),
                        "cvss": get_cvss(kw),
                        "remediation": get_remediation(kw),
                        "content": text
            })

                write_text_report(report_path, matches)
                    
    output = {
        "total_mathces": total_matches,
        "findings": json_findings
    }

    json_report_path.write_text(
         json.dumps(output, indent=2),
         encoding="utf-8"
    )

    write_html_report(
        html_report_path, 
        json_findings
    )

    print(f"HTML report saved to: {html_report_path}")

    
    print(f"✅ Folder scan complete. Total matches: {total_matches}")
    print(f"📄 Combined report saved to: {report_path}")
    print(f"🧾 JSON report saved to: {json_report_path}")
    scan_duration = round(time.time() - start_time, 2)
    print("n--- Scan Statistics ---")
    print(f"Files scanned: {files_scanned}")
    print(f"Files skipped: {files_skipped}")
    print(f"Scan duration: {scan_duration} seconds")

    print("n--- Severity Summary ---")

    risk_score =(
        severity_counts["HIGH"] * 10 +
        severity_counts["MEDIUM"] * 5 +
        severity_counts["LOW"] * 1
    )

    print(Fore.RED + f"HIGH findings: {severity_counts['HIGH']}")
    print(Fore.YELLOW + f"MEDIUM findings: {severity_counts['MEDIUM']}")
    print(Fore.GREEN + f"LOW findings: {severity_counts['LOW']}")
    print(f"Overall Risk Score: {risk_score}")

    if risk_score >= 150:
        print(Fore.MAGENTA + "Risk Level: CRITICAL")

    elif risk_score >= 75:
        print(Fore.RED + "Risk Level: HIGH")

    elif risk_score >= 25:
        print(Fore.YELLOW + "Risk Level: MEDIUM")

    else:
        print(Fore.GREEN + "Risk Level: LOW")

if __name__ == "__main__":
    main()

