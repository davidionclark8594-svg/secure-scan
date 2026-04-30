import logging
import json
from pathlib import Path
import re

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

PATTERNS = {
    "password_assignment": r"password\s*[:=]\s*\S+",
    "token_assignment": r"token\s*[:=]\s*\S+",
    "api_key_assignment": r"api[_\s]?key\s*[:=]\s*\S+",
}

ALLOWED_EXTENSIONS = [
    ".log",
    ".txt",
    ".env",
    ".config",
    ".json",
    ".yaml"
]

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
                matches.append((line_no, pattern_name, "HIGH", line.strip()))
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



def main():
    print("🧠 Directory Log Scanner")

    # Base dir = Week1 (because this file is Week1/src/file_scan.py)
    base_dir = Path(__file__).resolve().parents[1]

    folder = input("Enter folder to scan (blank = data): ").strip()
    folder = folder if folder else "data"

    folder_path = (base_dir / folder).resolve()
    report_path = (base_dir / "Reports" / "scan_report.txt").resolve()

    if not folder_path.exists() or not folder_path.is_dir():
        print(f"❌ Not a folder: {folder_path}")
        return

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("", encoding="utf-8")  # clear report

    json_report_path = (base_dir / "Reports" / "scan_report.json").resolve()

    json_findings = []

    total_matches = 0
    
    logging.info(f"Scanning folder: {folder_path}")

    for file_path in folder_path.rglob("*"):
        if not file_path.is_file():
            continue
        
        if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
            continue
        
        matches = scan_file(file_path)
        total_matches += len(matches)

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
                    json_findings.append({
                        "file": str(file_path),
                        "line": line_no,
                        "keyword": kw,
                        "severity": severity,
                        "content": text
            })

                for line_no, kw, severity, text in matches:
                    if severity == "HIGH":
                        color = Colors.RED
                    elif severity == "MEDIUM":
                        color = Colors.YELLOW
                    else:
                        color = Colors.BLUE

                    print(f"{color}Line {line_no} | {severity} | {kw} | {text}{Colors.RESET}")

                    f.write(f"Line {line_no:>3} | {severity:<7} | {kw:<20} | {text}\n")

                f.write("\n")

    output = {
        "total_mathces": total_matches,
        "findings": json_findings
    }

    json_report_path.write_text(
         json.dumps(output, indent=2),
         encoding="utf-8"
    )
    print(f"✅ Folder scan complete. Total matches: {total_matches}")
    print(f"📄 Combined report saved to: {report_path}")
    print(f"🧾 JSON report saved to: {json_report_path}")

if __name__ == "__main__":
    main()

