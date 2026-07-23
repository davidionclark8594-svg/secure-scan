import logging
import re
from pathlib import Path
from fingerprint import create_fingerprint
from confidence import classify_confidence
from cvss import get_cvss
from owasp import get_owasp_category
from rule_registry import load_rules
from remediation import get_remediation
from config import (
    KEYWORDS,
    SEVERITY_MAP,
    ALLOWED_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
    SUSPICIOUS_NAMES,
    SEVERITY_ORDER,
)

def scan_file(input_path: Path):
    """
    Scan an allowed text file for patterns and keywords.

    Returns tuples containing:
    line number, keyword, severity, and matched text.
    """
    if (
        not input_path.exists()
        or not input_path.is_file()
    ):
        return []

    try:
        lines = input_path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()
    except Exception as error:
        logging.warning(
            "Could not read %s: %s",
            input_path,
            error,
        )
        return []

    matches = []

    rules = load_rules()

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        lower_line = line.lower()
        pattern_matched = False

        for rule in rules:
            pattern_name = rule["keyword"]
            pattern = rule["pattern"]

            if re.search(pattern, lower_line):
                severity = rule["severity"]

                matches.append(
                    (
                        line_number,
                        pattern_name,
                        severity,
                        line.strip(),
                    )
                )

                pattern_matched = True
                break

        if pattern_matched:
            continue

        for keyword in KEYWORDS:
            if keyword in lower_line:
                severity = SEVERITY_MAP.get(
                    keyword,
                    "UNKNOWN",
                )

                matches.append(
                    (
                        line_number,
                        keyword,
                        severity,
                        line.strip(),
                    )
                )

                break

    return matches

def detect_filename_matches(
    file_path: Path,
):
    """
    Detect suspicious properties in a filename.

    These checks do not depend on the file contents.
    """
    matches = []
    lower_name = file_path.name.lower()

    for suspicious_word in SUSPICIOUS_NAMES:
        if suspicious_word in lower_name:
            matches.append(
                (
                    0,
                    "suspicious_filename",
                    "MEDIUM",
                    (
                        "Suspicious filename: "
                        f"{file_path.name}"
                    ),
                )
            )
            break

    if (
        file_path.suffix.lower()
        in DANGEROUS_EXTENSIONS
    ):
        matches.append(
            (
                0,
                "dangerous_file_type",
                "HIGH",
                (
                    "Dangerous file detected: "
                    f"{file_path.name}"
                ),
            )
        )

    has_double_extension = (
        "." in file_path.stem
        and not file_path.name.startswith(".")
    )

    if has_double_extension:
        matches.append(
            (
                0,
                "double_extension",
                "HIGH",
                (
                    "Suspicious double extension: "
                    f"{file_path.name}"
                ),
            )
        )

    return matches

def build_finding(
    file_path,
    line_number,
    keyword,
    severity,
    content,
):
    """
    Convert one scanner match into the standard
    finding dictionary used by all report formats.
    """
    return {
        "file": str(file_path),
        "line": line_number,
        "keyword": keyword,
        "severity": severity,
        "confidence": classify_confidence(
            keyword
        ),

        "fingerprint": create_fingerprint(
            file_path,
            keyword,
            line_number,
        ),
        
        "owasp": get_owasp_category(
            keyword
        ),
        "cvss": get_cvss(
            keyword
        ),
        "remediation": get_remediation(
            keyword
        ),
        "content": content,
    }

def write_text_report_header(
    report_path,
    file_path,
):
    with report_path.open(
        "a",
        encoding="utf-8",
    ) as report:
        report.write(
            f"Scan report for: {file_path}\n"
        )

        report.write(
            f"Keywords: {', '.join(KEYWORDS)}\n"
        )

        report.write("-" * 60 + "\n")


def write_text_report(
    report_path,
    matches,
):
    with report_path.open(
        "a",
        encoding="utf-8",
    ) as report:
        if not matches:
            report.write(
                "✅ No matches found.\n\n"
            )
            return

        high_count = sum(
            1
            for _, _, severity, _ in matches
            if severity == "HIGH"
        )

        medium_count = sum(
            1
            for _, _, severity, _ in matches
            if severity == "MEDIUM"
        )

        low_count = sum(
            1
            for _, _, severity, _ in matches
            if severity == "LOW"
        )

        report.write(
            f"Total Matches: {len(matches)}\n"
        )
        report.write(
            f"HIGH: {high_count}\n"
        )
        report.write(
            f"MEDIUM: {medium_count}\n"
        )
        report.write(
            f"LOW: {low_count}\n\n"
        )

        for (
            line_number,
            keyword,
            severity,
            content,
        ) in matches:
            report.write(
                f"Line {line_number} | "
                f"{severity} | "
                f"{keyword} | "
                f"{content}\n"
            )

        report.write("\n")

def scan_folder(
    folder_path,
    report_path,
):
    """
    Scan a folder and return all scan results.

    The returned dictionary contains:
    findings, total matches, file counts,
    and severity counts.
    """
    findings = []

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    total_matches = 0
    files_scanned = 0
    files_skipped = 0

    logging.info(
        "Scanning folder: %s",
        folder_path,
    )

    for file_path in folder_path.rglob("*"):
        if not file_path.is_file():
            files_skipped += 1
            continue

        files_scanned += 1

        matches = detect_filename_matches(
            file_path
        )

        if (
            file_path.suffix.lower()
            in ALLOWED_EXTENSIONS
        ):
            matches.extend(
                scan_file(file_path)
            )

        matches.sort(
            key=lambda match: (
                SEVERITY_ORDER.get(
                    match[2],
                    3,
                )
            )
        )

        total_matches += len(matches)

        write_text_report_header(
            report_path,
            file_path,
        )

        write_text_report(
            report_path,
            matches,
        )

        for (
            line_number,
            keyword,
            severity,
            content,
        ) in matches:
            if severity in severity_counts:
                severity_counts[severity] += 1

            finding = build_finding(
                file_path,
                line_number,
                keyword,
                severity,
                content,
            )

            findings.append(finding)

            if finding["owasp"] == "UNKNOWN":
                print(
                    f"UNKNOWN KEYWORD: {keyword}"
                )

    return {
        "findings": findings,
        "total_matches": total_matches,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "severity_counts": severity_counts,
    }