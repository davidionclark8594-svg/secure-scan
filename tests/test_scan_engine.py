from pathlib import Path

from scan_engine import scan_file


def test_scan_file_detects_known_security_patterns():
    fixture_path = Path(__file__).parent / "fixtures" / "security_test_data.txt"

    matches = scan_file(fixture_path)

    assert matches, "Expected SecureScan to detect findings in the security test fixture."

    detected_keywords = {match[1] for match in matches}

    assert "password_assignment" in detected_keywords
