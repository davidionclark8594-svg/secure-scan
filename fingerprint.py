import hashlib


def create_fingerprint(
    file_path,
    keyword,
    line_number,
):
    """
    Create a stable fingerprint for one finding.
    """

    fingerprint_source = (
        f"{file_path}|"
        f"{keyword}|"
        f"{line_number}"
    )

    return hashlib.sha256(
        fingerprint_source.encode("utf-8")
    ).hexdigest()[:16]