import zipfile
import io
import zlib

def analyze_zip(data):
    """
    Performs in-depth analysis of a ZIP file from a byte string.
    """
    findings = []

    try:
        zip_file = zipfile.ZipFile(io.BytesIO(data), 'r')
    except zipfile.BadZipFile:
        findings.append({
            "type": "INVALID_ZIP_FILE",
            "severity": "CRITICAL",
            "description": "The file is not a valid ZIP archive or is corrupted.",
        })
        return findings

    # 1. Check for global archive comment
    if zip_file.comment:
        findings.append({
            "type": "ZIP_COMMENT",
            "severity": "INFO",
            "description": "The ZIP archive contains a global comment.",
            "value": zip_file.comment.decode('utf-8', 'ignore')
        })

    # 2. Check for CRC errors
    try:
        bad_file = zip_file.testzip()
        if bad_file:
            # This indicates a CRC mismatch, which is a strong indicator of tampering.
            file_info = zip_file.getinfo(bad_file)
            findings.append({
                "type": "CRC_ERROR",
                "severity": "CRITICAL",
                "description": f"CRC check failed for file '{bad_file}' inside the archive. The data may be tampered or require a specific tool to extract.",
                "value": {
                    "filename": bad_file,
                    "expected_crc": hex(file_info.CRC)
                }
            })
    except zlib.error as e:
         findings.append({
            "type": "CRC_ERROR",
            "severity": "CRITICAL",
            "description": f"A zlib error occurred during CRC check, often indicating password protection or corruption: {e}",
        })


    # 3. Analyze each file in the archive
    for info in zip_file.infolist():
        # Check for per-file comments
        if info.comment:
            findings.append({
                "type": "ZIP_FILE_COMMENT",
                "severity": "INFO",
                "description": f"The file '{info.filename}' within the ZIP has a comment.",
                "value": {
                    "filename": info.filename,
                    "comment": info.comment.decode('utf-8', 'ignore')
                }
            })

        # Check for extra data fields
        if info.extra:
            findings.append({
                "type": "ZIP_EXTRA_FIELD",
                "severity": "WARNING",
                "description": f"The file '{info.filename}' contains an 'extra data' field, which could be used for steganography.",
                "offset": info.header_offset,
                "value": {
                    "filename": info.filename,
                    "size": len(info.extra),
                    "data_hex": info.extra.hex()
                }
            })

        # Check for pseudo-encryption
        # Bit 0 of flag_bits is the encryption marker.
        is_encrypted = (info.flag_bits & 0x1) == 1
        # Compression method 0 is STORE (no compression)
        is_stored = info.compress_type == zipfile.ZIP_STORED

        # Heuristic from user request: encrypted bit is set, but it's either not compressed
        # or the other encryption-related flags are not set as expected.
        # A simple check is for the encryption bit with STORED compression.
        if is_encrypted and is_stored:
            findings.append({
                "type": "PSEUDO_ENCRYPTION",
                "severity": "HIGH",
                "description": f"The file '{info.filename}' is marked as encrypted but uses no compression (STORED). This is a strong indicator of pseudo-encryption.",
                "hint": "Try unzipping with a tool that ignores the encryption flag, like 7-Zip, or by manually patching the flag bit.",
                "value": {"filename": info.filename}
            })
        elif is_encrypted:
            # General case for encrypted files
            findings.append({
                "type": "ENCRYPTED_FILE",
                "severity": "INFO",
                "description": f"The file '{info.filename}' is encrypted. Check comments, filenames, or other clues for a password.",
                "value": {"filename": info.filename}
            })

    return findings
