import magic
import os

# Known End-of-File (EOF) markers for common file types.
# We use the last occurrence of the marker in the file.
EOF_MARKERS = {
    'image/jpeg': b'\xff\xd9',
    'image/png': b'\x49\x45\x4e\x44\xae\x42\x60\x82', # IEND chunk
    'image/gif': b'\x00\x3b',
    # PDF EOF can be complex, %%EOF can appear multiple times.
    # We look for the last one.
    'application/pdf': b'\x25\x25\x45\x4f\x46'
}

def analyze_file_type(data, filename):
    """
    Analyzes the file type using magic bytes and compares with the extension.
    """
    findings = []

    # Get type from magic bytes
    try:
        magic_type = magic.from_buffer(data, mime=True)
    except Exception as e:
        findings.append({
            "type": "MAGIC_ANALYSIS_ERROR",
            "severity": "WARNING",
            "description": f"Could not analyze magic bytes: {e}",
        })
        magic_type = "unknown"

    # Get type from extension
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    # A simple mapping from extension to a potential MIME type
    # This is not exhaustive but covers common CTF cases.
    extension_map = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.zip': 'application/zip',
        '.pdf': 'application/pdf',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xls': 'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.ppt': 'application/vnd.ms-powerpoint',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    }

    extension_type = extension_map.get(ext, "unknown")

    type_mismatch = False
    if magic_type != "unknown" and extension_type != "unknown" and magic_type != extension_type:
        # Special case: docx/xlsx/pptx are zip files.
        if not (extension_type.startswith('application/vnd.openxmlformats') and magic_type == 'application/zip'):
            type_mismatch = True

    if type_mismatch:
        findings.append({
            "type": "MAGIC_BYTES_MISMATCH",
            "severity": "CRITICAL",
            "description": f"File extension type '{extension_type}' (from {ext}) does not match magic bytes type '{magic_type}'. This could be a deception.",
            "value": {"extension": extension_type, "actual": magic_type}
        })

    analysis_result = {
        "magic_bytes_type": magic_type,
        "extension": ext,
        "extension_type": extension_type,
        "type_mismatch": type_mismatch
    }

    return analysis_result, findings

def check_eof_data(data, file_type):
    """
    Checks for additional data appended after the standard EOF marker.
    """
    findings = []
    marker = EOF_MARKERS.get(file_type)

    if marker:
        try:
            # Find the last occurrence of the marker
            eof_offset = data.rindex(marker)
            marker_len = len(marker)

            # PDF files can have a newline after %%EOF
            if file_type == 'application/pdf':
                # Skip trailing newlines/carriage returns
                end_of_data = len(data)
                while end_of_data > eof_offset + marker_len and data[end_of_data-1] in (10, 13):
                    end_of_data -= 1
                appended_data_len = end_of_data - (eof_offset + marker_len)
            else:
                 appended_data_len = len(data) - (eof_offset + marker_len)

            if appended_data_len > 0:
                offset = eof_offset + marker_len
                # Get a preview of the appended data
                appended_data_preview = data[offset:offset+64]

                findings.append({
                    "type": "EOF_DATA",
                    "severity": "HIGH",
                    "description": f"Found {appended_data_len} bytes of extra data after the '{file_type}' EOF marker.",
                    "offset": offset,
                    "value": {
                        "length": appended_data_len,
                        "preview_hex": appended_data_preview.hex()
                    }
                })
        except ValueError:
            # EOF marker not found
            pass

    return findings
