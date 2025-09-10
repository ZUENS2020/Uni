from PIL import Image
import io
import math
from collections import Counter

def calculate_lsb_entropy(img):
    """
    Extracts the LSB plane of an image and calculates its Shannon entropy.
    """
    if img.mode not in ('RGB', 'RGBA'):
        # Only analyze modes with distinct color channels for simplicity
        return None, "Unsupported image mode for LSB analysis."

    pixels = list(img.getdata())

    # Extract LSBs from each channel (R, G, B)
    lsb_data = []
    for pixel in pixels:
        for i in range(3): # For R, G, B channels
            lsb_data.append(pixel[i] & 1)

    # Convert list of bits to a byte string for entropy calculation
    # We pack 8 bits into a byte.
    lsb_bytes = bytearray()
    for i in range(0, len(lsb_data), 8):
        byte_chunk = lsb_data[i:i+8]
        byte_val = 0
        for bit in byte_chunk:
            byte_val = (byte_val << 1) | bit
        lsb_bytes.append(byte_val)

    if not lsb_bytes:
        return 0.0, None

    # Calculate entropy of the LSB data
    entropy = 0
    length = len(lsb_bytes)
    counts = Counter(lsb_bytes)

    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy, None

def analyze_image(data):
    """
    Performs in-depth analysis of an image file from a byte string.
    """
    findings = []
    metadata = {}

    try:
        img = Image.open(io.BytesIO(data))
    except Exception as e:
        findings.append({
            "type": "INVALID_IMAGE_FILE",
            "severity": "WARNING",
            "description": f"Could not open file as an image. Error: {e}",
        })
        return findings, metadata

    # 1. Extract Metadata
    if img.info:
        for key, value in img.info.items():
            # Some metadata can be long byte strings, so we decode safely
            if isinstance(value, bytes):
                metadata[key] = value.decode('utf-8', 'ignore')
            else:
                metadata[key] = str(value) # Ensure value is serializable

        findings.append({
            "type": "IMAGE_METADATA",
            "severity": "INFO",
            "description": "Found metadata in the image file.",
            "value": metadata
        })

    # 2. LSB Steganography Detection via Entropy Analysis
    try:
        entropy, error = calculate_lsb_entropy(img)
        if error:
            findings.append({
                "type": "LSB_ANALYSIS_SKIPPED",
                "severity": "INFO",
                "description": f"LSB analysis was skipped: {error}",
            })
        elif entropy is not None:
            # A high entropy for the LSB plane is a strong indicator of steganography
            # A threshold of 7.5 is chosen (max entropy is 8.0 for random bytes)
            if entropy > 7.5:
                findings.append({
                    "type": "LSB_ANOMALY",
                    "severity": "HIGH",
                    "description": f"High entropy ({entropy:.4f}/8.0) detected in the LSB plane of the image. This strongly suggests LSB steganography.",
                    "hint": "Use a steganography tool like zsteg, stegsolve, or an online LSB extractor to retrieve the hidden data.",
                    "value": {"entropy": f"{entropy:.4f}"}
                })
            else:
                 findings.append({
                    "type": "LSB_ANALYSIS",
                    "severity": "INFO",
                    "description": f"LSB plane entropy is {entropy:.4f}/8.0. No obvious signs of random data (steganography).",
                    "value": {"entropy": f"{entropy:.4f}"}
                })
    except Exception as e:
         findings.append({
            "type": "LSB_ANALYSIS_ERROR",
            "severity": "WARNING",
            "description": f"An error occurred during LSB analysis: {e}",
        })

    return findings, metadata
