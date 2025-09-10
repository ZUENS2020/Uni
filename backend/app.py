import os
import sys
import hashlib
import re
import string
import magic
import numpy as np
import io
from flask import Flask, request, jsonify

# Add project root to path to allow importing from analysis module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analysis.zip import analyze_zip
from analysis.image import analyze_image

app = Flask(__name__)

# 设置文件上传的大小限制 (e.g., 50MB)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# --- Analysis Helper Functions (Generic) ---

def calculate_hashes(data):
    """计算数据的MD5和SHA256哈希 / Calculate MD5 and SHA256 hashes of the data."""
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    return {"md5": md5_hash, "sha256": sha256_hash}

def get_hex_ascii_preview(data, length=256):
    """生成数据的十六进制和ASCII预览 / Generate hex and ASCII preview of the data."""
    preview = {"head": [], "tail": []}
    head_data = data[:length]
    for i in range(0, len(head_data), 16):
        chunk = head_data[i:i+16]
        hex_view = ' '.join(f'{b:02x}' for b in chunk)
        ascii_view = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        preview["head"].append({"offset": i, "hex": hex_view.ljust(16*3-1), "ascii": ascii_view})

    if len(data) > length:
        tail_data = data[-length:]
        start_offset = len(data) - len(tail_data)
        for i in range(0, len(tail_data), 16):
            chunk = tail_data[i:i+16]
            hex_view = ' '.join(f'{b:02x}' for b in chunk)
            ascii_view = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            preview["tail"].append({"offset": start_offset + i, "hex": hex_view.ljust(16*3-1), "ascii": ascii_view})
    else:
        preview["tail"] = preview["head"]

    return preview

def extract_strings(data):
    """提取可打印字符串并识别Flag格式 / Extract printable strings and identify Flag format."""
    results = []
    printable_chars = bytes(string.printable, 'ascii')
    pattern = b"([%s]{4,})" % re.escape(printable_chars)
    for match in re.finditer(pattern, data):
        try:
            content = match.group(1).decode('ascii', errors='ignore')
            offset = match.start()
            is_flag = bool(re.search(r'(flag|ctf)\{.*?\}', content, re.IGNORECASE))
            results.append({"offset": offset, "content": content, "is_flag": is_flag if is_flag else None})
        except UnicodeDecodeError:
            continue
    return results

def calculate_entropy(data):
    """计算数据的香农熵 / Calculate the Shannon entropy of the data."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0] / len(data)
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy

def analyze_file_type(data, filename):
    """通过Magic Bytes和文件扩展名分析文件类型 / Analyze file type using Magic Bytes and extension."""
    magic_type = magic.from_buffer(data)
    extension = os.path.splitext(filename)[1].lower()
    ext_map = {
        '.txt': 'text', '.png': 'png', '.jpg': 'jpeg', '.jpeg': 'jpeg',
        '.gif': 'gif', '.pdf': 'pdf', '.zip': 'zip',
    }
    mismatch = False
    expected_type_frag = ext_map.get(extension)
    if expected_type_frag:
        if expected_type_frag not in magic_type.lower():
            mismatch = True
    return {"magic_bytes_type": magic_type, "extension": extension, "type_mismatch": mismatch}

# --- API Endpoint ---

@app.route('/ctf_analyze', methods=['POST'])
def ctf_analyze():
    if 'file' not in request.files:
        return jsonify({"errors": ["No file part in the request"]}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"errors": ["No file selected for uploading"]}), 400

    if file:
        filename = file.filename
        file_content = file.read()
        file_size = len(file_content)

        # Initialize response fields
        findings = []
        metadata = {}
        errors = []

        # --- Perform All Analyses ---
        file_digest = calculate_hashes(file_content)
        hex_preview = get_hex_ascii_preview(file_content)
        extracted_strings_list = extract_strings(file_content)
        entropy = calculate_entropy(file_content)
        type_analysis = analyze_file_type(file_content, filename)

        # Populate findings from generic analysis
        if type_analysis["type_mismatch"]:
            findings.append({
                "type": "File Type Mismatch", "severity": "WARNING",
                "description": f"File extension is '{type_analysis['extension']}' but content appears to be '{type_analysis['magic_bytes_type']}'.",
                "hint": "The file extension might be deliberately misleading. Trust the magic bytes."
            })
        if entropy > 7.5:
             findings.append({
                "type": "High Entropy", "severity": "INFO",
                "description": f"File has a high Shannon entropy of {entropy:.4f}. This could indicate encryption, compression, or packed data.",
                "value": entropy
            })

        # --- Dispatch to Specialized Analyzers ---
        magic_type_lower = type_analysis['magic_bytes_type'].lower()
        in_memory_stream = io.BytesIO(file_content)

        if 'zip archive' in magic_type_lower:
            try:
                zip_findings = analyze_zip(in_memory_stream)
                findings.extend(zip_findings)
            except Exception as e:
                errors.append(f"ZIP analysis failed: {e}")

        elif 'image data' in magic_type_lower:
            try:
                image_findings, image_metadata = analyze_image(in_memory_stream)
                findings.extend(image_findings)
                metadata.update(image_metadata)
            except Exception as e:
                errors.append(f"Image analysis failed: {e}")

        # --- Construct Final Response ---
        response_data = {
            "filename": filename,
            "filesize": file_size,
            "file_digest": file_digest,
            "overall_entropy": round(entropy, 4),
            "file_type_analysis": type_analysis,
            "hex_ascii_preview": hex_preview,
            "extracted_strings": extracted_strings_list,
            "findings": findings,
            "metadata": metadata,
            "errors": errors,
            "warnings": []
        }
        return jsonify(response_data)

    return jsonify({"errors": ["An unknown error occurred"]}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
