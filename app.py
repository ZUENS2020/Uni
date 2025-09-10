import hashlib
from flask import Flask, request, jsonify, render_template

# Import all our analysis modules
from analysis.common import calculate_entropy, extract_strings, find_flags, get_hex_preview
from analysis.general import analyze_file_type, check_eof_data
from analysis.zip import analyze_zip
from analysis.image import analyze_image

app = Flask(__name__)

# Set a file size limit (e.g., 50MB) to prevent server overload
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ctf_analyze', methods=['POST'])
def ctf_analyze_endpoint():
    # Basic request validation
    if 'file' not in request.files:
        return jsonify({"errors": ["No file part in the request."]}), 400

    uploaded_file = request.files['file']

    if uploaded_file.filename == '':
        return jsonify({"errors": ["No file selected for uploading."]}), 400

    filename = uploaded_file.filename
    file_bytes = uploaded_file.read()
    filesize = len(file_bytes)

    # Initialize the response structure
    response = {
        "filename": filename,
        "filesize": filesize,
        "file_digest": {},
        "hex_ascii_preview": {},
        "overall_entropy": 0.0,
        "file_type_analysis": {},
        "findings": [],
        "extracted_strings": [],
        "metadata": {},
        "errors": [],
        "warnings": [],
    }

    if not file_bytes:
        response["errors"].append("Uploaded file is empty.")
        return jsonify(response)

    # --- Start Analysis ---

    # 1. File Digests
    response["file_digest"]["md5"] = hashlib.md5(file_bytes).hexdigest()
    response["file_digest"]["sha256"] = hashlib.sha256(file_bytes).hexdigest()

    # 2. Previews and Entropy
    response["hex_ascii_preview"] = get_hex_preview(file_bytes)
    response["overall_entropy"] = calculate_entropy(file_bytes)

    # 3. String and Flag Extraction
    extracted_strings = extract_strings(file_bytes)
    if extracted_strings:
        response["extracted_strings"] = [{"offset": file_bytes.find(s.encode()), "string": s} for s in extracted_strings]

    potential_flags = find_flags(file_bytes)
    if potential_flags:
        for flag in potential_flags:
            response["findings"].append({
                "type": "POTENTIAL_FLAG",
                "severity": "CRITICAL",
                "description": "A string matching a common flag format was found.",
                "value": flag
            })

    # 4. General File Type Analysis (Magic Bytes, EOF)
    try:
        file_type_analysis, general_findings = analyze_file_type(file_bytes, filename)
        response["file_type_analysis"] = file_type_analysis
        response["findings"].extend(general_findings)

        magic_type = file_type_analysis.get("magic_bytes_type", "unknown")

        eof_findings = check_eof_data(file_bytes, magic_type)
        response["findings"].extend(eof_findings)

        # 5. Specialized Analysis based on file type
        # ZIP analysis
        if magic_type == 'application/zip' or file_type_analysis.get("extension_type", "").startswith('application/vnd.openxmlformats'):
            zip_findings = analyze_zip(file_bytes)
            response["findings"].extend(zip_findings)

        # Image analysis
        if magic_type.startswith('image/'):
            image_findings, image_metadata = analyze_image(file_bytes)
            response["findings"].extend(image_findings)
            if image_metadata:
                response["metadata"].update(image_metadata)

    except Exception as e:
        response["errors"].append(f"A critical error occurred during analysis: {e}")

    return jsonify(response)

if __name__ == '__main__':
    # Note: For production, use a proper WSGI server like Gunicorn or uWSGI
    app.run(host='0.0.0.0', port=5000, debug=True)
