# CTF File Analysis API Server

This project is a Python Flask-based API server designed for CTF (Capture The Flag) scenarios. Its core purpose is to automatically receive and analyze uploaded files to quickly identify anomalies, hidden information, steganography, and other potential clues that could lead to a flag.

## Features

*   **File Upload & Preview**: Provides Hex/ASCII previews of file data.
*   **File Type Identification**: Uses magic bytes to identify the true file type and detects mismatches with file extensions.
*   **In-Depth Archive Analysis (ZIP)**:
    *   Detects pseudo-encryption.
    *   Validates CRC checksums to find tampered data.
    *   Extracts global and per-file comments and extra data fields.
*   **Image Analysis**:
    *   Extracts all available metadata (EXIF, etc.).
    *   Performs LSB entropy analysis to detect potential steganography.
*   **Data Analysis**:
    *   Detects data appended after standard End-Of-File (EOF) markers.
    *   Calculates overall file entropy.
    *   Extracts all printable strings.
    *   Automatically finds strings matching common flag formats (e.g., `flag{...}`).

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Install system dependencies:**
    This project uses `python-magic`, which relies on the `libmagic` library. You must install it on your system.

    *   **On Debian/Ubuntu:**
        ```bash
        sudo apt-get update && sudo apt-get install libmagic1
        ```
    *   **On Red Hat/CentOS:**
        ```bash
        sudo yum install file-libs
        ```
    *   **On macOS (using Homebrew):**
        ```bash
        brew install libmagic
        ```

3.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

4.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Running the Server

To run the development server:

```bash
python app.py
```

The server will start on `http://0.0.0.0:5000`.

**Note:** For a production environment, it is highly recommended to use a proper WSGI server like Gunicorn:
```bash
gunicorn --workers 4 --bind 0.0.0.0:5000 app:app
```

## API Usage

Send a `POST` request to the `/ctf_analyze` endpoint with a file.

### Example using `curl`

Here is an example of how to send a file for analysis using `curl`:

```bash
curl -X POST -F "file=@/path/to/your/ctf_file.zip" http://127.0.0.1:5000/ctf_analyze
```

Replace `/path/to/your/ctf_file.zip` with the actual path to the file you want to analyze.

The API will return a detailed JSON response containing all the analysis results.
