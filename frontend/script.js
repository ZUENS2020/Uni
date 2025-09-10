document.addEventListener('DOMContentLoaded', () => {
    // --- Configuration ---
    const API_BASE_URL = 'http://localhost:5000';

    // --- DOM Elements ---
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const loadingIndicator = document.getElementById('loading-indicator');
    const uploadSection = document.getElementById('upload-section');
    const resultsSection = document.getElementById('results-section');
    const errorDisplay = document.getElementById('error-display');

    // --- Event Listeners ---
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFile(e.target.files[0]);
        }
    });

    // Drag and Drop Listeners
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.backgroundColor = 'var(--secondary-color)';
    });
    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.style.backgroundColor = '';
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.backgroundColor = '';
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    // --- Core Functions ---
    const handleFile = (file) => {
        if (!file) {
            displayError("No file selected.");
            return;
        }

        // Show loading state
        loadingIndicator.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        errorDisplay.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', file);

        uploadAndAnalyze(formData);
    };

    const uploadAndAnalyze = async (formData) => {
        try {
            const response = await fetch(`${API_BASE_URL}/ctf_analyze`, {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || `HTTP error! Status: ${response.status}`);
            }

            const data = await response.json();
            renderResults(data);

        } catch (error) {
            displayError(`Analysis failed: ${error.message}`);
        } finally {
            // Hide loading state
            loadingIndicator.classList.add('hidden');
            resultsSection.classList.remove('hidden');
        }
    };

    // --- Rendering Functions ---
    const renderResults = (data) => {
        if (data.errors && data.errors.length > 0) {
            displayError(data.errors.join('<br>'));
        }
        renderSummary(data);
        renderFindings(data.findings || []);
        renderHexPreview(data.hex_ascii_preview || { head: [], tail: [] });
        renderStrings(data.extracted_strings || []);
        renderMetadata(data.metadata || {});
    };

    const escapeHtml = (unsafe) => {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    const renderSummary = (data) => {
        const container = document.getElementById('summary-info');
        container.innerHTML = `
            <p><strong>Filename (文件名):</strong> ${escapeHtml(data.filename)}</p>
            <p><strong>Filesize (大小):</strong> ${data.filesize} bytes</p>
            <p><strong>Entropy (熵):</strong> ${data.overall_entropy.toFixed(4)}</p>
            <p><strong>MD5:</strong> ${data.file_digest.md5}</p>
            <p><strong>SHA256:</strong> ${data.file_digest.sha256}</p>
            <p><strong>Magic Bytes Type (文件类型):</strong> ${escapeHtml(data.file_type_analysis.magic_bytes_type)}</p>
        `;
    };

    const renderFindings = (findings) => {
        const container = document.getElementById('findings-list');
        if (findings.length === 0) {
            container.innerHTML = '<p>No significant findings. | 无关键发现。</p>';
            return;
        }
        container.innerHTML = findings.map(finding => `
            <div class="finding severity-${finding.severity}">
                <strong>${escapeHtml(finding.type)}</strong>
                <p>${escapeHtml(finding.description)}</p>
                ${finding.hint ? `<p><em>Hint: ${escapeHtml(finding.hint)}</em></p>` : ''}
            </div>
        `).join('');
    };

    const renderHexPreview = (preview) => {
        const container = document.getElementById('hex-preview-container');
        let tableHtml = '<table><tr><th>Offset (偏移量)</th><th>Hex (十六进制)</th><th>ASCII</th></tr>';

        preview.head.forEach(row => {
            tableHtml += `
                <tr class="hex-ascii-row">
                    <td class="offset">0x${row.offset.toString(16).padStart(8, '0')}</td>
                    <td>${escapeHtml(row.hex)}</td>
                    <td>${escapeHtml(row.ascii)}</td>
                </tr>
            `;
        });

        if (preview.tail.length > 0 && preview.head.length > 0 && preview.head[0].offset !== preview.tail[0].offset) {
            tableHtml += '<tr><td colspan="3" style="text-align:center;">... (tail) ...</td></tr>';
            preview.tail.forEach(row => {
                tableHtml += `
                    <tr class="hex-ascii-row">
                        <td class="offset">0x${row.offset.toString(16).padStart(8, '0')}</td>
                        <td>${escapeHtml(row.hex)}</td>
                        <td>${escapeHtml(row.ascii)}</td>
                    </tr>
                `;
            });
        }

        tableHtml += '</table>';
        container.innerHTML = tableHtml;
    };

    const renderStrings = (strings) => {
        const container = document.getElementById('strings-container');
        if (strings.length === 0) {
            container.innerHTML = '<p>No printable strings found. | 未发现可打印字符串。</p>';
            return;
        }
        container.innerHTML = strings.map(s =>
            `<div class="string-item ${s.is_flag ? 'is-flag' : ''}">` +
            `<span class="offset">0x${s.offset.toString(16).padStart(8, '0')}:</span> ` +
            `<span>${escapeHtml(s.content)}</span>` +
            `</div>`
        ).join('');
    };

    const renderMetadata = (metadata) => {
        const container = document.getElementById('metadata-container');
        const entries = Object.entries(metadata);
        if (entries.length === 0) {
            container.innerHTML = '<p>No metadata found. | 无元数据。</p>';
            return;
        }

        let html = '';
        for (const [category, values] of entries) {
            html += `<h3>${escapeHtml(category)}</h3>`;
            for (const [key, value] of Object.entries(values)) {
                 html += `<div class="meta-item"><strong>${escapeHtml(key)}:</strong> ${escapeHtml(String(value))}</div>`;
            }
        }
        container.innerHTML = html;
    };

    const displayError = (message) => {
        errorDisplay.innerHTML = message;
        errorDisplay.classList.remove('hidden');
        resultsSection.classList.add('hidden'); // Hide results if an error occurs
    };
});
