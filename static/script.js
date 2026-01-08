// DOM Elements
const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const fileName = document.getElementById('file-name');
const rowCount = document.getElementById('row-count');
const columnsContainer = document.getElementById('columns-container');
const secretKeyInput = document.getElementById('secret-key');
const toggleKeyBtn = document.getElementById('toggle-key');
const anonymizeBtn = document.getElementById('anonymize-btn');
const downloadBtn = document.getElementById('download-btn');
const resetBtn = document.getElementById('reset-btn');
const selectAllBtn = document.getElementById('select-all');
const deselectAllBtn = document.getElementById('deselect-all');
const summary = document.getElementById('summary');
const successMessage = document.getElementById('success-message');
const loadingOverlay = document.getElementById('loading-overlay');
const loadingText = document.getElementById('loading-text');

// Step sections
const stepUpload = document.getElementById('step-upload');
const stepColumns = document.getElementById('step-columns');
const stepKey = document.getElementById('step-key');
const stepAnonymize = document.getElementById('step-anonymize');
const stepDownload = document.getElementById('step-download');

// State
let currentFileId = null;
let uploadedColumns = [];
let selectedColumns = [];

// Helper Functions
function showLoading(text = 'Processing...') {
    loadingText.textContent = text;
    loadingOverlay.classList.remove('hidden');
}

function hideLoading() {
    loadingOverlay.classList.add('hidden');
}

function showStep(step) {
    [stepUpload, stepColumns, stepKey, stepAnonymize, stepDownload].forEach(s => {
        s.classList.add('hidden');
        s.classList.remove('active');
    });
    step.classList.remove('hidden');
    step.classList.add('active');
}

function showMultipleSteps(...steps) {
    [stepUpload, stepColumns, stepKey, stepAnonymize, stepDownload].forEach(s => {
        s.classList.add('hidden');
        s.classList.remove('active');
    });
    steps.forEach(step => {
        step.classList.remove('hidden');
        step.classList.add('active');
    });
}

// Upload Zone Events
uploadZone.addEventListener('click', () => fileInput.click());

uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('dragover');
});

uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('dragover');
});

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileUpload(files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileUpload(e.target.files[0]);
    }
});

// File Upload Handler
async function handleFileUpload(file) {
    if (!file.name.toLowerCase().endsWith('.csv')) {
        alert('Please upload a CSV file.');
        return;
    }

    showLoading('Uploading file...');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Upload failed');
        }

        currentFileId = data.file_id;
        uploadedColumns = data.columns;

        // Update UI
        fileName.textContent = file.name;
        rowCount.textContent = `${data.row_count} rows`;
        fileInfo.classList.remove('hidden');

        // Generate column checkboxes
        generateColumnCheckboxes(data.columns);

        // Show next steps
        showMultipleSteps(stepUpload, stepColumns, stepKey, stepAnonymize);

    } catch (error) {
        alert('Error: ' + error.message);
    } finally {
        hideLoading();
    }
}

// Generate Column Checkboxes
function generateColumnCheckboxes(columns) {
    columnsContainer.innerHTML = '';
    
    columns.forEach((col, index) => {
        const div = document.createElement('div');
        div.className = 'column-checkbox';
        div.innerHTML = `
            <input type="checkbox" id="col-${index}" value="${col}">
            <label for="col-${index}" title="${col}">${col}</label>
        `;

        const checkbox = div.querySelector('input');
        checkbox.addEventListener('change', () => {
            div.classList.toggle('selected', checkbox.checked);
            updateSelectedColumns();
        });

        div.addEventListener('click', (e) => {
            if (e.target !== checkbox) {
                checkbox.checked = !checkbox.checked;
                div.classList.toggle('selected', checkbox.checked);
                updateSelectedColumns();
            }
        });

        columnsContainer.appendChild(div);
    });
}

// Update Selected Columns
function updateSelectedColumns() {
    const checkboxes = columnsContainer.querySelectorAll('input[type="checkbox"]:checked');
    selectedColumns = Array.from(checkboxes).map(cb => cb.value);
    updateSummary();
}

// Update Summary
function updateSummary() {
    summary.innerHTML = `
        <div class="summary-item">
            <span class="summary-label">Columns to anonymize</span>
            <span class="summary-value">${selectedColumns.length} of ${uploadedColumns.length}</span>
        </div>
        ${selectedColumns.length > 0 ? `
            <div class="summary-columns">
                ${selectedColumns.map(col => `<span class="summary-column-tag">${col}</span>`).join('')}
            </div>
        ` : ''}
    `;
}

// Select/Deselect All
selectAllBtn.addEventListener('click', () => {
    const checkboxes = columnsContainer.querySelectorAll('input[type="checkbox"]');
    const divs = columnsContainer.querySelectorAll('.column-checkbox');
    checkboxes.forEach((cb, i) => {
        cb.checked = true;
        divs[i].classList.add('selected');
    });
    updateSelectedColumns();
});

deselectAllBtn.addEventListener('click', () => {
    const checkboxes = columnsContainer.querySelectorAll('input[type="checkbox"]');
    const divs = columnsContainer.querySelectorAll('.column-checkbox');
    checkboxes.forEach((cb, i) => {
        cb.checked = false;
        divs[i].classList.remove('selected');
    });
    updateSelectedColumns();
});

// Toggle Password Visibility
toggleKeyBtn.addEventListener('click', () => {
    const type = secretKeyInput.type === 'password' ? 'text' : 'password';
    secretKeyInput.type = type;
});

// Anonymize Button
anonymizeBtn.addEventListener('click', async () => {
    if (selectedColumns.length === 0) {
        alert('Please select at least one column to anonymize.');
        return;
    }

    if (!secretKeyInput.value.trim()) {
        alert('Please enter a secret key.');
        secretKeyInput.focus();
        return;
    }

    showLoading('Anonymizing data...');

    try {
        const response = await fetch('/anonymize', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                file_id: currentFileId,
                columns: selectedColumns,
                secret_key: secretKeyInput.value
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Anonymization failed');
        }

        // Show success
        successMessage.textContent = `${data.anonymized_columns.length} column(s) have been successfully anonymized.`;
        showStep(stepDownload);

    } catch (error) {
        alert('Error: ' + error.message);
    } finally {
        hideLoading();
    }
});

// Download Button
downloadBtn.addEventListener('click', () => {
    if (currentFileId) {
        window.location.href = `/download/${currentFileId}`;
    }
});

// Reset Button
resetBtn.addEventListener('click', async () => {
    // Cleanup on server
    if (currentFileId) {
        try {
            await fetch(`/cleanup/${currentFileId}`, { method: 'POST' });
        } catch (e) {
            // Ignore cleanup errors
        }
    }

    // Reset state
    currentFileId = null;
    uploadedColumns = [];
    selectedColumns = [];
    fileInput.value = '';
    secretKeyInput.value = '';
    fileInfo.classList.add('hidden');
    columnsContainer.innerHTML = '';
    summary.innerHTML = '';

    // Show upload step
    showStep(stepUpload);
});

// Initialize
updateSummary();
