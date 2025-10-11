
const fileInput = document.getElementById('jsonFile');
const fileName = document.getElementById('fileName');
const analyzeBtn = document.getElementById('analyzeBtn');
const outputDiv = document.getElementById('output');
const loadingIndicator = document.getElementById('loadingIndicator');
const labelText = document.getElementById('labelText');

let uploadedFile = null;

// Handle file selection
fileInput.addEventListener('change', function(e) {
    if (e.target.files.length > 0) {
        uploadedFile = e.target.files[0];
        fileName.textContent = `Selected: ${uploadedFile.name}`;
        fileName.style.color = '#059669';
        labelText.textContent = 'File selected - Click to change';
        analyzeBtn.disabled = false;
    } else {
        uploadedFile = null;
        fileName.textContent = '';
        labelText.textContent = 'Click to upload JSON file with network features';
        analyzeBtn.disabled = true;
    }
    outputDiv.classList.remove('show');
});

// Handle analyze button click
analyzeBtn.addEventListener('click', async function() {
    if (!uploadedFile) {
        showError('Please select a JSON file first.');
        return;
    }
    
    // Read and parse the JSON file
    const reader = new FileReader();
    reader.onload = async function(event) {
        try {
            const jsonData = JSON.parse(event.target.result);
            
            // Show loading indicator
            loadingIndicator.style.display = 'block';
            outputDiv.innerHTML = '';
            outputDiv.classList.remove('show');
            analyzeBtn.disabled = true;
            
            // Send to backend
            const response = await fetch('http://127.0.0.1:5000/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(jsonData)
            });
            
            loadingIndicator.style.display = 'none';
            analyzeBtn.disabled = false;
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `Server error: ${response.status}`);
            }
            
            const result = await response.json();
            displayResults(result);
            
        } catch (error) {
            loadingIndicator.style.display = 'none';
            analyzeBtn.disabled = false;
            
            if (error instanceof SyntaxError) {
                showError('Invalid JSON file format. Please check your file.');
            } else {
                showError(error.message);
            }
        }
    };
    
    reader.onerror = function() {
        loadingIndicator.style.display = 'none';
        analyzeBtn.disabled = false;
        showError('Error reading file. Please try again.');
    };
    
    reader.readAsText(uploadedFile);
});

// Display results in a beautiful format
function displayResults(result) {
    let html = '';
    
    // ML Model Results Card
    html += '<div class="result-card">';
    html += '<div class="section-title">';
    html += '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">';
    html += '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />';
    html += '</svg>';
    html += 'ML Model Results';
    html += '</div>';
    
    if (result.ml_pipeline_results) {
        const mlResults = result.ml_pipeline_results;
        const attackProb = (mlResults.model1_prob * 100).toFixed(2);
        
        html += '<div style="margin-bottom: 16px;">';
        html += `<span class="metric">Attack Probability: ${attackProb}%</span>`;
        html += `<span class="metric">Status: ${mlResults.triggered ? '🚨 Attack Detected' : '✅ Normal'}</span>`;
        html += '</div>';
        
        html += '<div class="json-block">' + syntaxHighlightJSON(mlResults) + '</div>';
    }
    html += '</div>';
    
    // Gemini Analyst Report Card
    html += '<div class="result-card">';
    html += '<div class="section-title">';
    html += '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">';
    html += '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />';
    html += '</svg>';
    html += 'Gemini AI Analyst Report';
    html += '</div>';
    
    if (result.gemini_analyst_report) {
        const report = result.gemini_analyst_report.output || JSON.stringify(result.gemini_analyst_report, null, 2);
        html += '<div class="report-block">' + escapeHTML(report) + '</div>';
    }
    html += '</div>';
    
    outputDiv.innerHTML = html;
    outputDiv.classList.add('show');
}

// Show error message
function showError(message) {
    outputDiv.innerHTML = '<div class="error">⚠️ ' + escapeHTML(message) + '</div>';
    outputDiv.classList.add('show');
}

// Syntax highlight JSON
function syntaxHighlightJSON(json) {
    if (!json) return '';
    let jsonStr = typeof json === 'string' ? json : JSON.stringify(json, null, 2);
    jsonStr = escapeHTML(jsonStr);
    
    // Add colors to different JSON elements
    jsonStr = jsonStr.replace(/(&quot;[^&]*&quot;):/g, '<span style="color:#7c3aed;font-weight:600">$1</span>:');
    jsonStr = jsonStr.replace(/: (&quot;[^&]*&quot;)/g, ': <span style="color:#059669">$1</span>');
    jsonStr = jsonStr.replace(/: (true|false)/g, ': <span style="color:#dc2626;font-weight:600">$1</span>');
    jsonStr = jsonStr.replace(/: (null)/g, ': <span style="color:#6b7280;font-style:italic">$1</span>');
    jsonStr = jsonStr.replace(/: (\d+\.?\d*)/g, ': <span style="color:#ea580c;font-weight:600">$1</span>');
    
    return jsonStr;
}

// Escape HTML to prevent XSS
function escapeHTML(str) {
    if (typeof str !== 'string') str = String(str);
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
