document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loading = document.getElementById('loading');
    const resultSection = document.getElementById('resultSection');
    const predictionResult = document.getElementById('predictionResult');
    const resultMessage = document.getElementById('resultMessage');
    const safeScoreBar = document.getElementById('safeScoreBar');
    const safeScoreText = document.getElementById('safeScoreText');
    const sslInfo = document.getElementById('sslInfo');
    const statusIcon = document.getElementById('statusIcon');

    analyzeBtn.addEventListener('click', analyzeURL);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeURL();
    });

    async function analyzeURL() {
        const url = urlInput.value.trim();

        if (!url) {
            alert('Please enter a URL');
            return;
        }

        // Reset UI
        loading.classList.remove('hidden');
        resultSection.classList.add('hidden');
        analyzeBtn.disabled = true;

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Analysis failed');
            }

            displayResult(data);
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            loading.classList.add('hidden');
            analyzeBtn.disabled = false;
        }
    }

    function displayResult(data) {
        resultSection.classList.remove('hidden');

        const isSafe = data.is_safe;
        const score = Math.round(data.safe_score * 100);

        predictionResult.textContent = isSafe ? 'Verified Safe' : 'Phishing Detected';
        resultMessage.textContent = data.message;
        sslInfo.textContent = data.ssl_info;

        // Update Score Bar
        safeScoreBar.style.width = score + '%';
        safeScoreText.textContent = score + '%';

        // Update Colors and Icons based on Safety
        if (isSafe) {
            statusIcon.innerHTML = '<i class="fas fa-check-shield"></i>';
            statusIcon.className = 'status-icon status-safe';
            predictionResult.style.color = 'var(--success-color)';
            safeScoreBar.style.background = 'var(--success-color)';
        } else {
            statusIcon.innerHTML = '<i class="fas fa-triangle-exclamation"></i>';
            statusIcon.className = 'status-icon status-unsafe';
            predictionResult.style.color = 'var(--error-color)';
            safeScoreBar.style.background = 'var(--error-color)';
        }

        // Smooth scroll to result
        resultSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
});
