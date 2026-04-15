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
    const redFlagsSection = document.getElementById('redFlagsSection');
    const redFlagsList = document.getElementById('redFlagsList');
    const featuresTableBody = document.getElementById('featuresTableBody');
    const featuresSummaryBar = document.getElementById('featuresSummaryBar');

    // Per-feature detailed descriptions keyed by (featureKey, value)
    const FEATURE_DESCRIPTIONS = {
        UsingIP: {
            '1':  'Domain name used (normal)',
            '0':  'Could not determine',
            '-1': 'Raw IP address in URL'
        },
        LongURL: {
            '1':  'Short URL (< 54 chars)',
            '0':  'Medium length (54-75 chars)',
            '-1': 'Very long URL (> 75 chars)'
        },
        ShortURL: {
            '1':  'Not a URL shortener',
            '0':  'Unknown service',
            '-1': 'URL shortener detected (e.g. bit.ly)'
        },
        'Symbol@': {
            '1':  'No @ symbol found',
            '0':  'Unknown',
            '-1': '@ symbol present in URL'
        },
        'Redirecting//': {
            '1':  'No suspicious redirect',
            '0':  'Unknown',
            '-1': 'Double-slash (//) redirect found'
        },
        'PrefixSuffix-': {
            '1':  'No hyphen in domain',
            '0':  'Unknown',
            '-1': 'Hyphen (-) found in domain'
        },
        SubDomains: {
            '1':  'Single sub-domain (normal)',
            '0':  'Two sub-domains (moderate)',
            '-1': 'Multiple sub-domains (suspicious)'
        },
        HTTPS: {
            '1':  'Valid SSL from trusted CA',
            '0':  'Self-signed or untrusted certificate',
            '-1': 'No HTTPS (plain HTTP)',
            '-2': 'Connection failed / site down'
        },
        DomainRegLen: {
            '1':  'Registered ≥ 1 year',
            '0':  'WHOIS data unavailable',
            '-1': 'Registered < 1 year'
        },
        Favicon: {
            '1':  'Favicon from same domain',
            '0':  'No favicon / unknown',
            '-1': 'Favicon loaded from external domain'
        },
        NonStdPort: {
            '1':  'Standard port (80/443)',
            '0':  'Unknown',
            '-1': 'Non-standard port in URL'
        },
        HTTPSDomainURL: {
            '1':  'No "https" token in domain name',
            '0':  'Unknown',
            '-1': '"https" token found in domain name'
        },
        RequestURL: {
            '1':  'Resources loaded from same domain (≥ 61%)',
            '0':  'Mixed sources (22-61%)',
            '-1': 'Mostly external resources (< 22%)'
        },
        AnchorURL: {
            '1':  'Anchors point to same domain (< 31%)',
            '0':  'Mixed anchor destinations (31-67%)',
            '-1': 'Anchors mostly external (> 67%)'
        },
        LinksInScriptTags: {
            '1':  'Scripts/links from same domain (≥ 81%)',
            '0':  'Mixed sources (17-81%)',
            '-1': 'Mostly external scripts (< 17%)'
        },
        ServerFormHandler: {
            '1':  'Form actions point to same domain',
            '0':  'Form actions point externally',
            '-1': 'Blank or about:blank form action'
        },
        InfoEmail: {
            '1':  'No mailto: link found',
            '0':  'Unknown',
            '-1': 'mailto: link detected'
        },
        AbnormalURL: {
            '1':  'Domain matches WHOIS record',
            '0':  'WHOIS data unavailable',
            '-1': 'Domain mismatch with WHOIS'
        },
        WebsiteForwarding: {
            '1':  'No or single redirect (≤ 1)',
            '0':  'Multiple redirects (2-4)',
            '-1': 'Excessive redirects (> 4)'
        },
        StatusBarCust: {
            '1':  'No status bar manipulation',
            '0':  'Unknown',
            '-1': 'onMouseOver status bar change detected'
        },
        DisableRightClick: {
            '1':  'Right-click is enabled',
            '0':  'Unknown',
            '-1': 'Right-click is disabled'
        },
        UsingPopupWindow: {
            '1':  'No suspicious pop-up windows',
            '0':  'Unknown',
            '-1': 'Pop-up / alert() detected'
        },
        IframeRedirection: {
            '1':  'No hidden iframe found',
            '0':  'Unknown',
            '-1': 'Hidden iframe detected'
        },
        AgeofDomain: {
            '1':  'Domain ≥ 6 months old',
            '0':  'Age could not be determined',
            '-1': 'Domain < 6 months old'
        },
        DNSRecording: {
            '1':  'DNS record is valid & aged',
            '0':  'DNS record unavailable',
            '-1': 'No or recent DNS record'
        },
        PageRank: {
            '1':  'High page rank (< 100K)',
            '0':  'Page rank unknown',
            '-1': 'Low page rank (≥ 100K)'
        },
        LinksPointingToPage: {
            '1':  'No inbound links (clean)',
            '0':  '1-2 inbound links',
            '-1': '> 2 inbound links (suspicious)'
        },
        StatsReport: {
            '1':  'Not listed in known bad-URL databases',
            '0':  'Unknown',
            '-1': 'Matched known bad URL/IP pattern'
        }
    };

    // Feature categories grouped by severity tier
    const FEATURE_CATEGORIES = [
        {
            name: 'Critical',
            icon: 'fa-circle-exclamation',
            color: '#ef4444',
            keys: ['UsingIP', 'HTTPS', 'ShortURL', 'StatsReport']
        },
        {
            name: 'High',
            icon: 'fa-triangle-exclamation',
            color: '#f97316',
            keys: ['AgeofDomain', 'DomainRegLen', 'DNSRecording', 'AbnormalURL', 'HTTPSDomainURL', 'NonStdPort', 'SubDomains', 'PrefixSuffix-']
        },
        {
            name: 'Medium',
            icon: 'fa-shield-halved',
            color: '#eab308',
            keys: ['RequestURL', 'AnchorURL', 'ServerFormHandler', 'LinksInScriptTags', 'Favicon', 'WebsiteForwarding', 'IframeRedirection', 'PageRank']
        },
        {
            name: 'Low',
            icon: 'fa-info-circle',
            color: '#6b7280',
            keys: ['LongURL', 'Symbol@', 'Redirecting//', 'InfoEmail', 'StatusBarCust', 'DisableRightClick', 'UsingPopupWindow', 'LinksPointingToPage']
        }
    ];

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
            statusIcon.innerHTML = '<i class="fas fa-shield-check"></i>';
            statusIcon.className = 'status-icon status-safe';
            predictionResult.style.color = 'var(--success-color)';
            safeScoreBar.style.background = 'var(--success-color)';
        } else {
            statusIcon.innerHTML = '<i class="fas fa-triangle-exclamation"></i>';
            statusIcon.className = 'status-icon status-unsafe';
            predictionResult.style.color = 'var(--error-color)';
            safeScoreBar.style.background = 'var(--error-color)';
        }

        // --- Red Flags ---
        if (data.red_flags && data.red_flags.length > 0) {
            redFlagsSection.classList.remove('hidden');
            redFlagsList.innerHTML = '';
            data.red_flags.forEach(flag => {
                const li = document.createElement('li');
                li.innerHTML = `<i class="fas fa-xmark"></i> ${flag}`;
                redFlagsList.appendChild(li);
            });
        } else {
            redFlagsSection.classList.add('hidden');
        }

        // --- Features Table ---
        renderFeaturesTable(data.features_detail, data.severity_breakdown);

        // Smooth scroll to result
        resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function getStatusInfo(value) {
        if (value === 1) return { cls: 'status-safe',       icon: 'fa-circle-check',       label: 'Safe' };
        if (value === 0) return { cls: 'status-suspicious', icon: 'fa-circle-exclamation',  label: 'Suspicious' };
        return               { cls: 'status-phishing',  icon: 'fa-circle-xmark',        label: 'Phishing' };
    }

    function getDescription(key, value) {
        const map = FEATURE_DESCRIPTIONS[key];
        if (map) {
            const desc = map[String(value)];
            if (desc) return desc;
        }
        // Fallback
        if (value === 1) return 'Legitimate';
        if (value === 0) return 'Neutral / Unknown';
        return 'Suspicious indicator';
    }

    function renderFeaturesTable(features, severityBreakdown) {
        if (!features) return;

        featuresTableBody.innerHTML = '';

        let safeCount = 0, suspiciousCount = 0, phishingCount = 0;
        let rowIndex = 0;

        // Iterate by severity category
        FEATURE_CATEGORIES.forEach(cat => {
            // Count flagged features in this category
            let catFlagged = 0;
            let catTotal = 0;
            cat.keys.forEach(key => {
                const feat = features[key];
                if (feat) {
                    catTotal++;
                    if (feat.value <= -1) catFlagged++;
                }
            });

            // Category header row with severity badge
            const headerTr = document.createElement('tr');
            headerTr.className = 'category-header-row';
            headerTr.innerHTML = `
                <td colspan="4">
                    <span class="severity-badge" style="background: ${cat.color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; margin-right: 8px; text-transform: uppercase; letter-spacing: 0.5px;">${cat.name}</span>
                    <i class="fas ${cat.icon}" style="color: ${cat.color}; margin-right: 4px;"></i>
                    ${cat.name} Severity
                    <span style="float: right; font-size: 0.8rem; opacity: 0.7;">${catFlagged}/${catTotal} flagged</span>
                </td>
            `;
            featuresTableBody.appendChild(headerTr);

            cat.keys.forEach(key => {
                const feat = features[key];
                if (!feat) return;

                const val = feat.value;
                const info = getStatusInfo(val);
                const description = getDescription(key, val);

                if (val === 1) safeCount++;
                else if (val === 0) suspiciousCount++;
                else phishingCount++;

                const tr = document.createElement('tr');
                tr.className = `feature-row ${info.cls}`;
                tr.style.animationDelay = `${rowIndex * 30}ms`;
                tr.innerHTML = `
                    <td>
                        <span class="feature-name">${feat.label}</span>
                        <span class="feature-key">${key}</span>
                    </td>
                    <td>
                        <span class="feature-value-badge ${info.cls}">${val}</span>
                    </td>
                    <td class="feature-desc-cell">
                        <span class="feature-description">${description}</span>
                    </td>
                    <td>
                        <span class="feature-status ${info.cls}">
                            <i class="fas ${info.icon}"></i>
                            ${info.label}
                        </span>
                    </td>
                `;
                featuresTableBody.appendChild(tr);
                rowIndex++;
            });
        });

        // Also render any features not covered by categories (safety net)
        const categorizedKeys = new Set(FEATURE_CATEGORIES.flatMap(c => c.keys));
        const uncategorized = Object.entries(features).filter(([k]) => !categorizedKeys.has(k));
        if (uncategorized.length > 0) {
            const headerTr = document.createElement('tr');
            headerTr.className = 'category-header-row';
            headerTr.innerHTML = `
                <td colspan="4">
                    <i class="fas fa-ellipsis"></i> Other
                </td>
            `;
            featuresTableBody.appendChild(headerTr);

            uncategorized.forEach(([key, feat]) => {
                const val = feat.value;
                const info = getStatusInfo(val);
                const description = getDescription(key, val);

                if (val === 1) safeCount++;
                else if (val === 0) suspiciousCount++;
                else phishingCount++;

                const tr = document.createElement('tr');
                tr.className = `feature-row ${info.cls}`;
                tr.style.animationDelay = `${rowIndex * 30}ms`;
                tr.innerHTML = `
                    <td>
                        <span class="feature-name">${feat.label}</span>
                        <span class="feature-key">${key}</span>
                    </td>
                    <td>
                        <span class="feature-value-badge ${info.cls}">${val}</span>
                    </td>
                    <td class="feature-desc-cell">
                        <span class="feature-description">${description}</span>
                    </td>
                    <td>
                        <span class="feature-status ${info.cls}">
                            <i class="fas ${info.icon}"></i>
                            ${info.label}
                        </span>
                    </td>
                `;
                featuresTableBody.appendChild(tr);
                rowIndex++;
            });
        }

        // Summary bar
        const total = safeCount + suspiciousCount + phishingCount;
        if (total > 0) {
            const safePct = (safeCount / total * 100).toFixed(1);
            const suspPct = (suspiciousCount / total * 100).toFixed(1);
            const phishPct = (phishingCount / total * 100).toFixed(1);

            featuresSummaryBar.innerHTML = `
                <div class="summary-counts">
                    <span class="count-safe"><i class="fas fa-circle-check"></i> ${safeCount} Safe</span>
                    <span class="count-suspicious"><i class="fas fa-circle-exclamation"></i> ${suspiciousCount} Suspicious</span>
                    <span class="count-phishing"><i class="fas fa-circle-xmark"></i> ${phishingCount} Phishing</span>
                </div>
                <div class="summary-track">
                    <div class="summary-seg seg-safe" style="width:${safePct}%"></div>
                    <div class="summary-seg seg-suspicious" style="width:${suspPct}%"></div>
                    <div class="summary-seg seg-phishing" style="width:${phishPct}%"></div>
                </div>
            `;
        }
    }
});
