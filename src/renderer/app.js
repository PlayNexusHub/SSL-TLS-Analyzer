// PlayNexus SSL/TLS Analyzer - Renderer Process
// Owner: Nortaq | Contact: playnexushq@gmail.com

class SSLAnalyzer {
    constructor() {
        this.currentResults = null;
        this.settings = {
            theme: 'dark',
            timeout: 10000,
            includeChain: true,
            checkVulnerabilities: true,
            saveHistory: true
        };
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.setupTabs();
        await this.loadSettings();
        this.applyTheme();
        
        // Handle menu events
        window.electronAPI.onMenuAction((action) => {
            this.handleMenuAction(action);
        });
    }

    setupEventListeners() {
        // Analysis form
        const analyzeBtn = document.getElementById('analyzeBtn');
        const hostnameInput = document.getElementById('hostname');
        const portInput = document.getElementById('port');
        
        analyzeBtn.addEventListener('click', () => this.analyzeSSL());
        
        // Enter key support
        [hostnameInput, portInput].forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.analyzeSSL();
            });
        });

        // Quick targets
        document.querySelectorAll('.quick-target').forEach(target => {
            target.addEventListener('click', (e) => {
                const hostname = e.target.dataset.hostname;
                const port = e.target.dataset.port || '443';
                document.getElementById('hostname').value = hostname;
                document.getElementById('port').value = port;
            });
        });

        // Export buttons
        document.getElementById('exportJson').addEventListener('click', () => this.exportResults('json'));
        document.getElementById('exportCsv').addEventListener('click', () => this.exportResults('csv'));
        document.getElementById('exportPdf').addEventListener('click', () => this.exportResults('pdf'));

        // Modal controls
        this.setupModalControls();
    }

    setupTabs() {
        const tabs = document.querySelectorAll('.analysis-tab');
        const panes = document.querySelectorAll('.tab-pane');

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetPane = tab.dataset.tab;
                
                // Update active tab
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                // Update active pane
                panes.forEach(p => p.classList.remove('active'));
                document.getElementById(targetPane).classList.add('active');
            });
        });
    }

    setupModalControls() {
        // Settings modal
        document.getElementById('settingsBtn').addEventListener('click', () => {
            this.showModal('settingsModal');
        });
        
        document.getElementById('saveSettings').addEventListener('click', () => {
            this.saveSettings();
        });

        // Help modal
        document.getElementById('helpBtn').addEventListener('click', () => {
            this.showModal('helpModal');
        });

        // Raw certificate modal
        document.getElementById('viewRawCert').addEventListener('click', () => {
            this.showRawCertificate();
        });

        // Close modals
        document.querySelectorAll('.modal-close, .btn-secondary').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const modal = e.target.closest('.modal');
                if (modal) this.hideModal(modal.id);
            });
        });

        // Click outside to close
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.hideModal(modal.id);
            });
        });
    }

    async analyzeSSL() {
        const hostname = document.getElementById('hostname').value.trim();
        const port = parseInt(document.getElementById('port').value) || 443;
        
        if (!hostname) {
            this.showError('Please enter a hostname');
            return;
        }

        if (!this.isValidHostname(hostname)) {
            this.showError('Please enter a valid hostname or IP address');
            return;
        }

        if (port < 1 || port > 65535) {
            this.showError('Please enter a valid port number (1-65535)');
            return;
        }

        this.showLoading();
        
        try {
            const results = await window.electronAPI.analyzeSSL({
                hostname,
                port,
                includeChain: this.settings.includeChain,
                checkVulnerabilities: this.settings.checkVulnerabilities,
                timeout: this.settings.timeout
            });
            
            this.currentResults = results;
            this.displayResults(results);
            
            if (this.settings.saveHistory) {
                await this.saveToHistory(hostname, port, results);
            }
            
        } catch (error) {
            this.showError(`Analysis failed: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }

    displayResults(results) {
        this.hideNoResults();
        this.showResults();
        
        // Update score
        this.updateScore(results.score);
        
        // Update overview
        this.updateOverview(results);
        
        // Update certificate details
        this.updateCertificateDetails(results.certificate);
        
        // Update certificate chain
        this.updateCertificateChain(results.chain);
        
        // Update protocols
        this.updateProtocols(results.protocols);
        
        // Update cipher suites
        this.updateCipherSuites(results.cipherSuites);
        
        // Update vulnerabilities
        this.updateVulnerabilities(results.vulnerabilities);
        
        // Show export section
        document.querySelector('.export-section').style.display = 'flex';
    }

    updateScore(score) {
        const scoreValue = document.querySelector('.score-value');
        const scoreGrade = document.querySelector('.score-grade');
        const scoreFill = document.querySelector('.score-fill');
        const scoreCircle = document.querySelector('.score-circle');
        
        scoreValue.textContent = score.value;
        scoreGrade.textContent = score.grade;
        scoreFill.style.width = `${score.value}%`;
        
        // Update circle gradient
        const percentage = score.value;
        const degrees = (percentage / 100) * 360;
        scoreCircle.style.background = `conic-gradient(var(--primary-color) ${degrees}deg, var(--border-color) ${degrees}deg)`;
        
        // Update color based on score
        let color = 'var(--danger-color)';
        if (score.value >= 80) color = 'var(--success-color)';
        else if (score.value >= 60) color = 'var(--warning-color)';
        
        scoreValue.style.color = color;
        scoreFill.style.background = color;
    }

    updateOverview(results) {
        // Certificate status
        const certStatus = document.getElementById('certStatus');
        const cert = results.certificate;
        
        if (cert.valid) {
            const daysUntilExpiry = Math.ceil((new Date(cert.validTo) - new Date()) / (1000 * 60 * 60 * 24));
            if (daysUntilExpiry > 30) {
                certStatus.textContent = 'Valid';
                certStatus.className = 'cert-status valid';
            } else if (daysUntilExpiry > 0) {
                certStatus.textContent = `Expires in ${daysUntilExpiry} days`;
                certStatus.className = 'cert-status expiring';
            } else {
                certStatus.textContent = 'Expired';
                certStatus.className = 'cert-status expired';
            }
        } else {
            certStatus.textContent = 'Invalid';
            certStatus.className = 'cert-status expired';
        }
        
        // Other overview info
        document.getElementById('issuer').textContent = cert.issuer || 'Unknown';
        document.getElementById('validFrom').textContent = this.formatDate(cert.validFrom);
        document.getElementById('validTo').textContent = this.formatDate(cert.validTo);
        document.getElementById('keySize').textContent = cert.keySize ? `${cert.keySize} bits` : 'Unknown';
        document.getElementById('signatureAlgorithm').textContent = cert.signatureAlgorithm || 'Unknown';
        
        // Summary
        const summary = document.querySelector('.summary-section p');
        summary.textContent = results.summary || 'SSL/TLS analysis completed successfully.';
        
        // Issues
        this.updateIssuesList(results.issues || []);
        
        // Recommendations
        this.updateRecommendationsList(results.recommendations || []);
    }

    updateIssuesList(issues) {
        const issuesList = document.querySelector('.issues-list');
        issuesList.innerHTML = '';
        
        if (issues.length === 0) {
            issuesList.innerHTML = '<div class="issue-item" style="background: rgba(40, 167, 69, 0.1); border-color: var(--success-color); color: var(--success-color);">No security issues detected</div>';
            return;
        }
        
        issues.forEach(issue => {
            const issueItem = document.createElement('div');
            issueItem.className = 'issue-item';
            issueItem.textContent = issue;
            issuesList.appendChild(issueItem);
        });
    }

    updateRecommendationsList(recommendations) {
        const recList = document.querySelector('.recommendations-list');
        recList.innerHTML = '';
        
        if (recommendations.length === 0) {
            recList.innerHTML = '<div class="recommendation-item">No specific recommendations at this time.</div>';
            return;
        }
        
        recommendations.forEach(rec => {
            const recItem = document.createElement('div');
            recItem.className = 'recommendation-item';
            recItem.textContent = rec;
            recList.appendChild(recItem);
        });
    }

    updateCertificateDetails(cert) {
        const certInfo = document.querySelector('.cert-info');
        certInfo.innerHTML = `
            <strong>Subject:</strong> ${cert.subject || 'Unknown'}<br>
            <strong>Issuer:</strong> ${cert.issuer || 'Unknown'}<br>
            <strong>Serial Number:</strong> ${cert.serialNumber || 'Unknown'}<br>
            <strong>Valid From:</strong> ${this.formatDate(cert.validFrom)}<br>
            <strong>Valid To:</strong> ${this.formatDate(cert.validTo)}<br>
            <strong>Key Algorithm:</strong> ${cert.keyAlgorithm || 'Unknown'}<br>
            <strong>Key Size:</strong> ${cert.keySize ? `${cert.keySize} bits` : 'Unknown'}<br>
            <strong>Signature Algorithm:</strong> ${cert.signatureAlgorithm || 'Unknown'}<br>
            <strong>Version:</strong> ${cert.version || 'Unknown'}<br>
            <strong>Fingerprint (SHA-1):</strong> ${cert.fingerprint || 'Unknown'}<br>
            <strong>Fingerprint (SHA-256):</strong> ${cert.fingerprintSha256 || 'Unknown'}
        `;
        
        // Subject Alternative Names
        if (cert.subjectAltNames && cert.subjectAltNames.length > 0) {
            certInfo.innerHTML += `<br><strong>Subject Alternative Names:</strong><br>`;
            cert.subjectAltNames.forEach(san => {
                certInfo.innerHTML += `&nbsp;&nbsp;• ${san}<br>`;
            });
        }
    }

    updateCertificateChain(chain) {
        const validationResult = document.querySelector('.validation-result');
        const chainDisplay = document.querySelector('.chain-display');
        
        if (chain.valid) {
            validationResult.className = 'validation-result valid';
            validationResult.innerHTML = '<span>✓</span> Certificate chain is valid and trusted';
        } else {
            validationResult.className = 'validation-result invalid';
            validationResult.innerHTML = '<span>✗</span> Certificate chain validation failed';
        }
        
        chainDisplay.innerHTML = '';
        
        if (chain.certificates && chain.certificates.length > 0) {
            chain.certificates.forEach((cert, index) => {
                const chainItem = document.createElement('div');
                chainItem.className = 'chain-item';
                chainItem.innerHTML = `
                    <div class="chain-level">${index === 0 ? 'End Entity' : index === chain.certificates.length - 1 ? 'Root CA' : 'Intermediate CA'}</div>
                    <div class="chain-subject">${cert.subject}</div>
                    <div class="chain-issuer">Issued by: ${cert.issuer}</div>
                    <div class="chain-validity">Valid: ${this.formatDate(cert.validFrom)} - ${this.formatDate(cert.validTo)}</div>
                `;
                chainDisplay.appendChild(chainItem);
            });
        } else {
            chainDisplay.innerHTML = '<div class="chain-item">No certificate chain information available</div>';
        }
    }

    updateProtocols(protocols) {
        const protocolsList = document.querySelector('.protocols-list');
        protocolsList.innerHTML = '';
        
        const protocolOrder = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0', 'SSL 2.0'];
        
        protocolOrder.forEach(protocolName => {
            const protocol = protocols.find(p => p.name === protocolName);
            const protocolItem = document.createElement('div');
            protocolItem.className = 'protocol-item';
            
            let statusClass = 'not-supported';
            let statusText = 'Not Supported';
            
            if (protocol) {
                if (protocol.supported) {
                    if (protocolName === 'TLS 1.3' || protocolName === 'TLS 1.2') {
                        statusClass = 'secure';
                        statusText = 'Secure';
                    } else {
                        statusClass = 'insecure';
                        statusText = 'Insecure';
                    }
                }
            }
            
            protocolItem.innerHTML = `
                <div class="protocol-name">${protocolName}</div>
                <div class="protocol-status ${statusClass}">${statusText}</div>
            `;
            
            protocolsList.appendChild(protocolItem);
        });
    }

    updateCipherSuites(cipherSuites) {
        const ciphersList = document.querySelector('.ciphers-list');
        const cipherFilter = document.getElementById('cipherFilter');
        
        // Setup filter
        cipherFilter.addEventListener('change', () => {
            this.filterCipherSuites(cipherSuites, cipherFilter.value);
        });
        
        this.renderCipherSuites(cipherSuites);
    }

    renderCipherSuites(cipherSuites, filter = 'all') {
        const ciphersList = document.querySelector('.ciphers-list');
        ciphersList.innerHTML = '';
        
        let filteredCiphers = cipherSuites;
        if (filter !== 'all') {
            filteredCiphers = cipherSuites.filter(cipher => cipher.strength === filter);
        }
        
        filteredCiphers.forEach(cipher => {
            const cipherItem = document.createElement('div');
            cipherItem.className = 'cipher-item';
            
            let strengthClass = cipher.strength ? cipher.strength.toLowerCase() : 'none';
            
            cipherItem.innerHTML = `
                <div class="cipher-name">${cipher.name}</div>
                <div class="cipher-strength ${strengthClass}">${cipher.strength || 'Unknown'}</div>
                <div class="cipher-bits">${cipher.bits || 'N/A'} bits</div>
                <div class="cipher-protocol">${cipher.protocol || 'Unknown'}</div>
            `;
            
            ciphersList.appendChild(cipherItem);
        });
        
        if (filteredCiphers.length === 0) {
            ciphersList.innerHTML = '<div class="cipher-item"><div>No cipher suites match the selected filter</div></div>';
        }
    }

    filterCipherSuites(cipherSuites, filter) {
        this.renderCipherSuites(cipherSuites, filter);
    }

    updateVulnerabilities(vulnerabilities) {
        const vulnList = document.querySelector('.vulnerabilities-list');
        vulnList.innerHTML = '';
        
        if (vulnerabilities.length === 0) {
            vulnList.innerHTML = `
                <div class="vulnerability-item" style="background: rgba(40, 167, 69, 0.1); border-color: var(--success-color);">
                    <div class="vulnerability-header">
                        <div class="vulnerability-title" style="color: var(--success-color);">No Known Vulnerabilities</div>
                        <div class="vulnerability-severity" style="background: var(--success-color); color: white;">Good</div>
                    </div>
                    <div>No known SSL/TLS vulnerabilities were detected for this configuration.</div>
                </div>
            `;
            return;
        }
        
        vulnerabilities.forEach(vuln => {
            const vulnItem = document.createElement('div');
            vulnItem.className = 'vulnerability-item';
            
            vulnItem.innerHTML = `
                <div class="vulnerability-header">
                    <div class="vulnerability-title">${vuln.name}</div>
                    <div class="vulnerability-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</div>
                </div>
                <div class="vulnerability-description">${vuln.description}</div>
                ${vuln.recommendation ? `<div class="vulnerability-recommendation"><strong>Recommendation:</strong> ${vuln.recommendation}</div>` : ''}
            `;
            
            vulnList.appendChild(vulnItem);
        });
    }

    async exportResults(format) {
        if (!this.currentResults) {
            this.showError('No results to export');
            return;
        }
        
        try {
            const success = await window.electronAPI.exportResults({
                results: this.currentResults,
                format: format
            });
            
            if (success) {
                this.showSuccess(`Results exported successfully as ${format.toUpperCase()}`);
            }
        } catch (error) {
            this.showError(`Export failed: ${error.message}`);
        }
    }

    showRawCertificate() {
        if (!this.currentResults || !this.currentResults.certificate) {
            this.showError('No certificate data available');
            return;
        }
        
        const rawCertData = document.querySelector('.raw-cert-data');
        rawCertData.textContent = this.currentResults.certificate.raw || 'Raw certificate data not available';
        
        this.showModal('rawCertModal');
        
        // Copy button
        document.getElementById('copyCert').addEventListener('click', () => {
            navigator.clipboard.writeText(rawCertData.textContent).then(() => {
                this.showSuccess('Certificate copied to clipboard');
            });
        });
        
        // Download button
        document.getElementById('downloadCert').addEventListener('click', () => {
            this.downloadCertificate();
        });
    }

    async downloadCertificate() {
        if (!this.currentResults || !this.currentResults.certificate) {
            this.showError('No certificate data available');
            return;
        }
        
        try {
            const success = await window.electronAPI.downloadCertificate({
                certificate: this.currentResults.certificate,
                hostname: document.getElementById('hostname').value
            });
            
            if (success) {
                this.showSuccess('Certificate downloaded successfully');
            }
        } catch (error) {
            this.showError(`Download failed: ${error.message}`);
        }
    }

    async loadSettings() {
        try {
            const settings = await window.electronAPI.getSettings();
            this.settings = { ...this.settings, ...settings };
            this.applySettingsToUI();
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    async saveSettings() {
        try {
            // Get values from form
            this.settings.theme = document.getElementById('themeSelect').value;
            this.settings.timeout = parseInt(document.getElementById('timeoutInput').value) || 10000;
            this.settings.includeChain = document.getElementById('includeChainCheck').checked;
            this.settings.checkVulnerabilities = document.getElementById('checkVulnCheck').checked;
            this.settings.saveHistory = document.getElementById('saveHistoryCheck').checked;
            
            await window.electronAPI.saveSettings(this.settings);
            this.applyTheme();
            this.hideModal('settingsModal');
            this.showSuccess('Settings saved successfully');
        } catch (error) {
            this.showError(`Failed to save settings: ${error.message}`);
        }
    }

    applySettingsToUI() {
        document.getElementById('themeSelect').value = this.settings.theme;
        document.getElementById('timeoutInput').value = this.settings.timeout;
        document.getElementById('includeChainCheck').checked = this.settings.includeChain;
        document.getElementById('checkVulnCheck').checked = this.settings.checkVulnerabilities;
        document.getElementById('saveHistoryCheck').checked = this.settings.saveHistory;
    }

    applyTheme() {
        document.body.setAttribute('data-theme', this.settings.theme);
    }

    async saveToHistory(hostname, port, results) {
        try {
            await window.electronAPI.saveToHistory({
                hostname,
                port,
                results,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error('Failed to save to history:', error);
        }
    }

    handleMenuAction(action) {
        switch (action) {
            case 'new-analysis':
                this.clearResults();
                document.getElementById('hostname').focus();
                break;
            case 'export-json':
                this.exportResults('json');
                break;
            case 'export-csv':
                this.exportResults('csv');
                break;
            case 'export-pdf':
                this.exportResults('pdf');
                break;
            case 'settings':
                this.showModal('settingsModal');
                break;
            case 'help':
                this.showModal('helpModal');
                break;
        }
    }

    clearResults() {
        this.currentResults = null;
        this.showNoResults();
        this.hideResults();
        document.getElementById('hostname').value = '';
        document.getElementById('port').value = '443';
        document.querySelector('.export-section').style.display = 'none';
    }

    showLoading() {
        document.querySelector('.loading-state').classList.remove('hidden');
        document.querySelector('.results-section').classList.add('hidden');
        document.getElementById('analyzeBtn').disabled = true;
    }

    hideLoading() {
        document.querySelector('.loading-state').classList.add('hidden');
        document.getElementById('analyzeBtn').disabled = false;
    }

    showResults() {
        document.querySelector('.results-section').classList.remove('hidden');
        document.querySelector('.results-content').classList.remove('hidden');
    }

    hideResults() {
        document.querySelector('.results-section').classList.add('hidden');
    }

    showNoResults() {
        document.querySelector('.no-results').classList.remove('hidden');
        document.querySelector('.results-content').classList.add('hidden');
    }

    hideNoResults() {
        document.querySelector('.no-results').classList.add('hidden');
    }

    showModal(modalId) {
        document.getElementById(modalId).classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    hideModal(modalId) {
        document.getElementById(modalId).classList.add('hidden');
        document.body.style.overflow = 'auto';
    }

    showError(message) {
        // You could implement a toast notification system here
        alert(`Error: ${message}`);
    }

    showSuccess(message) {
        // You could implement a toast notification system here
        alert(`Success: ${message}`);
    }

    isValidHostname(hostname) {
        // Basic hostname/IP validation
        const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        
        return hostnameRegex.test(hostname) || ipRegex.test(hostname);
    }

    formatDate(dateString) {
        if (!dateString) return 'Unknown';
        try {
            return new Date(dateString).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (error) {
            return dateString;
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SSLAnalyzer();
});
