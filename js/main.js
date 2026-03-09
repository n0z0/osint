import { UI } from './modules/ui.js';
import * as API from './modules/api.js';
import { State } from './modules/state.js';

/**
 * main.js - Application Entry Point
 * Wires UI events to logical actions.
 */

document.addEventListener('DOMContentLoaded', () => {

    // Status initialization (Simulated check)
    setTimeout(() => {
        UI.showToast('Secure connection established. All systems nominal.', 'success');
    }, 1000);

    // Subscribe UI to state changes
    State.subscribe((newState) => {
        UI.updateDashboard(newState);
    });

    // --- Binding Events ---
    initIPTool();
    initDomainTool();
    initReconTool();
    initUsernameTool();
    initLeakTool();
    initCVETool();
    initShodanTool();
    initSettings();
});

/**
 * Initialize IP Intelligence Tool
 */
function initIPTool() {
    const btn = document.getElementById('btn-analyze-ip');
    const input = document.getElementById('ip-input');

    if (!btn || !input) return;

    const performAnalysis = async () => {
        const ip = input.value.trim();
        if (!ip) {
            UI.showToast('Please enter an IP address.', 'error');
            return;
        }

        UI.setLoadingState('btn-analyze-ip', true);
        UI.clearContainer('ip-results');

        try {
            const data = await API.getIpIntel(ip);
            UI.renderDataGrid('ip-results', data);
            UI.showToast('IP Intelligence gathered successfully.', 'success');
            State.addQuery(ip, 'IP Lookup', 'Complete');
        } catch (error) {
            UI.showToast(`Analysis failed: ${error.message}`, 'error');
            State.addQuery(ip, 'IP Lookup', 'Failed');
        } finally {
            UI.setLoadingState('btn-analyze-ip', false);
        }
    };

    btn.addEventListener('click', performAnalysis);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performAnalysis();
    });
}

/**
 * Initialize Domain Intelligence Tool
 */
function initDomainTool() {
    const btn = document.getElementById('btn-analyze-domain');
    const input = document.getElementById('domain-input');

    if (!btn || !input) return;

    const performAnalysis = async () => {
        const domain = input.value.trim();
        if (!domain) {
            UI.showToast('Please enter a domain name.', 'error');
            return;
        }

        UI.setLoadingState('btn-analyze-domain', true);
        UI.clearContainer('domain-results');

        try {
            const data = await API.getDomainIntel(domain);
            UI.renderDataGrid('domain-results', data);
            UI.showToast('Domain records resolved.', 'success');
            State.addQuery(domain, 'Domain Intel', 'Complete');
        } catch (error) {
            UI.showToast(`Analysis failed: ${error.message}`, 'error');
            State.addQuery(domain, 'Domain Intel', 'Failed');
        } finally {
            UI.setLoadingState('btn-analyze-domain', false);
        }
    };

    btn.addEventListener('click', performAnalysis);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performAnalysis();
    });
}

/**
 * Initialize Advanced Recon Tool
 */
function initReconTool() {
    const btn = document.getElementById('btn-analyze-recon');
    const input = document.getElementById('recon-input');

    if (!btn || !input) return;

    const performAnalysis = async () => {
        const target = input.value.trim();
        if (!target) {
            UI.showToast('Please enter a target domain or IP.', 'error');
            return;
        }

        UI.setLoadingState('btn-analyze-recon', true);
        const resultsContainer = document.getElementById('recon-results');
        const subdomainOutput = document.getElementById('subdomain-output');
        const portscanOutput = document.getElementById('portscan-output');

        resultsContainer.classList.remove('hidden');
        subdomainOutput.innerHTML = '<i class="ph ph-spinner spinner"></i> Enumerating subdomains...';
        portscanOutput.innerHTML = '<i class="ph ph-spinner spinner"></i> Scanning common ports...';

        try {
            // Run both scans concurrently
            const [subdomains, portscan] = await Promise.all([
                API.getSubdomains(target),
                API.getPortScan(target)
            ]);

            // Format raw text to be safe and visible HTML
            subdomainOutput.innerHTML = subdomains.replace(/\n/g, '<br>') || "No subdomains found.";
            portscanOutput.innerHTML = portscan.replace(/\n/g, '<br>') || "Scan failed or blocked.";

            UI.showToast('Advanced Recon completed.', 'success');
            State.addQuery(target, 'Advanced Recon', 'Complete', portscan.includes('open')); // mark as threat if open ports found
        } catch (error) {
            subdomainOutput.innerHTML = "Error retrieving data.";
            portscanOutput.innerHTML = "Error retrieving data.";
            UI.showToast(`Recon failed: ${error.message}`, 'error');
            State.addQuery(target, 'Advanced Recon', 'Failed');
        } finally {
            UI.setLoadingState('btn-analyze-recon', false);
        }
    };

    btn.addEventListener('click', performAnalysis);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performAnalysis();
    });
}

/**
 * Initialize Username Profiling Tool
 */
function initUsernameTool() {
    const btn = document.getElementById('btn-analyze-username');
    const input = document.getElementById('username-input');

    if (!btn || !input) return;

    const performAnalysis = async () => {
        const username = input.value.trim();
        if (!username) {
            UI.showToast('Please enter a username.', 'error');
            return;
        }

        UI.setLoadingState('btn-analyze-username', true);
        UI.clearContainer('username-results');

        try {
            const data = await API.getGithubUser(username);
            UI.renderDataGrid('username-results', data);
            UI.showToast('Identity profile mapped.', 'success');
            State.addQuery(`@${username}`, 'Identity Profiling', 'Complete');
        } catch (error) {
            UI.showToast(`Profile not found: ${error.message}`, 'error');
            State.addQuery(`@${username}`, 'Identity Profiling', 'Failed');
        } finally {
            UI.setLoadingState('btn-analyze-username', false);
        }
    };

    btn.addEventListener('click', performAnalysis);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performAnalysis();
    });
}

/**
 * Initialize Data Breach / Leak Tool
 */
function initLeakTool() {
    const btn = document.getElementById('btn-analyze-leak');
    const input = document.getElementById('leak-input');

    if (!btn || !input) return;

    const performAnalysis = async () => {
        const target = input.value.trim();
        if (!target) {
            UI.showToast('Please enter an email.', 'error');
            return;
        }

        UI.setLoadingState('btn-analyze-leak', true);
        UI.clearContainer('leak-results');

        try {
            const data = await API.getLeakInfo(target);
            UI.renderDataGrid('leak-results', data);

            if (data.status === "Safe") {
                UI.showToast('Target is safe from known leaks.', 'success');
                State.addQuery(target, 'Leak Check', 'Complete', false);
            } else {
                UI.showToast('WARNING: Data Breach exposure detected.', 'error');
                State.addQuery(target, 'Leak Check', 'Complete', true); // Record as threat
            }

        } catch (error) {
            UI.showToast(`Check failed: ${error.message}`, 'error');
            State.addQuery(target, 'Leak Check', 'Failed');
        } finally {
            UI.setLoadingState('btn-analyze-leak', false);
        }
    };

    btn.addEventListener('click', performAnalysis);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performAnalysis();
    });
}

/**
 * Initialize CVE Lookup Tool
 */
function initCVETool() {
    const btn = document.getElementById('btn-analyze-cve');
    const input = document.getElementById('cve-input');

    if (!btn || !input) return;

    const performAnalysis = async () => {
        const cveId = input.value.trim();
        if (!cveId) {
            UI.showToast('Please enter a CVE year and ID.', 'error');
            return;
        }

        UI.setLoadingState('btn-analyze-cve', true);
        UI.clearContainer('cve-results');

        try {
            const data = await API.getCVEInfo(cveId);
            UI.renderDataGrid('cve-results', data);
            UI.showToast(`CVE-${cveId} resolved.`, 'success');

            // Mark as threat if CVSS is High or Critical
            const isCritical = data.cvss >= 7.0;
            State.addQuery(`CVE-${cveId}`, 'Vulnerability Lookup', 'Complete', isCritical);

        } catch (error) {
            UI.showToast(`Lookup failed: ${error.message}`, 'error');
            State.addQuery(`CVE-${cveId}`, 'Vulnerability Lookup', 'Failed');
        } finally {
            UI.setLoadingState('btn-analyze-cve', false);
        }
    };

    btn.addEventListener('click', performAnalysis);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performAnalysis();
    });
}

/**
 * Initialize Shodan Intelligence Tool
 */
function initShodanTool() {
    const btnDork = document.getElementById('btn-shodan-dork');
    const btnScan = document.getElementById('btn-analyze-shodan');
    const input = document.getElementById('shodan-input');

    if (!btnDork || !btnScan || !input) return;

    // Route A: Dork Generator
    btnDork.addEventListener('click', () => {
        const target = input.value.trim();
        if (!target) {
            UI.showToast('Please enter a target IP, domain, or keyword.', 'error');
            return;
        }

        // Determine if it's an IP/hostname or a keyword
        const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
        let dork = isIP ? `host:${target}` : `hostname:"${target}"`;

        const url = `https://www.shodan.io/search?query=${encodeURIComponent(dork)}`;
        window.open(url, '_blank');
        UI.showToast('Shodan opened in new tab.', 'info');
        State.addQuery(target, 'Shodan Dork', 'Complete');
    });

    // Route B: API Scan
    const performAnalysis = async () => {
        const ip = input.value.trim();
        if (!ip) {
            UI.showToast('Please enter a target IP address for API scan.', 'error');
            return;
        }

        const apiKey = localStorage.getItem('shodan_api_key');
        if (!apiKey) {
            UI.showToast('Missing Shodan API Key. Check Settings.', 'error');
            document.getElementById('settings-modal').classList.remove('hidden');
            return;
        }

        UI.setLoadingState('btn-analyze-shodan', true);
        UI.clearContainer('shodan-results');

        try {
            const data = await API.getShodanHost(ip, apiKey);
            UI.renderDataGrid('shodan-results', data);
            UI.showToast(`Shodan data retrieved for ${ip}.`, 'success');

            // Mark as threat if vulns exist
            const isThreat = data.vulns !== 'None verified';
            State.addQuery(ip, 'Shodan API Scan', 'Complete', isThreat);

        } catch (error) {
            UI.showToast(`Shodan Scan failed: ${error.message}`, 'error');
            State.addQuery(ip, 'Shodan API Scan', 'Failed');
        } finally {
            UI.setLoadingState('btn-analyze-shodan', false);
        }
    };

    btnScan.addEventListener('click', performAnalysis);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performAnalysis(); // Default enter to API scan
    });
}

/**
 * Initialize Settings Modal
 */
function initSettings() {
    const btnOpen = document.getElementById('btn-settings');
    const linkOpen = document.getElementById('link-shodan-settings');
    const btnClose = document.getElementById('btn-close-settings');
    const btnSave = document.getElementById('btn-save-settings');
    const modal = document.getElementById('settings-modal');
    const inputShodan = document.getElementById('input-shodan-key');

    const openModal = (e) => {
        if (e) e.preventDefault();
        inputShodan.value = localStorage.getItem('shodan_api_key') || '';
        modal.classList.remove('hidden');
    };

    if (btnOpen) btnOpen.addEventListener('click', openModal);
    if (linkOpen) linkOpen.addEventListener('click', openModal);

    if (btnClose) {
        btnClose.addEventListener('click', () => {
            modal.classList.add('hidden');
        });
    }

    if (btnSave) {
        btnSave.addEventListener('click', () => {
            const key = inputShodan.value.trim();
            if (key) {
                localStorage.setItem('shodan_api_key', key);
                UI.showToast('Settings saved successfully.', 'success');
            } else {
                localStorage.removeItem('shodan_api_key');
                UI.showToast('Settings cleared.', 'info');
            }
            modal.classList.add('hidden');
        });
    }
}
