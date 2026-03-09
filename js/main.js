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
    initGoogleDorkingTool();
    initSettings();
});

/**
 * Initialize Google Dorking Tool (GHDB)
 */
function initGoogleDorkingTool() {
    const input = document.getElementById('dork-domain-input');
    const btnSearch = document.getElementById('btn-custom-dork');
    const viewPanel = document.getElementById('google-dorking');

    if (!input || !btnSearch || !viewPanel) return;

    // Custom Search Button
    btnSearch.addEventListener('click', () => {
        const domain = input.value.trim();
        if (!domain) return UI.showToast('Please enter a target domain first.', 'warning');

        const url = `https://www.google.com/search?q=site:${encodeURIComponent(domain)}`;
        window.open(url, '_blank');
        UI.showToast('Opened basic site search in Google', 'info');
        State.addQuery(domain, 'Google Dork: Basic', 'Complete');
    });

    // Handle Curated Dork Chips within this panel specifically
    const dorkChips = viewPanel.querySelectorAll('.dork-chip');
    dorkChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const domain = input.value.trim();
            const dorkValue = chip.getAttribute('data-dork');

            // If user hasn't put a domain, just open the raw dork without site:
            let query = dorkValue;
            if (domain) {
                query = `site:${domain} ${dorkValue}`;
            } else {
                UI.showToast('No domain specified. Running raw dork globally...', 'info');
            }

            const url = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
            window.open(url, '_blank');
            State.addQuery(domain || 'Global', `Google Dork: ${dorkValue.substring(0, 15)}...`, 'Complete');
        });
    });
}

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
    const viewPanel = document.getElementById('leak-check');

    if (!btn || !input || !viewPanel) return;

    // Handle Quick Dorks for Leak Route B
    const dorkChips = viewPanel.querySelectorAll('.dork-chip');
    dorkChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const target = input.value.trim();
            const dorkValue = chip.getAttribute('data-dork');

            // Strip anything but numbers/plus if it looks like a phone, or just use raw text
            const sanitizedTarget = target ? target.replace(/[^\+0-9a-zA-Z\.\@\s-]/g, '') : '';

            let query = dorkValue;
            if (sanitizedTarget) {
                // Determine logic: some dorks need quote wrap, some don't
                if (dorkValue.includes('intext:')) {
                    query = `${dorkValue}"${sanitizedTarget}"`;
                } else if (dorkValue.includes('site:t.me')) {
                    // Search for the number without '+'
                    query = `${dorkValue} "${sanitizedTarget.replace('+', '')}"`;
                } else {
                    query = `"${sanitizedTarget}" ${dorkValue}`;
                }
            } else {
                UI.showToast('No target specified. Running raw phone dork globally.', 'info');
            }

            const url = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
            window.open(url, '_blank');
            State.addQuery(sanitizedTarget || 'Global Phone', `Breach Dork: ${dorkValue.substring(0, 15)}...`, 'Complete');
        });
    });

    const performAnalysis = async () => {
        const target = input.value.trim();
        if (!target) {
            UI.showToast('Please enter an Email or Phone number.', 'error');
            return;
        }

        UI.setLoadingState('btn-analyze-leak', true);
        UI.clearContainer('leak-results');

        const hibpKey = localStorage.getItem('hibp_api_key');

        try {
            const data = await API.getLeakInfo(target, hibpKey);
            UI.renderDataGrid('leak-results', data);

            if (data.status === "Safe") {
                UI.showToast('Target is safe from known leaks.', 'success');
                State.addQuery(target, 'Leak Check', 'Complete', false);
            } else {
                UI.showToast('WARNING: Data Breach exposure detected.', 'error');
                State.addQuery(target, 'Leak Check', 'Complete', true); // Record as threat
            }

        } catch (error) {
            // Handle specific UI redirects
            if (error.message.includes('A paid HIBP API Key is required')) {
                UI.showToast(error.message, 'warning');
                const modal = document.getElementById('settings-modal');
                if (modal) modal.classList.remove('hidden');
            } else {
                UI.showToast(`Check failed: ${error.message}`, 'error');
            }
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
 * Initialize IoT Search Engines Tool (Shodan, Censys, ZoomEye)
 */
function initShodanTool() {
    const btnShodanDork = document.getElementById('btn-shodan-dork');
    const btnCensysDork = document.getElementById('btn-censys-dork');
    const btnZoomEyeDork = document.getElementById('btn-zoomeye-dork');
    const btnScan = document.getElementById('btn-analyze-shodan');
    const input = document.getElementById('shodan-input');

    if (!btnShodanDork || !btnScan || !input) return;

    // Helper to determine if input is a specific Dork command or plain target
    const isIPTarget = (val) => /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(val);
    const isRawDork = (val) => val.includes(':') || val.includes('"') || val.includes(' ');

    // Handle Quick Dork Clicks
    const dorkChips = document.querySelectorAll('.dork-chip');
    dorkChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const dorkValue = chip.getAttribute('data-dork');
            input.value = dorkValue;
            UI.showToast('Dork template applied. Now click a search engine below.', 'info');
        });
    });

    // Route A: Shodan Dork
    btnShodanDork.addEventListener('click', () => {
        const target = input.value.trim();
        if (!target) return UI.showToast('Please enter a target or dork.', 'error');

        let dork = target;
        if (!isRawDork(target)) {
            dork = isIPTarget(target) ? `host:${target}` : `hostname:"${target}"`;
        }

        window.open(`https://www.shodan.io/search?query=${encodeURIComponent(dork)}`, '_blank');
        UI.showToast('Opened in Shodan.', 'info');
        State.addQuery(target, 'Shodan Dork', 'Complete');
    });

    // Route A: Censys Dork
    if (btnCensysDork) {
        btnCensysDork.addEventListener('click', () => {
            const target = input.value.trim();
            if (!target) return UI.showToast('Please enter a target or dork.', 'error');

            let dork = target;
            if (!isRawDork(target)) {
                dork = isIPTarget(target) ? `ip:${target}` : `services.tls.certificates.leaf_data.subject.common_name:"${target}"`;
            }

            window.open(`https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(dork)}`, '_blank');
            UI.showToast('Opened in Censys.', 'info');
            State.addQuery(target, 'Censys Dork', 'Complete');
        });
    }

    // Route A: ZoomEye Dork
    if (btnZoomEyeDork) {
        btnZoomEyeDork.addEventListener('click', () => {
            const target = input.value.trim();
            if (!target) return UI.showToast('Please enter a target or dork.', 'error');

            let dork = target;
            if (!isRawDork(target)) {
                dork = isIPTarget(target) ? `ip:"${target}"` : `site:"${target}"`;
            }

            window.open(`https://www.zoomeye.org/searchResult?q=${encodeURIComponent(dork)}`, '_blank');
            UI.showToast('Opened in ZoomEye.', 'info');
            State.addQuery(target, 'ZoomEye Dork', 'Complete');
        });
    }

    // Route B: API Scan (Shodan Only)
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
    const linkShodanOpen = document.getElementById('link-shodan-settings');
    const viewPanelLeak = document.getElementById('leak-check');
    const btnClose = document.getElementById('btn-close-settings');
    const btnSave = document.getElementById('btn-save-settings');
    const modal = document.getElementById('settings-modal');
    const inputShodan = document.getElementById('input-shodan-key');
    const inputHibp = document.getElementById('input-hibp-key');

    const openModal = (e) => {
        if (e) e.preventDefault();
        inputShodan.value = localStorage.getItem('shodan_api_key') || '';
        inputHibp.value = localStorage.getItem('hibp_api_key') || '';
        modal.classList.remove('hidden');
    };

    if (btnOpen) btnOpen.addEventListener('click', openModal);
    if (linkShodanOpen) linkShodanOpen.addEventListener('click', openModal);

    // Bind HIBP settings links inside Leak module
    if (viewPanelLeak) {
        const linkHibpOpen = viewPanelLeak.querySelector('.link-hibp-settings');
        if (linkHibpOpen) linkHibpOpen.addEventListener('click', openModal);
    }

    if (btnClose) {
        btnClose.addEventListener('click', () => {
            modal.classList.add('hidden');
        });
    }

    if (btnSave) {
        btnSave.addEventListener('click', () => {
            const keyShodan = inputShodan.value.trim();
            const keyHibp = inputHibp.value.trim();

            if (keyShodan) localStorage.setItem('shodan_api_key', keyShodan);
            else localStorage.removeItem('shodan_api_key');

            if (keyHibp) localStorage.setItem('hibp_api_key', keyHibp);
            else localStorage.removeItem('hibp_api_key');

            UI.showToast('Settings saved successfully.', 'success');
            modal.classList.add('hidden');
        });
    }
}
