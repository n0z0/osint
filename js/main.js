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
