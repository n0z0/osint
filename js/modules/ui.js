/**
 * ui.js - User Interface Management
 * Handles tabs, theming, toasts, and DOM updates.
 */

class UIManager {
    constructor() {
        this.initTheme();
        this.initSidebar();
        this.initSearchShortcut();
    }

    // --- Dashboard Updates ---
    updateDashboard(state) {
        // Update Stats
        const queriesEl = document.getElementById('stat-queries');
        const threatsEl = document.getElementById('stat-threats');

        if (queriesEl) queriesEl.textContent = state.queries.toLocaleString();
        if (threatsEl) threatsEl.textContent = state.threats.toLocaleString();

        // Update Table
        const tbody = document.getElementById('recent-investigations-body');
        if (!tbody) return;

        if (state.history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No recent investigations. Start a query.</td></tr>';
            return;
        }

        tbody.innerHTML = state.history.map(item => {
            const statusClass = item.status === 'Complete' ? 'success' : (item.status === 'Failed' ? 'danger' : 'warning');

            // Reusing State logic for formatting using dynamic import to avoid circular dependency in UI if possible, 
            // but we'll format it right here or let State handle it before passing. 
            // Since UI shouldn't ideally know about State directly, we assume State passes raw data.
            // For simplicity, we'll format timestamp simply or rely on State logic.
            // We'll use a basic fallback here.

            return `
                <tr>
                    <td class="font-mono">${item.target}</td>
                    <td>${item.type}</td>
                    <td><span class="badge ${statusClass}">${item.status}</span></td>
                    <td class="text-muted text-sm" data-timestamp="${item.timestamp}">Just now</td>
                </tr>
            `;
        }).join('');
    }

    // --- Theming ---
    initTheme() {
        const themeToggle = document.getElementById('theme-toggle');
        const currentTheme = localStorage.getItem('theme') || 'dark';

        document.documentElement.setAttribute('data-theme', currentTheme);

        themeToggle.addEventListener('click', () => {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const newTheme = isDark ? 'light' : 'dark';

            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }

    // --- Sidebar & Navigation ---
    initSidebar() {
        const navItems = document.querySelectorAll('.nav-item');
        const viewPanels = document.querySelectorAll('.view-panel');

        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();

                // Remove active classes
                navItems.forEach(nav => nav.classList.remove('active'));
                viewPanels.forEach(panel => panel.classList.remove('active'));

                // Add active class to clicked
                item.classList.add('active');

                // Show corresponding view
                const targetViewId = item.getAttribute('data-tab');
                document.getElementById(targetViewId).classList.add('active');
            });
        });
    }

    // --- Global Shortcuts ---
    initSearchShortcut() {
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                const searchInput = document.getElementById('global-search');
                searchInput.focus();
            }
        });
    }

    // --- UI Notifications (Toast) ---
    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        // Map icons based on type
        const icons = {
            success: 'check-circle',
            error: 'warning-circle',
            info: 'info'
        };
        const iconName = icons[type] || icons.info;

        toast.innerHTML = `
            <i class="ph ph-${iconName} toast-icon"></i>
            <div class="toast-content">${message}</div>
        `;

        container.appendChild(toast);

        // Remove element after duration
        setTimeout(() => {
            toast.classList.add('fade-out');
            toast.addEventListener('animationend', () => toast.remove());
        }, 3000);
    }

    // --- Button State Utilities ---
    setLoadingState(buttonId, isLoading) {
        const btn = document.getElementById(buttonId);
        if (!btn) return;

        if (isLoading) {
            btn.dataset.originalHTML = btn.innerHTML;
            btn.innerHTML = `<i class="ph ph-spinner spinner"></i> Processing...`;
            btn.disabled = true;
            btn.style.opacity = '0.7';
        } else {
            btn.innerHTML = btn.dataset.originalHTML || btn.innerHTML;
            btn.disabled = false;
            btn.style.opacity = '1';
        }
    }

    // --- Render JSON Objects to UI grid --
    renderDataGrid(containerId, dataObject) {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.classList.remove('hidden');

        let html = '<div class="data-grid">';

        const buildGrid = (obj) => {
            for (const [key, value] of Object.entries(obj)) {
                if (value === null || value === '') continue;

                if (typeof value === 'object' && !Array.isArray(value)) {
                    // flatten slightly but keep it simple
                    buildGrid(value);
                } else {
                    const formattedKey = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());

                    let formattedVal = value;
                    if (Array.isArray(value)) {
                        formattedVal = value.map(item => {
                            // Jika item di dalam array adalah object, kita ekstrak value-nya agar tidak jadi [object Object]
                            if (typeof item === 'object' && item !== null) {
                                return Object.entries(item)
                                    .map(([k, v]) => `<span style="opacity: 0.7">${k}:</span> ${v}`)
                                    .join(', ');
                            }
                            return item;
                        }).join('<br><div style="margin: 4px 0; border-top: 1px solid var(--border-color); opacity: 0.3"></div>');
                    }

                    html += `
                        <div class="data-item">
                            <div class="data-label">${formattedKey}</div>
                            <div class="data-value" style="font-size: 0.9em; line-height: 1.4; word-break: break-word;">${formattedVal}</div>
                        </div>
                     `;
                }
            }
        };

        buildGrid(dataObject);
        html += '</div>';

        // Add Raw JSON view
        html += `
            <details style="margin-top: 1rem;">
                <summary style="cursor: pointer; color: var(--text-muted); font-size: 0.875rem;">View Raw Data</summary>
                <div class="result-raw">${JSON.stringify(dataObject, null, 2)}</div>
            </details>
         `;

        container.innerHTML = html;
    }

    // Clear container
    clearContainer(containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = '';
            container.classList.add('hidden');
        }
    }
}

export const UI = new UIManager();
