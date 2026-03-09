/**
 * state.js - Application State Management
 * Handles real-time tracking of investigations and statistics
 */

class StateManager {
    constructor() {
        this.queries = parseInt(localStorage.getItem('total_queries') || '0');
        this.threats = parseInt(localStorage.getItem('threats_detected') || '0');
        this.history = JSON.parse(localStorage.getItem('investigation_history') || '[]');

        // Listeners for UI updates
        this.listeners = [];
    }

    subscribe(listener) {
        this.listeners.push(listener);
        // Initial broadcast
        this.notify();
    }

    notify() {
        this.listeners.forEach(listener => listener({
            queries: this.queries,
            threats: this.threats,
            history: this.history
        }));
    }

    addQuery(target, type, status, isThreat = false) {
        this.queries++;
        if (isThreat) this.threats++;

        const investigation = {
            id: Date.now().toString(36),
            target,
            type,
            status,
            timestamp: new Date().toISOString()
        };

        // Keep last 10 items only
        this.history.unshift(investigation);
        if (this.history.length > 10) {
            this.history.pop();
        }

        // Persist
        localStorage.setItem('total_queries', this.queries.toString());
        localStorage.setItem('threats_detected', this.threats.toString());
        localStorage.setItem('investigation_history', JSON.stringify(this.history));

        this.notify();
    }

    // Helper to format ISO date to relative time
    timeAgo(dateString) {
        const date = new Date(dateString);
        const seconds = Math.floor((new Date() - date) / 1000);

        let interval = seconds / 31536000;
        if (interval > 1) return Math.floor(interval) + " years ago";
        interval = seconds / 2592000;
        if (interval > 1) return Math.floor(interval) + " months ago";
        interval = seconds / 86400;
        if (interval > 1) return Math.floor(interval) + " days ago";
        interval = seconds / 3600;
        if (interval > 1) return Math.floor(interval) + " hrs ago";
        interval = seconds / 60;
        if (interval > 1) return Math.floor(interval) + " mins ago";
        return Math.floor(seconds) + " secs ago";
    }
}

export const State = new StateManager();
