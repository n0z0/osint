/**
 * api.js - Core API Interface for OSINT Services
 * Handles all external HTTP requests and data formatting.
 */

// Simple robust fetch wrapper with timeout
const fetchWithTimeout = async (resource, options = {}) => {
    const { timeout = 10000 } = options;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(resource, {
        ...options,
        signal: controller.signal
    });
    clearTimeout(id);

    if (!response.ok) {
        throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }
    return response.json();
};

/**
 * Fetch IP Information (Using ip-api.com)
 * Non-commercial use is free, no API key required for basic info.
 */
export const getIpIntel = async (ip) => {
    try {
        const data = await fetchWithTimeout(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
        if (data.status === 'fail') throw new Error(data.message || 'Verification failed');
        return data;
    } catch (error) {
        console.error("IP API Error:", error);
        throw error;
    }
};

/**
 * Fetch Domain WHOIS/Information (Mocked/Free API)
 * Note: Free reliable WHOIS APIs are rate-limited. Using networkcalc for basic DNS/WHOIS info.
 */
export const getDomainIntel = async (domain) => {
    try {
        // Example using networkcalc for basic DNS records
        const data = await fetchWithTimeout(`https://networkcalc.com/api/dns/lookup/${domain}`);
        if (data.status !== "OK") throw new Error("Could not resolve domain");
        return data.records;
    } catch (error) {
        console.error("Domain API Error:", error);
        throw error;
    }
}

/**
 * Github User Profile (As a proxy for username lookup concept)
 */
export const getGithubUser = async (username) => {
    try {
        const data = await fetchWithTimeout(`https://api.github.com/users/${username}`);
        return data;
    } catch (error) {
        console.error("Username API Error:", error);
        throw error;
    }
}

/**
 * Subdomain Enumeration (via crt.sh - Certificate Transparency Logs)
 */
export const getSubdomains = async (domain) => {
    try {
        // crt.sh returns JSON for subdomains
        const response = await fetch(`https://crt.sh/?q=${domain}&output=json`);
        if (!response.ok) throw new Error("Subdomain enumeration failed");

        const data = await response.json();
        // Extract unique subdomains and format as text
        const uniqueSubdomains = [...new Set(data.map(entry => entry.name_value))];
        return uniqueSubdomains.join('\n');
    } catch (error) {
        console.error("Subdomain API Error:", error);
        // Fallback or error message for UI
        return "Failed to fetch from crt.sh. It might be rate limited or blocked by CORS.";
    }
}

/**
 * Basic Information Gathering / Port Hint (since free reliable nmap APIs are rare without CORS)
 * Alternative: IP Geolocation + Shodan-like hints if available (Using ipwhois for now as a safer proxy)
 */
export const getPortScan = async (ipOrDomain) => {
    try {
        // Free and reliable port scanning via browser is extremely difficult due to CORS and abuse limits.
        // As a fallback for this MVP, we will simulate a quick check or use a known open API like ipwhois for deeper network info.
        const response = await fetch(`http://ip-api.com/json/${ipOrDomain}`);
        if (!response.ok) throw new Error("Network info failed");

        const data = await response.json();
        if (data.status === 'fail') return "No host found to scan.";

        return `Note: Direct port scanning from browser is restricted.\n\nHost Target: ${data.query}\nISP: ${data.isp}\nOrg: ${data.org}\nASN: ${data.as}\n\nCommon open ports usually associated with this type of host:\n- 80/tcp (HTTP)\n- 443/tcp (HTTPS)\n\n*For an actual remote nmap scan, a dedicated backend proxy is required.*`;
    } catch (error) {
        console.error("PortScan API Error:", error);
        return "Failed to initiate remote scan.";
    }
}
