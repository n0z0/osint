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

/**
 * Data Breach Check (Proxying HIBP / EmailRep or similar open APIs)
 * Note: Genuine HIBP requires a paid API key for direct queries.
 * If API key is provided, we try HIBP. If not, and it's an email, we fallback to XposedOrNot.
 */
export const getLeakInfo = async (target, hibpApiKey = null) => {
    // Basic phone number detection (+ followed by 10-15 digits)
    const isPhone = /^\+[1-9]\d{1,14}$/.test(target.replace(/\s|-/g, ''));

    if (isPhone && !hibpApiKey) {
        throw new Error("A paid HIBP API Key is required to scan Phone Numbers natively. Please configure it in Settings or use the 'Route B' Dorks below.");
    }

    try {
        if (hibpApiKey) {
            // Use genuine HIBP API
            const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(target.replace(/\s|-/g, ''))}?truncateResponse=false`;

            // Note: In a real frontend environment, calling HIBP directly might fail due to strict CORS.
            // A CORS proxy is often required. We'll attempt a direct call here, but acknowledge CORS limits.
            const response = await fetch(url, {
                headers: {
                    'hibp-api-key': hibpApiKey,
                    'user-agent': 'OSINT-Dashboard-App'
                }
            });

            if (response.status === 404) {
                return { status: "Safe", message: "No public breaches found on HIBP." };
            }

            if (!response.ok) {
                if (response.status === 401) throw new Error("Invalid HIBP API Key.");
                throw new Error(`HIBP Error: ${response.statusText}`);
            }

            const data = await response.json();
            return {
                status: 'Danger',
                source: 'HaveIBeenPwned API',
                breaches: data.map(b => ({
                    Name: b.Name,
                    Domain: b.Domain,
                    DataClasses: b.DataClasses.join(', '),
                    BreachDate: b.BreachDate
                }))
            };
        } else {
            // Fallback to XposedOrNot for Email only
            const response = await fetchWithTimeout(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(target)}`);

            // Handle 404 (Not Found = No breaches) gracefully
            if (response.Error === "Not found") {
                return { status: "Safe", message: "No public breaches found for this email." };
            }
            return response;
        }

    } catch (error) {
        if (error.message.includes("404")) {
            return { status: "Safe", message: "No public breaches found." };
        }
        console.error("Leak API Error:", error);
        throw new Error(error.message || "Unable to reach Breach Database API.");
    }
}

/**
 * CVE Vulnerability Lookup (Using NVD / MITRE public APIs)
 */
export const getCVEInfo = async (cveId) => {
    try {
        // cve.circl.lu is a public reliable alternative to direct NVD which often limits without keys
        // Since their server sends a conflicting CORS header sometimes, we route through a proxy
        const targetUrl = encodeURIComponent(`https://cve.circl.lu/api/cve/CVE-${cveId}`);
        const proxyData = await fetchWithTimeout(`https://api.allorigins.win/get?url=${targetUrl}`);

        const response = proxyData.contents ? JSON.parse(proxyData.contents) : null;

        // Circl returns null if not found
        if (!response) {
            throw new Error(`CVE-${cveId} not found in database.`);
        }

        // We trim the massive response for UI friendliness
        return {
            id: response.id,
            cvss: response.cvss,
            severity: (response.cvss >= 9.0) ? 'CRITICAL' : (response.cvss >= 7.0) ? 'HIGH' : (response.cvss >= 4.0) ? 'MEDIUM' : 'LOW',
            summary: response.summary,
            published: response.Published,
            modified: response.Modified,
            references: (response.references || []).slice(0, 5).join(', ') // Just show 5
        };

    } catch (error) {
        console.error("CVE API Error:", error);
        throw new Error(`Failed to lookup CVE-${cveId}: ` + error.message);
    }
}

/**
 * Shodan API Search (Route B - Requires API Key)
 */
export const getShodanHost = async (ip, apiKey) => {
    try {
        if (!apiKey) throw new Error("API Key is missing. Please configure it in Settings.");

        // We use a CORS Proxy (like allorigins or corsproxy.io) because Shodan API blocks browser origin requests
        const shodanUrl = encodeURIComponent(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
        const response = await fetchWithTimeout(`https://api.allorigins.win/get?url=${shodanUrl}`);

        const data = JSON.parse(response.contents);

        if (data.error) {
            throw new Error(data.error);
        }

        // Simplify payload for UI
        return {
            ip: data.ip_str,
            organization: data.org,
            os: data.os || 'Unknown',
            ports: data.ports ? data.ports.join(', ') : 'None detected',
            vulns: data.vulns ? data.vulns.join(', ') : 'None verified',
            last_update: data.last_update
        };

    } catch (error) {
        console.error("Shodan API Error:", error);
        throw new Error("Shodan API Failed: " + error.message);
    }
}
