/**
 * Inbox Guardian - API & Service Integration Layer
 * Connects frontend with REST backend endpoints with automated client-side fallback
 * to local heuristic engine and demo datasets when running in static standalone mode.
 */

class ApiService {
  constructor() {
    this.baseUrl = window.location.origin;
    this.isBackendAvailable = false;
    this.checkBackend();
  }

  async checkBackend() {
    try {
      const res = await fetch(`${this.baseUrl}/api/status`, { method: 'GET' });
      if (res.ok) {
        this.isBackendAvailable = true;
        console.log("[+] Inbox Guardian REST API connected.");
      }
    } catch (e) {
      this.isBackendAvailable = false;
      console.log("[i] Running in Standalone Client Mode (Heuristic Engine Active).");
    }
  }

  /**
   * Submit EML or raw text for analysis
   */
  async analyzeEmail(rawContent) {
    if (this.isBackendAvailable) {
      try {
        const response = await fetch(`${this.baseUrl}/api/analyze-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ eml_raw: rawContent })
        });
        if (response.ok) {
          return await response.json();
        }
      } catch (err) {
        console.warn("Backend request failed, failing over to client engine:", err);
      }
    }

    // Local client-side parsing fallback
    const parsed = EMLParser.parse(rawContent);
    return ThreatEngine.analyze(parsed);
  }

  /**
   * Fetch Global Threat Intelligence Feed
   */
  async getThreatIntelligence() {
    if (this.isBackendAvailable) {
      try {
        const response = await fetch(`${this.baseUrl}/api/threat-intelligence`);
        if (response.ok) {
          const data = await response.json();
          return data.indicators;
        }
      } catch (err) {
        console.warn("Backend threat intel fetch failed:", err);
      }
    }
    return GLOBAL_THREAT_FEEDS;
  }

  /**
   * Query IP Geolocation & ASN telemetry
   */
  async getGeolocation(ip) {
    if (this.isBackendAvailable) {
      try {
        const response = await fetch(`${this.baseUrl}/api/geolocation/${ip}`);
        if (response.ok) {
          return await response.json();
        }
      } catch (err) {
        console.warn("Geolocation fetch failed:", err);
      }
    }
    // Fallback to local heuristic lookup
    return ThreatEngine.generateGeolocations([ip])[0];
  }
}

// Global instance
const apiService = new ApiService();
