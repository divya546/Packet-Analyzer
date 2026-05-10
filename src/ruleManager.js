// ruleManager.js

const fs = require('fs');

/**
 * Block reason types
 */
const BlockReasonType = {
  IP: 'IP',
  APP: 'APP',
  DOMAIN: 'DOMAIN',
  PORT: 'PORT',
};

/**
 * RuleManager
 *
 * Supports:
 * - IP blocking
 * - Application blocking
 * - Domain blocking (including wildcard patterns like *.facebook.com)
 * - Port blocking
 */
class RuleManager {
  constructor() {
    this.blockedIPs = new Set();        // strings like "192.168.1.1"
    this.blockedApps = new Set();       // strings like "YOUTUBE"
    this.blockedDomains = new Set();    // exact domains
    this.domainPatterns = [];           // wildcard patterns
    this.blockedPorts = new Set();      // numbers
  }

  // =========================================================
  // IP Blocking
  // =========================================================

  blockIP(ip) {
    this.blockedIPs.add(String(ip));
  }

  unblockIP(ip) {
    this.blockedIPs.delete(String(ip));
  }

  isIPBlocked(ip) {
    return this.blockedIPs.has(String(ip));
  }

  getBlockedIPs() {
    return Array.from(this.blockedIPs);
  }

  // =========================================================
  // App Blocking
  // =========================================================

  blockApp(app) {
    this.blockedApps.add(String(app).toUpperCase());
  }

  unblockApp(app) {
    this.blockedApps.delete(String(app).toUpperCase());
  }

  isAppBlocked(app) {
    return this.blockedApps.has(String(app).toUpperCase());
  }

  getBlockedApps() {
    return Array.from(this.blockedApps);
  }

  // =========================================================
  // Domain Blocking
  // =========================================================

  blockDomain(domain) {
    domain = domain.toLowerCase();

    if (domain.includes('*')) {
      if (!this.domainPatterns.includes(domain)) {
        this.domainPatterns.push(domain);
      }
    } else {
      this.blockedDomains.add(domain);
    }
  }

  unblockDomain(domain) {
    domain = domain.toLowerCase();

    this.blockedDomains.delete(domain);
    this.domainPatterns = this.domainPatterns.filter(
      pattern => pattern !== domain
    );
  }

  isDomainBlocked(domain) {
    if (!domain) return false;

    domain = domain.toLowerCase();

    // Exact match
    if (this.blockedDomains.has(domain)) {
      return true;
    }

    // Wildcard patterns
    for (const pattern of this.domainPatterns) {
      if (RuleManager.domainMatchesPattern(domain, pattern)) {
        return true;
      }
    }

    return false;
  }

  getBlockedDomains() {
    return [
      ...Array.from(this.blockedDomains),
      ...this.domainPatterns,
    ];
  }

  // =========================================================
  // Port Blocking
  // =========================================================

  blockPort(port) {
    this.blockedPorts.add(Number(port));
  }

  unblockPort(port) {
    this.blockedPorts.delete(Number(port));
  }

  isPortBlocked(port) {
    return this.blockedPorts.has(Number(port));
  }

  // =========================================================
  // Combined Check
  // =========================================================

  /**
   * Returns:
   * - null if allowed
   * - { type, detail } if blocked
   */
  shouldBlock(srcIP, dstPort, app, domain) {
    if (this.isIPBlocked(srcIP)) {
      return {
        type: BlockReasonType.IP,
        detail: String(srcIP),
      };
    }

    if (app && this.isAppBlocked(app)) {
      return {
        type: BlockReasonType.APP,
        detail: String(app),
      };
    }

    if (domain && this.isDomainBlocked(domain)) {
      return {
        type: BlockReasonType.DOMAIN,
        detail: domain,
      };
    }

    if (this.isPortBlocked(dstPort)) {
      return {
        type: BlockReasonType.PORT,
        detail: String(dstPort),
      };
    }

    return null;
  }

  // =========================================================
  // Persistence
  // =========================================================

  saveRules(filename) {
    try {
      const data = {
        blockedIPs: Array.from(this.blockedIPs),
        blockedApps: Array.from(this.blockedApps),
        blockedDomains: Array.from(this.blockedDomains),
        domainPatterns: this.domainPatterns,
        blockedPorts: Array.from(this.blockedPorts),
      };

      fs.writeFileSync(
        filename,
        JSON.stringify(data, null, 2),
        'utf-8'
      );

      return true;
    } catch (error) {
      console.error('Failed to save rules:', error.message);
      return false;
    }
  }

  loadRules(filename) {
    try {
      const raw = fs.readFileSync(filename, 'utf-8');
      const data = JSON.parse(raw);

      this.blockedIPs = new Set(data.blockedIPs || []);
      this.blockedApps = new Set(data.blockedApps || []);
      this.blockedDomains = new Set(data.blockedDomains || []);
      this.domainPatterns = data.domainPatterns || [];
      this.blockedPorts = new Set(data.blockedPorts || []);

      return true;
    } catch (error) {
      console.error('Failed to load rules:', error.message);
      return false;
    }
  }

  // =========================================================
  // Utilities
  // =========================================================

  clearAll() {
    this.blockedIPs.clear();
    this.blockedApps.clear();
    this.blockedDomains.clear();
    this.domainPatterns = [];
    this.blockedPorts.clear();
  }

  getStats() {
    return {
      blocked_ips: this.blockedIPs.size,
      blocked_apps: this.blockedApps.size,
      blocked_domains:
        this.blockedDomains.size + this.domainPatterns.length,
      blocked_ports: this.blockedPorts.size,
    };
  }

  /**
   * Wildcard matching
   * Example:
   * - pattern: "*.facebook.com"
   * - domain: "video.facebook.com"
   */
  static domainMatchesPattern(domain, pattern) {
    pattern = pattern.toLowerCase();
    domain = domain.toLowerCase();

    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1); // ".facebook.com"
      return domain.endsWith(suffix);
    }

    return domain === pattern;
  }
}

module.exports = {
  RuleManager,
  BlockReasonType,
};