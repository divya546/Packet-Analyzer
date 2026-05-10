// connectionTracker.js

/**
 * Connection states
 */
const ConnectionState = {
  NEW: 'NEW',
  ESTABLISHED: 'ESTABLISHED',
  CLASSIFIED: 'CLASSIFIED',
  BLOCKED: 'BLOCKED',
  CLOSED: 'CLOSED',
};

/**
 * Application types
 */
const AppType = {
  UNKNOWN: 'UNKNOWN',
  YOUTUBE: 'YOUTUBE',
  NETFLIX: 'NETFLIX',
  WHATSAPP: 'WHATSAPP',
  INSTAGRAM: 'INSTAGRAM',
};

/**
 * FiveTuple key generator
 */
function tupleToKey(tuple) {
  return `${tuple.srcIP}:${tuple.srcPort}-${tuple.dstIP}:${tuple.dstPort}-${tuple.protocol}`;
}

/**
 * Connection object
 */
class Connection {
  constructor(tuple) {
    this.tuple = tuple;

    this.state = ConnectionState.NEW;
    this.app = AppType.UNKNOWN;
    this.sni = '';

    this.packets = 0;
    this.bytes = 0;

    this.outboundPackets = 0;
    this.inboundPackets = 0;

    this.outboundBytes = 0;
    this.inboundBytes = 0;

    this.createdAt = new Date();
    this.lastSeen = new Date();

    this.blocked = false;
  }
}

/**
 * Connection Tracker
 */
class ConnectionTracker {
  constructor(fpId, maxConnections = 100000) {
    this.fpId = fpId;
    this.maxConnections = maxConnections;

    // Map<key, Connection>
    this.connections = new Map();

    // Statistics
    this.totalSeen = 0;
    this.classifiedCount = 0;
    this.blockedCount = 0;
  }

  /**
   * Get existing or create new connection
   */
  getOrCreateConnection(tuple) {
    const key = tupleToKey(tuple);

    if (this.connections.has(key)) {
      return this.connections.get(key);
    }

    if (this.connections.size >= this.maxConnections) {
      this.evictOldest();
    }

    const conn = new Connection(tuple);
    this.connections.set(key, conn);
    this.totalSeen++;

    return conn;
  }

  /**
   * Get existing connection
   */
  getConnection(tuple) {
    const key = tupleToKey(tuple);
    return this.connections.get(key) || null;
  }

  /**
   * Update connection stats with new packet
   */
  updateConnection(conn, packetSize, isOutbound) {
    if (!conn) return;

    conn.packets++;
    conn.bytes += packetSize;
    conn.lastSeen = new Date();

    if (conn.state === ConnectionState.NEW) {
      conn.state = ConnectionState.ESTABLISHED;
    }

    if (isOutbound) {
      conn.outboundPackets++;
      conn.outboundBytes += packetSize;
    } else {
      conn.inboundPackets++;
      conn.inboundBytes += packetSize;
    }
  }

  /**
   * Mark connection as classified
   */
  classifyConnection(conn, app, sni = '') {
    if (!conn) return;

    if (conn.state !== ConnectionState.CLASSIFIED) {
      this.classifiedCount++;
    }

    conn.state = ConnectionState.CLASSIFIED;
    conn.app = app;
    conn.sni = sni;
  }

  /**
   * Mark connection as blocked
   */
  blockConnection(conn) {
    if (!conn) return;

    if (!conn.blocked) {
      this.blockedCount++;
    }

    conn.blocked = true;
    conn.state = ConnectionState.BLOCKED;
  }

  /**
   * Mark connection as closed
   */
  closeConnection(tuple) {
    const conn = this.getConnection(tuple);
    if (!conn) return;

    conn.state = ConnectionState.CLOSED;
  }

  /**
   * Remove stale connections
   * @param {number} timeoutSeconds
   * @returns {number}
   */
  cleanupStale(timeoutSeconds = 300) {
    const now = Date.now();
    const timeoutMs = timeoutSeconds * 1000;

    let removed = 0;

    for (const [key, conn] of this.connections.entries()) {
      if (now - conn.lastSeen.getTime() > timeoutMs) {
        this.connections.delete(key);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Get all connections
   */
  getAllConnections() {
    return Array.from(this.connections.values()).map(conn => ({
      ...conn,
    }));
  }

  /**
   * Get active connection count
   */
  getActiveCount() {
    return this.connections.size;
  }

  /**
   * Get tracker statistics
   */
  getStats() {
    return {
      active_connections: this.connections.size,
      total_connections_seen: this.totalSeen,
      classified_connections: this.classifiedCount,
      blocked_connections: this.blockedCount,
    };
  }

  /**
   * Clear all connections
   */
  clear() {
    this.connections.clear();
    this.totalSeen = 0;
    this.classifiedCount = 0;
    this.blockedCount = 0;
  }

  /**
   * Iterate over all connections
   */
  forEach(callback) {
    for (const conn of this.connections.values()) {
      callback(conn);
    }
  }

  /**
   * Evict oldest connection
   */
  evictOldest() {
    let oldestKey = null;
    let oldestTime = Infinity;

    for (const [key, conn] of this.connections.entries()) {
      const time = conn.lastSeen.getTime();
      if (time < oldestTime) {
        oldestTime = time;
        oldestKey = key;
      }
    }

    if (oldestKey !== null) {
      this.connections.delete(oldestKey);
    }
  }
}

/**
 * Global Connection Table
 */
class GlobalConnectionTable {
  constructor(numFps) {
    this.trackers = new Array(numFps).fill(null);
  }

  /**
   * Register tracker
   */
  registerTracker(fpId, tracker) {
    this.trackers[fpId] = tracker;
  }

  /**
   * Get aggregated stats
   */
  getGlobalStats() {
    const stats = {
      total_active_connections: 0,
      total_connections_seen: 0,
      app_distribution: {},
      top_domains: [],
    };

    const domainCounts = new Map();

    for (const tracker of this.trackers) {
      if (!tracker) continue;

      const trackerStats = tracker.getStats();
      stats.total_active_connections += trackerStats.active_connections;
      stats.total_connections_seen += trackerStats.total_connections_seen;

      tracker.forEach(conn => {
        // App distribution
        const app = conn.app || AppType.UNKNOWN;
        stats.app_distribution[app] =
          (stats.app_distribution[app] || 0) + 1;

        // Domain counts
        if (conn.sni) {
          domainCounts.set(
            conn.sni,
            (domainCounts.get(conn.sni) || 0) + 1
          );
        }
      });
    }

    stats.top_domains = Array.from(domainCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    return stats;
  }

  /**
   * Generate human-readable report
   */
  generateReport() {
    const stats = this.getGlobalStats();

    let report = '';
    report += '=== Global Connection Report ===\n';
    report += `Active Connections: ${stats.total_active_connections}\n`;
    report += `Total Seen: ${stats.total_connections_seen}\n\n`;

    report += 'Application Distribution:\n';
    for (const [app, count] of Object.entries(stats.app_distribution)) {
      report += `  ${app}: ${count}\n`;
    }

    report += '\nTop Domains:\n';
    for (const [domain, count] of stats.top_domains) {
      report += `  ${domain}: ${count}\n`;
    }

    return report;
  }
}

module.exports = {
  ConnectionTracker,
  GlobalConnectionTable,
  Connection,
  ConnectionState,
  AppType,
  tupleToKey,
};