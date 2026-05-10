// src/dpiEngine.js

const fs = require('fs');
const path = require('path');
const { ConnectionTracker, GlobalConnectionTable } = require('./connectionTracker');

/**
 * DPI Engine - Main Orchestrator
 */
class DPIEngine {
  constructor(config = {}) {
    this.config = {
      numLoadBalancers: 2,
      fpsPerLb: 2,
      queueSize: 10000,
      rulesFile: '',
      verbose: true,
      ...config,
    };

    // Shared components
    this.ruleManager = null;
    this.globalConnTable = new GlobalConnectionTable(
      this.config.numLoadBalancers * this.config.fpsPerLb
    );

    // Fast Path trackers
    this.trackers = [];

    // Statistics
    this.stats = {
      totalPackets: 0,
      forwardedPackets: 0,
      blockedPackets: 0,
      bytesProcessed: 0,
      startTime: null,
      endTime: null,
    };

    // Control flags
    this.running = false;
    this.processingComplete = false;
  }

  /**
   * Initialize engine
   */
  initialize() {
    const totalFPs =
      this.config.numLoadBalancers * this.config.fpsPerLb;

    for (let i = 0; i < totalFPs; i++) {
      const tracker = new ConnectionTracker(i);
      this.trackers.push(tracker);
      this.globalConnTable.registerTracker(i, tracker);
    }

    console.log(`Initialized DPI Engine with ${totalFPs} Fast Path processors`);
    return true;
  }

  /**
   * Process PCAP file
   * NOTE: This is currently a simulation because PCAP parsing
   * logic is not yet implemented.
   */
  async processFile(inputFile) {
    if (!this.initialize()) {
      throw new Error('Failed to initialize DPI Engine');
    }

    this.start();

    console.log(`Processing file: ${inputFile}`);
    console.log('--------------------------------------');

    // Check if file exists
    if (!fs.existsSync(inputFile)) {
      throw new Error(`File not found: ${inputFile}`);
    }

    // Simulated packets
    const samplePackets = [
      {
        tuple: {
          src_ip: '192.168.1.100',
          dst_ip: '142.250.185.206',
          src_port: 52341,
          dst_port: 443,
          protocol: 'TCP',
        },
        size: 1500,
        isOutbound: true,
        sni: 'www.google.com',
        app: 'GOOGLE',
      },
      {
        tuple: {
          src_ip: '192.168.1.100',
          dst_ip: '157.240.1.35',
          src_port: 52342,
          dst_port: 443,
          protocol: 'TCP',
        },
        size: 1400,
        isOutbound: true,
        sni: 'www.facebook.com',
        app: 'FACEBOOK',
      },
      {
        tuple: {
          src_ip: '192.168.1.100',
          dst_ip: '140.82.114.4',
          src_port: 52343,
          dst_port: 443,
          protocol: 'TCP',
        },
        size: 1300,
        isOutbound: true,
        sni: 'github.com',
        app: 'GITHUB',
      },
      {
        tuple: {
          src_ip: '192.168.1.100',
          dst_ip: '104.16.85.20',
          src_port: 52344,
          dst_port: 443,
          protocol: 'TCP',
        },
        size: 1200,
        isOutbound: true,
        sni: 'discord.com',
        app: 'DISCORD',
      },
    ];

    for (const packet of samplePackets) {
      this.processPacket(packet);
    }

    this.stop();

    console.log('\nProcessing complete.\n');
    console.log(this.generateReport());
    console.log(this.generateClassificationReport());

    return true;
  }

  /**
   * Start engine
   */
  start() {
    this.running = true;
    this.processingComplete = false;
    this.stats.startTime = new Date();
  }

  /**
   * Stop engine
   */
  stop() {
    this.running = false;
    this.processingComplete = true;
    this.stats.endTime = new Date();
  }

  /**
   * Process a single packet
   */
  processPacket(packet) {
    this.stats.totalPackets++;
    this.stats.bytesProcessed += packet.size || 0;

    const fpId = this.selectFastPath(packet.tuple);
    const tracker = this.trackers[fpId];

    const conn = tracker.getOrCreateConnection(packet.tuple);

    tracker.updateConnection(
      conn,
      packet.size || 0,
      packet.isOutbound || false
    );

    if (packet.sni) {
      tracker.classifyConnection(
        conn,
        packet.app || 'UNKNOWN',
        packet.sni
      );
    }

    const blocked = false;

    if (blocked) {
      tracker.blockConnection(conn);
      this.stats.blockedPackets++;
      console.log(`[BLOCKED] ${packet.sni || 'Unknown'}`);
    } else {
      this.stats.forwardedPackets++;
      console.log(
        `[FORWARDED] ${packet.sni || 'Unknown'} (${packet.app || 'UNKNOWN'})`
      );
    }
  }

  /**
   * Hash tuple to select fast path
   */
  selectFastPath(tuple) {
    const key = JSON.stringify(tuple);
    let hash = 0;

    for (let i = 0; i < key.length; i++) {
      hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
    }

    return hash % this.trackers.length;
  }

  /**
   * Generate engine report
   */
  generateReport() {
    const durationMs =
      this.stats.endTime && this.stats.startTime
        ? this.stats.endTime - this.stats.startTime
        : Date.now() - this.stats.startTime;

    return `
=== DPI Engine Report ===

Packets Processed : ${this.stats.totalPackets}
Packets Forwarded : ${this.stats.forwardedPackets}
Packets Blocked   : ${this.stats.blockedPackets}
Bytes Processed   : ${this.stats.bytesProcessed}
Duration          : ${durationMs} ms

${this.globalConnTable.generateReport()}
`;
  }

  /**
   * Classification report
   */
  generateClassificationReport() {
    const globalStats = this.globalConnTable.getGlobalStats();

    let report = '=== Classification Report ===\n\n';

    for (const [app, count] of Object.entries(
      globalStats.app_distribution || {}
    )) {
      report += `${app}: ${count}\n`;
    }

    return report;
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      running: this.running,
      ...this.globalConnTable.getGlobalStats(),
    };
  }

  /**
   * Print status
   */
  printStatus() {
    console.log(this.generateReport());
  }
}

module.exports = DPIEngine;


/**
 * Run directly:
 * node src/dpiEngine.js
 */
if (require.main === module) {
  (async () => {
    try {
      const engine = new DPIEngine({
        verbose: true,
      });

      const inputFile = path.join(__dirname, '..', 'test_dpi.pcap');

      await engine.processFile(inputFile);
    } catch (error) {
      console.error('Error:', error.message);
    }
  })();
}