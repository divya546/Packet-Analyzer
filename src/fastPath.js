// fastPath.js

const { ConnectionTracker } = require('./connectionTracker');

/**
 * PacketAction Enum
 */
const PacketAction = {
  FORWARD: 'FORWARD',
  DROP: 'DROP',
  BLOCK: 'BLOCK',
};

/**
 * ============================================================================
 * Fast Path Processor
 * ============================================================================
 *
 * Each FastPathProcessor:
 * 1. Receives packets
 * 2. Tracks connections
 * 3. Extracts SNI / HTTP Host
 * 4. Applies rules
 * 5. Forwards or drops packets
 */
class FastPathProcessor {
  /**
   * @param {number} fpId
   * @param {RuleManager} ruleManager
   * @param {Function} outputCallback (job, action) => void
   */
  constructor(fpId, ruleManager, outputCallback) {
    this.fpId = fpId;

    // Per-FP connection tracker
    this.connTracker = new ConnectionTracker(fpId);

    // Shared rule manager
    this.ruleManager = ruleManager;

    // Callback when packet is forwarded/dropped
    this.outputCallback = outputCallback;

    // Simple JS queue
    this.inputQueue = [];

    // Stats
    this.stats = {
      packets_processed: 0,
      packets_forwarded: 0,
      packets_dropped: 0,
      connections_tracked: 0,
      sni_extractions: 0,
      classification_hits: 0,
    };

    this.running = false;
    this.processing = false;
  }

  /**
   * Start processing
   */
  start() {
    this.running = true;
    this.run();
  }

  /**
   * Stop processing
   */
  stop() {
    this.running = false;
  }

  /**
   * Push packet into queue
   */
  enqueue(job) {
    this.inputQueue.push(job);
  }

  /**
   * Get input queue
   */
  getInputQueue() {
    return this.inputQueue;
  }

  /**
   * Get connection tracker
   */
  getConnectionTracker() {
    return this.connTracker;
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      connections_tracked: this.connTracker.getActiveCount(),
    };
  }

  /**
   * Get FP ID
   */
  getId() {
    return this.fpId;
  }

  /**
   * Check if running
   */
  isRunning() {
    return this.running;
  }

  /**
   * Main processing loop
   */
  async run() {
    if (this.processing) return;
    this.processing = true;

    while (this.running) {
      if (this.inputQueue.length === 0) {
        await new Promise(resolve => setTimeout(resolve, 5));
        continue;
      }

      const job = this.inputQueue.shift();
      const action = this.processPacket(job);

      if (this.outputCallback) {
        this.outputCallback(job, action);
      }
    }

    this.processing = false;
  }

  /**
   * Process a single packet
   */
  processPacket(job) {
    this.stats.packets_processed++;

    const conn = this.connTracker.getOrCreateConnection(job.tuple);

    this.connTracker.updateConnection(
      conn,
      job.size || 0,
      job.isOutbound || false
    );

    // Inspect payload
    this.inspectPayload(job, conn);

    // Apply rules
    const action = this.checkRules(job, conn);

    if (action === PacketAction.FORWARD) {
      this.stats.packets_forwarded++;
    } else {
      this.stats.packets_dropped++;
    }

    return action;
  }

  /**
   * Inspect packet payload for classification
   */
  inspectPayload(job, conn) {
    if (this.tryExtractSNI(job, conn)) {
      this.stats.sni_extractions++;
      this.stats.classification_hits++;
      return;
    }

    if (this.tryExtractHTTPHost(job, conn)) {
      this.stats.classification_hits++;
    }
  }

  /**
   * Extract SNI from TLS Client Hello
   */
  tryExtractSNI(job, conn) {
    if (!job.sni) return false;

    this.connTracker.classifyConnection(
      conn,
      job.app || 'TLS',
      job.sni
    );

    return true;
  }

  /**
   * Extract Host from HTTP request
   */
  tryExtractHTTPHost(job, conn) {
    if (!job.host) return false;

    this.connTracker.classifyConnection(
      conn,
      job.app || 'HTTP',
      job.host
    );

    return true;
  }

  /**
   * Check blocking rules
   */
  checkRules(job, conn) {
    // If RuleManager implemented
    if (this.ruleManager?.shouldBlock) {
      const shouldBlock = this.ruleManager.shouldBlock(
        job,
        conn
      );

      if (shouldBlock) {
        this.connTracker.blockConnection(conn);
        return PacketAction.BLOCK;
      }
    }

    return PacketAction.FORWARD;
  }

  /**
   * Update TCP State (placeholder)
   */
  updateTCPState(conn, tcpFlags) {
    // Optional future implementation
  }
}

/**
 * ============================================================================
 * FP Manager
 * ============================================================================
 */
class FPManager {
  /**
   * @param {number} numFps
   * @param {RuleManager} ruleManager
   * @param {Function} outputCallback
   */
  constructor(numFps, ruleManager, outputCallback) {
    this.fps = [];

    for (let i = 0; i < numFps; i++) {
      this.fps.push(
        new FastPathProcessor(
          i,
          ruleManager,
          outputCallback
        )
      );
    }
  }

  /**
   * Start all FP processors
   */
  startAll() {
    for (const fp of this.fps) {
      fp.start();
    }
  }

  /**
   * Stop all FP processors
   */
  stopAll() {
    for (const fp of this.fps) {
      fp.stop();
    }
  }

  /**
   * Get FP by ID
   */
  getFP(id) {
    return this.fps[id];
  }

  /**
   * Get queue of a specific FP
   */
  getFPQueue(id) {
    return this.fps[id].getInputQueue();
  }

  /**
   * Get all queue references
   */
  getQueuePtrs() {
    return this.fps.map(fp => fp.getInputQueue());
  }

  /**
   * Get number of FPs
   */
  getNumFPs() {
    return this.fps.length;
  }

  /**
   * Get aggregated stats
   */
  getAggregatedStats() {
    const aggregated = {
      total_processed: 0,
      total_forwarded: 0,
      total_dropped: 0,
      total_connections: 0,
    };

    for (const fp of this.fps) {
      const stats = fp.getStats();

      aggregated.total_processed += stats.packets_processed;
      aggregated.total_forwarded += stats.packets_forwarded;
      aggregated.total_dropped += stats.packets_dropped;
      aggregated.total_connections += stats.connections_tracked;
    }

    return aggregated;
  }

  /**
   * Generate classification report
   */
  generateClassificationReport() {
    let report = '=== Fast Path Classification Report ===\n\n';

    for (const fp of this.fps) {
      const stats = fp.getStats();

      report += `FP ${fp.getId()}:\n`;
      report += `  Processed: ${stats.packets_processed}\n`;
      report += `  Forwarded: ${stats.packets_forwarded}\n`;
      report += `  Dropped: ${stats.packets_dropped}\n`;
      report += `  SNI Extractions: ${stats.sni_extractions}\n`;
      report += `  Classification Hits: ${stats.classification_hits}\n\n`;
    }

    return report;
  }
}

module.exports = {
  FastPathProcessor,
  FPManager,
  PacketAction,
};