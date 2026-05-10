// loadBalancer.js

/**
 * Convert FiveTuple to hashable string key
 */
function tupleToKey(tuple) {
  return `${tuple.srcIP}:${tuple.srcPort}-${tuple.dstIP}:${tuple.dstPort}-${tuple.protocol}`;
}

/**
 * Simple hash function
 */
function hashString(str) {
  let hash = 0;

  for (let i = 0; i < str.length; i++) {
    hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
  }

  return hash;
}

/**
 * ============================================================================
 * LoadBalancer
 * ============================================================================
 *
 * Reader -> LB Queue -> LoadBalancer -> FP Queues
 */
class LoadBalancer {
  /**
   * @param {number} lbId
   * @param {Array<FastPathProcessor>} fpQueues
   * @param {number} fpStartId
   */
  constructor(lbId, fpQueues, fpStartId = 0) {
    this.lbId = lbId;
    this.fpStartId = fpStartId;
    this.fpQueues = fpQueues;
    this.numFps = fpQueues.length;

    // Input queue from reader
    this.inputQueue = [];

    // Statistics
    this.stats = {
      packets_received: 0,
      packets_dispatched: 0,
      per_fp_packets: new Array(this.numFps).fill(0),
    };

    // Control
    this.running = false;
    this.processing = false;
  }

  /**
   * Start LB loop
   */
  start() {
    this.running = true;
    this.run();
  }

  /**
   * Stop LB loop
   */
  stop() {
    this.running = false;
  }

  /**
   * Add packet to LB input queue
   */
  enqueue(packetJob) {
    this.inputQueue.push(packetJob);
  }

  /**
   * Get input queue
   */
  getInputQueue() {
    return this.inputQueue;
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
    };
  }

  /**
   * Get LB ID
   */
  getId() {
    return this.lbId;
  }

  /**
   * Check if running
   */
  isRunning() {
    return this.running;
  }

  /**
   * Main loop
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
      this.stats.packets_received++;

      const localFpIndex = this.selectFP(job.tuple);
      const targetFP = this.fpQueues[localFpIndex];

      // Push packet to FP queue
      if (typeof targetFP.enqueue === 'function') {
        targetFP.enqueue(job);
      } else if (Array.isArray(targetFP)) {
        targetFP.push(job);
      }

      this.stats.packets_dispatched++;
      this.stats.per_fp_packets[localFpIndex]++;
    }

    this.processing = false;
  }

  /**
   * Determine target FP using consistent hashing
   */
  selectFP(tuple) {
    const key = tupleToKey(tuple);
    const hash = hashString(key);

    return hash % this.numFps;
  }
}

/**
 * ============================================================================
 * LBManager
 * ============================================================================
 */
class LBManager {
  /**
   * @param {number} numLbs
   * @param {number} fpsPerLb
   * @param {Array<FastPathProcessor>} fpProcessors
   */
  constructor(numLbs, fpsPerLb, fpProcessors) {
    this.lbs = [];
    this.fpsPerLb = fpsPerLb;

    for (let i = 0; i < numLbs; i++) {
      const start = i * fpsPerLb;
      const end = start + fpsPerLb;

      const assignedFps = fpProcessors.slice(start, end);

      this.lbs.push(
        new LoadBalancer(i, assignedFps, start)
      );
    }
  }

  /**
   * Start all LBs
   */
  startAll() {
    for (const lb of this.lbs) {
      lb.start();
    }
  }

  /**
   * Stop all LBs
   */
  stopAll() {
    for (const lb of this.lbs) {
      lb.stop();
    }
  }

  /**
   * Select LB for a packet
   */
  getLBForPacket(tuple) {
    const key = tupleToKey(tuple);
    const hash = hashString(key);

    const lbIndex = hash % this.lbs.length;
    return this.lbs[lbIndex];
  }

  /**
   * Get specific LB
   */
  getLB(id) {
    return this.lbs[id];
  }

  /**
   * Get number of LBs
   */
  getNumLBs() {
    return this.lbs.length;
  }

  /**
   * Get aggregated stats
   */
  getAggregatedStats() {
    const aggregated = {
      total_received: 0,
      total_dispatched: 0,
    };

    for (const lb of this.lbs) {
      const stats = lb.getStats();

      aggregated.total_received += stats.packets_received;
      aggregated.total_dispatched += stats.packets_dispatched;
    }

    return aggregated;
  }
}

module.exports = {
  LoadBalancer,
  LBManager,
  tupleToKey,
  hashString,
};