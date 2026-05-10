// threadSafeQueue.js
// Promise-based thread-safe queue for Node.js

class ThreadSafeQueue {
  /**
   * @param {number} maxSize Maximum number of items allowed in queue
   */
  constructor(maxSize = 10000) {
    this.maxSize = maxSize;

    // Actual queue storage
    this.queue = [];

    // Shutdown flag
    this.shutdownFlag = false;

    // Waiting consumers (pop)
    this.waitingConsumers = [];

    // Waiting producers (push when queue is full)
    this.waitingProducers = [];
  }

  /**
   * Push item into queue (waits if queue is full)
   * @param {*} item
   */
  async push(item) {
    if (this.shutdownFlag) return;

    // If a consumer is already waiting, deliver immediately
    if (this.waitingConsumers.length > 0) {
      const resolve = this.waitingConsumers.shift();
      resolve(item);
      return;
    }

    // If queue has room, insert directly
    if (this.queue.length < this.maxSize) {
      this.queue.push(item);
      return;
    }

    // Queue full -> wait until space becomes available
    await new Promise(resolve => {
      this.waitingProducers.push({ item, resolve });
    });
  }

  /**
   * Try to push without waiting
   * @param {*} item
   * @returns {boolean}
   */
  tryPush(item) {
    if (this.shutdownFlag) return false;

    // Immediate delivery to waiting consumer
    if (this.waitingConsumers.length > 0) {
      const resolve = this.waitingConsumers.shift();
      resolve(item);
      return true;
    }

    if (this.queue.length >= this.maxSize) {
      return false;
    }

    this.queue.push(item);
    return true;
  }

  /**
   * Pop item from queue (waits if empty)
   * @returns {Promise<*>}
   */
  async pop() {
    // Existing item available
    if (this.queue.length > 0) {
      const item = this.queue.shift();
      this._releaseProducer();
      return item;
    }

    // Shutdown and no data
    if (this.shutdownFlag) {
      return null;
    }

    // Wait for future item
    return new Promise(resolve => {
      this.waitingConsumers.push(resolve);
    });
  }

  /**
   * Pop with timeout
   * @param {number} timeoutMs
   * @returns {Promise<*>} item or null on timeout
   */
  async popWithTimeout(timeoutMs) {
    // Immediate item available
    if (this.queue.length > 0) {
      const item = this.queue.shift();
      this._releaseProducer();
      return item;
    }

    if (this.shutdownFlag) {
      return null;
    }

    return new Promise(resolve => {
      const consumer = item => {
        clearTimeout(timer);
        resolve(item);
      };

      this.waitingConsumers.push(consumer);

      const timer = setTimeout(() => {
        const index = this.waitingConsumers.indexOf(consumer);
        if (index !== -1) {
          this.waitingConsumers.splice(index, 1);
        }
        resolve(null);
      }, timeoutMs);
    });
  }

  /**
   * Check if queue is empty
   */
  empty() {
    return this.queue.length === 0;
  }

  /**
   * Current queue size
   */
  size() {
    return this.queue.length;
  }

  /**
   * Shutdown queue and wake all waiting operations
   */
  shutdown() {
    this.shutdownFlag = true;

    // Wake consumers with null
    while (this.waitingConsumers.length > 0) {
      const resolve = this.waitingConsumers.shift();
      resolve(null);
    }

    // Wake producers
    while (this.waitingProducers.length > 0) {
      const producer = this.waitingProducers.shift();
      producer.resolve();
    }
  }

  /**
   * Check if shutdown has been triggered
   */
  isShutdown() {
    return this.shutdownFlag;
  }

  /**
   * Move one waiting producer into queue if possible
   * @private
   */
  _releaseProducer() {
    if (
      this.waitingProducers.length > 0 &&
      this.queue.length < this.maxSize &&
      !this.shutdownFlag
    ) {
      const { item, resolve } = this.waitingProducers.shift();

      // Deliver directly to waiting consumer if present
      if (this.waitingConsumers.length > 0) {
        const consumerResolve = this.waitingConsumers.shift();
        consumerResolve(item);
      } else {
        this.queue.push(item);
      }

      resolve();
    }
  }
}

module.exports = ThreadSafeQueue;