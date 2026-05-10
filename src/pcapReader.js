// pcapReader.js
// Reads .pcap files in Node.js

const fs = require('fs');

/**
 * PCAP magic numbers
 */
const PCAP_MAGIC = {
  LITTLE_ENDIAN: 0xa1b2c3d4,
  BIG_ENDIAN: 0xd4c3b2a1,
};

/**
 * Represents one packet from the pcap file
 */
class RawPacket {
  constructor(header, data) {
    this.header = header;
    this.data = data; // Buffer
  }
}

/**
 * PcapReader
 */
class PcapReader {
  constructor() {
    this.buffer = null;
    this.offset = 0;

    this.globalHeader = null;
    this.needsByteSwap = false;
  }

  /**
   * Open a pcap file
   * @param {string} filename
   * @returns {boolean}
   */
  open(filename) {
    try {
      this.buffer = fs.readFileSync(filename);

      if (this.buffer.length < 24) {
        throw new Error('Invalid PCAP file');
      }

      this.parseGlobalHeader();
      this.offset = 24;

      return true;
    } catch (err) {
      console.error('Failed to open PCAP:', err.message);
      return false;
    }
  }

  /**
   * Close file
   */
  close() {
    this.buffer = null;
    this.offset = 0;
    this.globalHeader = null;
  }

  /**
   * Check if file is open
   */
  isOpen() {
    return this.buffer !== null;
  }

  /**
   * Get global header
   */
  getGlobalHeader() {
    return this.globalHeader;
  }

  /**
   * Parse global header
   */
  parseGlobalHeader() {
    const magicLE = this.buffer.readUInt32LE(0);

    if (magicLE === PCAP_MAGIC.LITTLE_ENDIAN) {
      this.needsByteSwap = false;
    } else if (magicLE === PCAP_MAGIC.BIG_ENDIAN) {
      this.needsByteSwap = true;
    } else {
      throw new Error('Unsupported PCAP format');
    }

    const read16 = (offset) =>
      this.needsByteSwap
        ? this.buffer.readUInt16BE(offset)
        : this.buffer.readUInt16LE(offset);

    const read32 = (offset) =>
      this.needsByteSwap
        ? this.buffer.readUInt32BE(offset)
        : this.buffer.readUInt32LE(offset);

    const readInt32 = (offset) =>
      this.needsByteSwap
        ? this.buffer.readInt32BE(offset)
        : this.buffer.readInt32LE(offset);

    this.globalHeader = {
      magic_number: read32(0),
      version_major: read16(4),
      version_minor: read16(6),
      thiszone: readInt32(8),
      sigfigs: read32(12),
      snaplen: read32(16),
      network: read32(20),
    };
  }

  /**
   * Read next packet
   * @returns {RawPacket|null}
   */
  readNextPacket() {
    if (!this.buffer || this.offset >= this.buffer.length) {
      return null;
    }

    if (this.offset + 16 > this.buffer.length) {
      return null;
    }

    const read32 = (offset) =>
      this.needsByteSwap
        ? this.buffer.readUInt32BE(offset)
        : this.buffer.readUInt32LE(offset);

    const packetHeader = {
      tsSec: read32(this.offset),
      tsUsec: read32(this.offset + 4),
      inclLen: read32(this.offset + 8),
      origLen: read32(this.offset + 12),
    };

    this.offset += 16;

    if (this.offset + packetHeader.inclLen > this.buffer.length) {
      return null;
    }

    const packetData = this.buffer.subarray(
      this.offset,
      this.offset + packetHeader.inclLen
    );

    this.offset += packetHeader.inclLen;

    return new RawPacket(packetHeader, packetData);
  }
}

module.exports = {
  PcapReader,
  RawPacket,
  PCAP_MAGIC,
};