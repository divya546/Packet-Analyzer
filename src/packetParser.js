// packetParser.js

/**
 * TCP Flag constants
 */
const TCPFlags = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
};

/**
 * Protocol numbers
 */
const Protocol = {
  ICMP: 1,
  TCP: 6,
  UDP: 17,
};

/**
 * EtherType values
 */
const EtherType = {
  IPv4: 0x0800,
  IPv6: 0x86dd,
  ARP: 0x0806,
};

/**
 * Parsed packet structure
 */
class ParsedPacket {
  constructor() {
    // Timestamp
    this.timestampSec = 0;
    this.timestampUsec = 0;

    // Ethernet layer
    this.srcMac = '';
    this.destMac = '';
    this.etherType = 0;

    // IP layer
    this.hasIp = false;
    this.ipVersion = 0;
    this.srcIp = '';
    this.destIp = '';
    this.protocol = 0;
    this.ttl = 0;

    // Transport layer
    this.hasTcp = false;
    this.hasUdp = false;
    this.srcPort = 0;
    this.destPort = 0;

    // TCP-specific
    this.tcpFlags = 0;
    this.seqNumber = 0;
    this.ackNumber = 0;

    // Payload
    this.payloadLength = 0;
    this.payloadData = null; // Buffer slice
  }
}

/**
 * Packet Parser
 */
class PacketParser {
  /**
   * Parse a raw packet
   * @param {Object} raw
   * @param {Buffer} raw.data
   * @param {Object} raw.header
   * @returns {ParsedPacket|null}
   */
  static parse(raw) {
    const parsed = new ParsedPacket();

    if (raw.header) {
      parsed.timestampSec = raw.header.tsSec || 0;
      parsed.timestampUsec = raw.header.tsUsec || 0;
    }

    const data = raw.data;
    if (!Buffer.isBuffer(data)) {
      return null;
    }

    let offset = 0;

    // Ethernet
    offset = this.parseEthernet(data, parsed, offset);
    if (offset === null) return null;

    // IPv4
    if (parsed.etherType === EtherType.IPv4) {
      offset = this.parseIPv4(data, parsed, offset);
      if (offset === null) return parsed;
    }

    // TCP
    if (parsed.protocol === Protocol.TCP) {
      offset = this.parseTCP(data, parsed, offset);
      if (offset === null) return parsed;
    }

    // UDP
    if (parsed.protocol === Protocol.UDP) {
      offset = this.parseUDP(data, parsed, offset);
      if (offset === null) return parsed;
    }

    // Payload
    if (offset < data.length) {
      parsed.payloadData = data.subarray(offset);
      parsed.payloadLength = data.length - offset;
    }

    return parsed;
  }

  /**
   * Parse Ethernet header
   */
  static parseEthernet(data, parsed, offset) {
    if (data.length < offset + 14) return null;

    parsed.destMac = this.macToString(data.subarray(offset, offset + 6));
    parsed.srcMac = this.macToString(data.subarray(offset + 6, offset + 12));
    parsed.etherType = data.readUInt16BE(offset + 12);

    return offset + 14;
  }

  /**
   * Parse IPv4 header
   */
  static parseIPv4(data, parsed, offset) {
    if (data.length < offset + 20) return null;

    const versionIhl = data[offset];
    const version = versionIhl >> 4;
    const ihl = versionIhl & 0x0f;
    const headerLength = ihl * 4;

    if (version !== 4) return null;
    if (data.length < offset + headerLength) return null;

    parsed.hasIp = true;
    parsed.ipVersion = 4;
    parsed.ttl = data[offset + 8];
    parsed.protocol = data[offset + 9];

    parsed.srcIp = this.ipToString(data.readUInt32BE(offset + 12));
    parsed.destIp = this.ipToString(data.readUInt32BE(offset + 16));

    return offset + headerLength;
  }

  /**
   * Parse TCP header
   */
  static parseTCP(data, parsed, offset) {
    if (data.length < offset + 20) return null;

    parsed.hasTcp = true;
    parsed.srcPort = data.readUInt16BE(offset);
    parsed.destPort = data.readUInt16BE(offset + 2);

    parsed.seqNumber = data.readUInt32BE(offset + 4);
    parsed.ackNumber = data.readUInt32BE(offset + 8);

    const dataOffset = (data[offset + 12] >> 4) * 4;
    parsed.tcpFlags = data[offset + 13];

    return offset + dataOffset;
  }

  /**
   * Parse UDP header
   */
  static parseUDP(data, parsed, offset) {
    if (data.length < offset + 8) return null;

    parsed.hasUdp = true;
    parsed.srcPort = data.readUInt16BE(offset);
    parsed.destPort = data.readUInt16BE(offset + 2);

    return offset + 8;
  }

  /**
   * Convert MAC buffer to string
   */
  static macToString(buf) {
    return Array.from(buf)
      .map(b => b.toString(16).padStart(2, '0'))
      .join(':');
  }

  /**
   * Convert uint32 IP to string
   */
  static ipToString(ip) {
    return [
      (ip >>> 24) & 0xff,
      (ip >>> 16) & 0xff,
      (ip >>> 8) & 0xff,
      ip & 0xff,
    ].join('.');
  }

  /**
   * Protocol number to string
   */
  static protocolToString(protocol) {
    switch (protocol) {
      case Protocol.TCP:
        return 'TCP';
      case Protocol.UDP:
        return 'UDP';
      case Protocol.ICMP:
        return 'ICMP';
      default:
        return `Unknown(${protocol})`;
    }
  }

  /**
   * TCP flags to string
   */
  static tcpFlagsToString(flags) {
    const names = [];

    if (flags & TCPFlags.FIN) names.push('FIN');
    if (flags & TCPFlags.SYN) names.push('SYN');
    if (flags & TCPFlags.RST) names.push('RST');
    if (flags & TCPFlags.PSH) names.push('PSH');
    if (flags & TCPFlags.ACK) names.push('ACK');
    if (flags & TCPFlags.URG) names.push('URG');

    return names.join('|') || 'NONE';
  }
}

module.exports = {
  PacketParser,
  ParsedPacket,
  TCPFlags,
  Protocol,
  EtherType,
};