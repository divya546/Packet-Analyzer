// types.js
// Core shared types for the DPI Engine

/**
 * ==========================================================
 * FiveTuple
 * Uniquely identifies a network flow/connection
 * ==========================================================
 */
class FiveTuple {
  constructor(srcIp, dstIp, srcPort, dstPort, protocol) {
    this.src_ip = srcIp;
    this.dst_ip = dstIp;
    this.src_port = srcPort;
    this.dst_port = dstPort;
    this.protocol = protocol;
  }

  /**
   * Check equality with another tuple
   */
  equals(other) {
    return (
      this.src_ip === other.src_ip &&
      this.dst_ip === other.dst_ip &&
      this.src_port === other.src_port &&
      this.dst_port === other.dst_port &&
      this.protocol === other.protocol
    );
  }

  /**
   * Reverse flow direction
   */
  reverse() {
    return new FiveTuple(
      this.dst_ip,
      this.src_ip,
      this.dst_port,
      this.src_port,
      this.protocol
    );
  }

  /**
   * Convert to unique string key
   */
  toString() {
    return `${this.src_ip}:${this.src_port}->${this.dst_ip}:${this.dst_port}/${this.protocol}`;
  }
}

/**
 * Hash function equivalent for JS
 */
function hashFiveTuple(tuple) {
  const str = tuple.toString();
  let hash = 0;

  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) >>> 0;
  }

  return hash;
}

/**
 * ==========================================================
 * Application Types
 * ==========================================================
 */
const AppType = {
  UNKNOWN: 'UNKNOWN',
  HTTP: 'HTTP',
  HTTPS: 'HTTPS',
  DNS: 'DNS',
  TLS: 'TLS',
  QUIC: 'QUIC',

  GOOGLE: 'GOOGLE',
  FACEBOOK: 'FACEBOOK',
  YOUTUBE: 'YOUTUBE',
  TWITTER: 'TWITTER',
  INSTAGRAM: 'INSTAGRAM',
  NETFLIX: 'NETFLIX',
  AMAZON: 'AMAZON',
  MICROSOFT: 'MICROSOFT',
  APPLE: 'APPLE',
  WHATSAPP: 'WHATSAPP',
  TELEGRAM: 'TELEGRAM',
  TIKTOK: 'TIKTOK',
  SPOTIFY: 'SPOTIFY',
  ZOOM: 'ZOOM',
  DISCORD: 'DISCORD',
  GITHUB: 'GITHUB',
  CLOUDFLARE: 'CLOUDFLARE',
};

function appTypeToString(type) {
  return type || AppType.UNKNOWN;
}

/**
 * Map SNI/domain to AppType
 */
function sniToAppType(sni = '') {
  const domain = sni.toLowerCase();

  if (domain.includes('google')) return AppType.GOOGLE;
  if (domain.includes('youtube')) return AppType.YOUTUBE;
  if (domain.includes('facebook')) return AppType.FACEBOOK;
  if (domain.includes('instagram')) return AppType.INSTAGRAM;
  if (domain.includes('twitter') || domain.includes('x.com'))
    return AppType.TWITTER;
  if (domain.includes('netflix')) return AppType.NETFLIX;
  if (domain.includes('amazon')) return AppType.AMAZON;
  if (domain.includes('microsoft')) return AppType.MICROSOFT;
  if (domain.includes('apple')) return AppType.APPLE;
  if (domain.includes('whatsapp')) return AppType.WHATSAPP;
  if (domain.includes('telegram')) return AppType.TELEGRAM;
  if (domain.includes('tiktok')) return AppType.TIKTOK;
  if (domain.includes('spotify')) return AppType.SPOTIFY;
  if (domain.includes('zoom')) return AppType.ZOOM;
  if (domain.includes('discord')) return AppType.DISCORD;
  if (domain.includes('github')) return AppType.GITHUB;
  if (domain.includes('cloudflare')) return AppType.CLOUDFLARE;

  return AppType.UNKNOWN;
}

/**
 * ==========================================================
 * Connection State
 * ==========================================================
 */
const ConnectionState = {
  NEW: 'NEW',
  ESTABLISHED: 'ESTABLISHED',
  CLASSIFIED: 'CLASSIFIED',
  BLOCKED: 'BLOCKED',
  CLOSED: 'CLOSED',
};

/**
 * ==========================================================
 * Packet Action
 * ==========================================================
 */
const PacketAction = {
  FORWARD: 'FORWARD',
  DROP: 'DROP',
  INSPECT: 'INSPECT',
  LOG_ONLY: 'LOG_ONLY',
};

/**
 * ==========================================================
 * Connection
 * ==========================================================
 */
class Connection {
  constructor(tuple) {
    this.tuple = tuple;
    this.state = ConnectionState.NEW;
    this.app_type = AppType.UNKNOWN;
    this.sni = '';

    this.packets_in = 0;
    this.packets_out = 0;
    this.bytes_in = 0;
    this.bytes_out = 0;

    this.first_seen = Date.now();
    this.last_seen = Date.now();

    this.action = PacketAction.FORWARD;

    // TCP state flags
    this.syn_seen = false;
    this.syn_ack_seen = false;
    this.fin_seen = false;
  }
}

/**
 * ==========================================================
 * PacketJob
 * ==========================================================
 */
class PacketJob {
  constructor() {
    this.packet_id = 0;
    this.tuple = null;
    this.data = Buffer.alloc(0);

    this.eth_offset = 0;
    this.ip_offset = 0;
    this.transport_offset = 0;
    this.payload_offset = 0;
    this.payload_length = 0;

    this.tcp_flags = 0;
    this.payload_data = null;

    this.ts_sec = 0;
    this.ts_usec = 0;
  }
}

/**
 * ==========================================================
 * DPI Statistics
 * ==========================================================
 */
class DPIStats {
  constructor() {
    this.total_packets = 0;
    this.total_bytes = 0;
    this.forwarded_packets = 0;
    this.dropped_packets = 0;
    this.tcp_packets = 0;
    this.udp_packets = 0;
    this.other_packets = 0;
    this.active_connections = 0;
  }
}

module.exports = {
  FiveTuple,
  hashFiveTuple,

  AppType,
  appTypeToString,
  sniToAppType,

  ConnectionState,
  PacketAction,

  Connection,
  PacketJob,
  DPIStats,
};