// sniExtractor.js
// Extract SNI from TLS Client Hello, Host header from HTTP,
// and basic DNS query extraction.

class SNIExtractor {
  static CONTENT_TYPE_HANDSHAKE = 0x16;
  static HANDSHAKE_CLIENT_HELLO = 0x01;
  static EXTENSION_SNI = 0x0000;
  static SNI_TYPE_HOSTNAME = 0x00;

  /**
   * Extract SNI hostname from TLS Client Hello.
   * @param {Buffer} payload
   * @returns {string|null}
   */
  static extract(payload) {
    if (!Buffer.isBuffer(payload)) return null;
    if (!this.isTLSClientHello(payload)) return null;

    let offset = 0;

    // TLS Record Header
    offset += 5;

    // Handshake Header
    offset += 1; // handshake type
    offset += 3; // handshake length

    // Client Version
    offset += 2;

    // Random
    offset += 32;

    if (offset >= payload.length) return null;

    // Session ID
    const sessionIdLen = payload[offset];
    offset += 1 + sessionIdLen;

    if (offset + 2 > payload.length) return null;

    // Cipher Suites
    const cipherSuitesLen = this.readUint16BE(payload, offset);
    offset += 2 + cipherSuitesLen;

    if (offset >= payload.length) return null;

    // Compression Methods
    const compressionLen = payload[offset];
    offset += 1 + compressionLen;

    if (offset + 2 > payload.length) return null;

    // Extensions Length
    const extensionsLen = this.readUint16BE(payload, offset);
    offset += 2;

    const extensionsEnd = offset + extensionsLen;

    while (offset + 4 <= extensionsEnd && offset + 4 <= payload.length) {
      const extType = this.readUint16BE(payload, offset);
      const extLen = this.readUint16BE(payload, offset + 2);
      offset += 4;

      if (offset + extLen > payload.length) break;

      if (extType === this.EXTENSION_SNI) {
        // SNI extension structure
        if (offset + 5 > payload.length) return null;

        const serverNameListLen = this.readUint16BE(payload, offset);
        let sniOffset = offset + 2;

        if (sniOffset + 3 > payload.length) return null;

        const nameType = payload[sniOffset];
        sniOffset += 1;

        const nameLen = this.readUint16BE(payload, sniOffset);
        sniOffset += 2;

        if (
          nameType !== this.SNI_TYPE_HOSTNAME ||
          sniOffset + nameLen > payload.length
        ) {
          return null;
        }

        return payload
          .toString('utf8', sniOffset, sniOffset + nameLen)
          .toLowerCase();
      }

      offset += extLen;
    }

    return null;
  }

  /**
   * Check whether payload looks like TLS Client Hello.
   */
  static isTLSClientHello(payload) {
    if (!Buffer.isBuffer(payload)) return false;
    if (payload.length < 6) return false;

    return (
      payload[0] === this.CONTENT_TYPE_HANDSHAKE &&
      payload[5] === this.HANDSHAKE_CLIENT_HELLO
    );
  }

  /**
   * Extract all extension types.
   */
  static extractExtensions(payload) {
    const extensions = [];

    if (!Buffer.isBuffer(payload)) return extensions;
    if (!this.isTLSClientHello(payload)) return extensions;

    // Simplified debug implementation
    const sni = this.extract(payload);
    if (sni) {
      extensions.push([this.EXTENSION_SNI, sni]);
    }

    return extensions;
  }

  static readUint16BE(buffer, offset) {
    return buffer.readUInt16BE(offset);
  }

  static readUint24BE(buffer, offset) {
    return (
      (buffer[offset] << 16) |
      (buffer[offset + 1] << 8) |
      buffer[offset + 2]
    );
  }
}

/**
 * QUIC SNI Extractor (simplified placeholder)
 */
class QUICSNIExtractor {
  static extract(payload) {
    // Full QUIC parsing is complex.
    // Placeholder returns null.
    return null;
  }

  static isQUICInitial(payload) {
    if (!Buffer.isBuffer(payload) || payload.length < 1) return false;

    // QUIC long header starts with bit 0x80 set.
    return (payload[0] & 0x80) !== 0;
  }
}

/**
 * HTTP Host Header Extractor
 */
class HTTPHostExtractor {
  static extract(payload) {
    if (!Buffer.isBuffer(payload)) return null;
    if (!this.isHTTPRequest(payload)) return null;

    const text = payload.toString('utf8');

    const match = text.match(/^Host:\s*(.+)$/im);
    if (!match) return null;

    return match[1].trim().toLowerCase();
  }

  static isHTTPRequest(payload) {
    if (!Buffer.isBuffer(payload)) return false;

    const methods = [
      'GET ',
      'POST ',
      'PUT ',
      'DELETE ',
      'HEAD ',
      'OPTIONS ',
      'PATCH ',
    ];

    const start = payload.toString('utf8', 0, 16);

    return methods.some(method => start.startsWith(method));
  }
}

/**
 * DNS Query Extractor
 */
class DNSExtractor {
  static extractQuery(payload) {
    if (!Buffer.isBuffer(payload)) return null;
    if (!this.isDNSQuery(payload)) return null;

    // DNS header is 12 bytes
    let offset = 12;
    const labels = [];

    while (offset < payload.length) {
      const len = payload[offset];

      if (len === 0) {
        offset++;
        break;
      }

      if (offset + 1 + len > payload.length) {
        return null;
      }

      labels.push(
        payload.toString('utf8', offset + 1, offset + 1 + len)
      );

      offset += 1 + len;
    }

    return labels.join('.').toLowerCase();
  }

  static isDNSQuery(payload) {
    if (!Buffer.isBuffer(payload)) return false;
    if (payload.length < 12) return false;

    const flags = payload.readUInt16BE(2);

    // QR bit = 0 means query
    return (flags & 0x8000) === 0;
  }
}

module.exports = {
  SNIExtractor,
  QUICSNIExtractor,
  HTTPHostExtractor,
  DNSExtractor,
};