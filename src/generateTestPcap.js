// src/generateTestPcap.js
// Run with: node src/generateTestPcap.js

const fs = require("fs");

class PCAPWriter {
  constructor(filename) {
    this.fd = fs.openSync(filename, "w");
    this.timestamp = 1700000000;
    this.writeGlobalHeader();
  }

  writeGlobalHeader() {
    const buffer = Buffer.alloc(24);

    // PCAP Global Header (Little Endian)
    buffer.writeUInt32LE(0xa1b2c3d4, 0); // magic number
    buffer.writeUInt16LE(2, 4);          // version major
    buffer.writeUInt16LE(4, 6);          // version minor
    buffer.writeInt32LE(0, 8);           // timezone
    buffer.writeUInt32LE(0, 12);         // sigfigs
    buffer.writeUInt32LE(65535, 16);     // snaplen
    buffer.writeUInt32LE(1, 20);         // network = Ethernet

    fs.writeSync(this.fd, buffer);
  }

  writePacket(data) {
    const header = Buffer.alloc(16);

    header.writeUInt32LE(this.timestamp, 0);
    header.writeUInt32LE(Math.floor(Math.random() * 1000000), 4);
    header.writeUInt32LE(data.length, 8);
    header.writeUInt32LE(data.length, 12);

    fs.writeSync(this.fd, header);
    fs.writeSync(this.fd, data);

    this.timestamp += 1;
  }

  close() {
    fs.closeSync(this.fd);
  }
}

// ================= Utility Functions =================

function ipToBuffer(ip) {
  return Buffer.from(ip.split(".").map(Number));
}

function macToBuffer(mac) {
  return Buffer.from(mac.replace(/:/g, ""), "hex");
}

function createEthernetHeader(srcMac, dstMac, ethertype = 0x0800) {
  const buffer = Buffer.alloc(14);

  macToBuffer(dstMac).copy(buffer, 0);
  macToBuffer(srcMac).copy(buffer, 6);
  buffer.writeUInt16BE(ethertype, 12);

  return buffer;
}

function createIPHeader(srcIP, dstIP, protocol, payloadLength) {
  const buffer = Buffer.alloc(20);

  buffer[0] = 0x45; // Version + IHL
  buffer[1] = 0x00; // TOS
  buffer.writeUInt16BE(20 + payloadLength, 2);
  buffer.writeUInt16BE(Math.floor(Math.random() * 65535), 4);
  buffer.writeUInt16BE(0x4000, 6); // Don't Fragment
  buffer[8] = 64; // TTL
  buffer[9] = protocol;
  buffer.writeUInt16BE(0, 10); // checksum (ignored)

  ipToBuffer(srcIP).copy(buffer, 12);
  ipToBuffer(dstIP).copy(buffer, 16);

  return buffer;
}

function createTCPHeader(srcPort, dstPort, seq, ack, flags) {
  const buffer = Buffer.alloc(20);

  buffer.writeUInt16BE(srcPort, 0);
  buffer.writeUInt16BE(dstPort, 2);
  buffer.writeUInt32BE(seq, 4);
  buffer.writeUInt32BE(ack, 8);

  buffer[12] = 0x50; // Data offset = 5
  buffer[13] = flags;

  buffer.writeUInt16BE(65535, 14); // window
  buffer.writeUInt16BE(0, 16);     // checksum
  buffer.writeUInt16BE(0, 18);     // urgent pointer

  return buffer;
}

function createUDPHeader(srcPort, dstPort, payloadLength) {
  const buffer = Buffer.alloc(8);

  buffer.writeUInt16BE(srcPort, 0);
  buffer.writeUInt16BE(dstPort, 2);
  buffer.writeUInt16BE(8 + payloadLength, 4);
  buffer.writeUInt16BE(0, 6);

  return buffer;
}

function createTLSClientHello(sni) {
  const sniBytes = Buffer.from(sni, "ascii");

  const sniEntry = Buffer.alloc(3 + sniBytes.length);
  sniEntry[0] = 0;
  sniEntry.writeUInt16BE(sniBytes.length, 1);
  sniBytes.copy(sniEntry, 3);

  const sniList = Buffer.alloc(2 + sniEntry.length);
  sniList.writeUInt16BE(sniEntry.length, 0);
  sniEntry.copy(sniList, 2);

  const sniExt = Buffer.alloc(4 + sniList.length);
  sniExt.writeUInt16BE(0x0000, 0);
  sniExt.writeUInt16BE(sniList.length, 2);
  sniList.copy(sniExt, 4);

  const extensions = sniExt;
  const extensionsData = Buffer.alloc(2 + extensions.length);
  extensionsData.writeUInt16BE(extensions.length, 0);
  extensions.copy(extensionsData, 2);

  const randomBytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    randomBytes[i] = Math.floor(Math.random() * 256);
  }

  const clientVersion = Buffer.from([0x03, 0x03]);
  const sessionId = Buffer.from([0x00]);
  const cipherSuites = Buffer.from([
    0x00, 0x02, // length
    0x13, 0x01  // TLS_AES_128_GCM_SHA256
  ]);
  const compression = Buffer.from([0x01, 0x00]);

  const body = Buffer.concat([
    clientVersion,
    randomBytes,
    sessionId,
    cipherSuites,
    compression,
    extensionsData
  ]);

  const handshakeHeader = Buffer.alloc(4);
  handshakeHeader[0] = 0x01; // Client Hello
  handshakeHeader.writeUIntBE(body.length, 1, 3);

  const handshake = Buffer.concat([handshakeHeader, body]);

  const recordHeader = Buffer.alloc(5);
  recordHeader[0] = 0x16; // Handshake
  recordHeader.writeUInt16BE(0x0301, 1);
  recordHeader.writeUInt16BE(handshake.length, 3);

  return Buffer.concat([recordHeader, handshake]);
}

function createHTTPRequest(host) {
  return Buffer.from(
    `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: DPI-Test/1.0\r\n\r\n`
  );
}

function createDNSQuery(domain) {
  const labels = domain.split(".");
  const parts = [];

  for (const label of labels) {
    const buf = Buffer.alloc(1 + label.length);
    buf[0] = label.length;
    buf.write(label, 1);
    parts.push(buf);
  }

  parts.push(Buffer.from([0x00])); // end
  parts.push(Buffer.from([0x00, 0x01, 0x00, 0x01])); // Type A, Class IN

  const question = Buffer.concat(parts);

  const header = Buffer.alloc(12);
  header.writeUInt16BE(Math.floor(Math.random() * 65535), 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4); // QDCOUNT

  return Buffer.concat([header, question]);
}

// ================= Main =================

function main() {
  const writer = new PCAPWriter("test_dpi.pcap");

  const userMac = "00:11:22:33:44:55";
  const gatewayMac = "aa:bb:cc:dd:ee:ff";
  const userIP = "192.168.1.100";

  const tlsConnections = [
    ["142.250.185.206", "www.google.com", 443],
    ["142.250.185.110", "www.youtube.com", 443],
    ["157.240.1.35", "www.facebook.com", 443],
    ["140.82.114.4", "github.com", 443],
    ["104.16.85.20", "discord.com", 443],
  ];

  let seq = 1000;

  // TLS packets
  for (const [dstIP, sni, dstPort] of tlsConnections) {
    const srcPort = 50000 + Math.floor(Math.random() * 10000);

    const eth = createEthernetHeader(userMac, gatewayMac);
    const tcp = createTCPHeader(srcPort, dstPort, seq, 0, 0x18);
    const tls = createTLSClientHello(sni);
    const ip = createIPHeader(userIP, dstIP, 6, tcp.length + tls.length);

    writer.writePacket(Buffer.concat([eth, ip, tcp, tls]));

    seq += 10000;
  }

  // HTTP packet
  {
    const dstIP = "93.184.216.34";
    const host = "example.com";
    const srcPort = 52000;

    const eth = createEthernetHeader(userMac, gatewayMac);
    const tcp = createTCPHeader(srcPort, 80, seq, 0, 0x18);
    const http = createHTTPRequest(host);
    const ip = createIPHeader(userIP, dstIP, 6, tcp.length + http.length);

    writer.writePacket(Buffer.concat([eth, ip, tcp, http]));
  }

  // DNS packet
  {
    const dnsData = createDNSQuery("www.google.com");
    const udp = createUDPHeader(53000, 53, dnsData.length);
    const eth = createEthernetHeader(userMac, gatewayMac);
    const ip = createIPHeader(userIP, "8.8.8.8", 17, udp.length + dnsData.length);

    writer.writePacket(Buffer.concat([eth, ip, udp, dnsData]));
  }

  writer.close();

  console.log("Created test_dpi.pcap successfully!");
}

main();