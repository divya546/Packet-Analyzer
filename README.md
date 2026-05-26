# DPI Engine – Deep Packet Inspection System

A simplified Deep Packet Inspection (DPI) engine built using Node.js that analyzes packets from PCAP files, performs flow tracking, extracts TLS SNI / HTTP Host information, and applies rule-based filtering similar to a basic firewall system.

---

# Overview

```text
PCAP File
    │
    ▼
DPI Engine
    │
 ┌──┼───────────────┐
 ▼  ▼               ▼
Packet Parsing   Flow Tracking   App Detection
(Ethernet/IP/TCP) (5-Tuple)      (SNI / HTTP Host)
    │
    ▼
Rule-Based Filtering
    │
    ▼
Traffic Analytics Report
Features
PCAP File Parsing in Node.js
Ethernet / IPv4 / TCP Packet Decoding
TLS SNI Extraction
HTTP Host Detection
5-Tuple Flow Tracking
Rule-Based Packet Filtering
Application Identification
Simulated Multi-worker Processing Pipeline
Traffic Analytics & Reporting
Tech Stack
Node.js
JavaScript
Buffer API
Event-driven Architecture
Async Processing
Project Structure
packet-analyzer/
│
├── src/
│   ├── connectionTracker.js
│   ├── dpiEngine.js
│   ├── fastPath.js
│   ├── loadBalancer.js
│   ├── packetParser.js
│   ├── pcapReader.js
│   ├── ruleManager.js
│   ├── sniExtractor.js
│   ├── threadSafeQueue.js
│   ├── platform.js
│   ├── generateTestPcap.js
│   └── types.js
│
├── test_dpi.pcap
├── output.pcap
├── package.json
└── README.md
How It Works
Reads packets from a PCAP file
Parses Ethernet, IP, and TCP headers
Extracts TLS SNI or HTTP Host information
Tracks flows using the 5-tuple:
Source IP
Destination IP
Source Port
Destination Port
Protocol
Classifies applications/domains
Applies filtering rules
Generates analytics report
Sample Output
Initialized DPI Engine with 4 Fast Path processors

[FORWARDED] www.google.com (GOOGLE)
[FORWARDED] github.com (GITHUB)
[FORWARDED] discord.com (DISCORD)

=== DPI Engine Report ===

Packets Processed : 4
Packets Forwarded : 4
Packets Blocked   : 0
Bytes Processed   : 5400
Duration          : 4 ms
Applications Detected
Google
GitHub
Discord
Facebook


Concepts Used:-

TCP/IP Networking
Packet Parsing
Deep Packet Inspection (DPI)
TLS Handshake Inspection
SNI Extraction
Flow Tracking
Rule-Based Filtering
Queue-based Processing
Run the Project
Install Dependencies
npm install
Run DPI Engine
node src/dpiEngine.js
Purpose of the Project

# This project was built to understand:

How packet analyzers work?
How DPI systems inspect traffic?
How applications can be identified from packets?

Basic firewall-style filtering logic
Low-level networking concepts using Node.js
Future Improvements
Real-time packet capture
UDP & DNS parsing
Better protocol detection
Advanced filtering rules
Dashboard for analytics
Worker Threads for true parallelism