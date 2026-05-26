DPI Engine – Deep Packet Inspection System (Node.js)

A Node.js-based Deep Packet Inspection (DPI) engine that analyzes network packets from PCAP files, performs flow tracking, extracts application-level metadata (SNI / HTTP Host), and applies rule-based filtering to simulate firewall-like behavior.

⚙️ System Overview
PCAP File (Captured Network Traffic)
            │
            ▼
     DPI Engine (Node.js)
            │
 ┌──────────┼──────────┐
 ▼          ▼          ▼
Packet   Flow      Application
Parsing  Tracking   Detection (SNI/HTTP)
            │
            ▼
   Rule-Based Filtering Engine
            │
            ▼
   Analytics + Filtered Output Report
✨ Key Features
📦 PCAP File Parsing in Node.js
🌐 Low-level Packet Decoding (Ethernet → IP → TCP)
🔍 Deep Packet Inspection (TLS SNI Extraction)
🧠 Application Identification (Domain-based classification)
🚫 Rule-based Blocking System (IP / Domain / App)
🔗 5-Tuple Flow Tracking (srcIP, dstIP, srcPort, dstPort, protocol)
⚡ Simulated Multi-worker Pipeline (Async processing model)
📊 Network Traffic Analytics Report Generation
📁 Project Structure
packet-analyzer/
│
├── src/
│   ├── connectionTracker.js   # Flow/state tracking using 5-tuple
│   ├── dpiEngine.js           # Core orchestrator
│   ├── fastPath.js            # Optimized packet path processing
│   ├── loadBalancer.js        # Distributes packets across workers
│   ├── packetParser.js        # Ethernet/IP/TCP parsing logic
│   ├── pcapReader.js          # Reads PCAP file stream
│   ├── ruleManager.js         # Blocking/filtering rules engine
│   ├── sniExtractor.js        # TLS SNI extraction
│   ├── threadSafeQueue.js     # Concurrent queue system
│   ├── platform.js            # Environment abstraction
│   ├── generateTestPcap.js    # Synthetic traffic generator
│   └── types.js               # Shared type definitions
│
├── test_dpi.pcap              # Sample network traffic
├── output.pcap                # Processed output
├── package.json
└── README.md
📊 Sample Output

Your engine generates structured analytics like:

Packets Processed : 4
Packets Forwarded : 4
Packets Blocked   : 0
Bytes Processed   : 5400
Duration          : 4 ms

Application Distribution:
  DISCORD  : 1
  GITHUB   : 1
  FACEBOOK : 1

Top Domains:
  discord.com
  github.com
  facebook.com
🛠️ Tech Stack
Node.js (Core runtime)
Buffer API (Binary packet parsing)
Event-driven architecture
Map / Set data structures
Stream-style processing (simulated pipelines)
🧠 What This Project Demonstrates
Network packet parsing (low-level systems programming)
Understanding of TCP/IP stack
TLS handshake inspection (SNI extraction)
Flow-based state tracking (5-tuple modeling)
Rule-based firewall architecture
Scalable backend pipeline design in Node.js
🚀 Why This Project Stands Out

This project simulates a simplified enterprise-grade DPI system, similar in concept to:

Network security firewalls
Traffic inspection systems
Intrusion detection systems (IDS)

It demonstrates the ability to design low-level systems in a high-level runtime (Node.js).