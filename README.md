# Network Communication & Security Labs (Python)

This repository contains five lab exercises developed during the "Advanced Network Communication" course at Jerusalem College of Technology (Oct 2024 – Feb 2025). The labs are implemented in Python and demonstrate core principles in network programming, communication protocols, and secure transmission techniques.

## Project Overview

### 1. Multi-client Chat Server

A TCP-based server supporting multiple clients concurrently. Includes:
- User registration with unique names
- Private messaging and broadcast messages
- Query for connected client names
- Blocking specific users
- Graceful disconnection
- Custom message framing protocol (length-prefixed)

### 2. DNS Enumeration

A Python script that performs subdomain enumeration and DNS lookups using sockets and optionally Scapy. Useful for identifying accessible subdomains and mapping DNS infrastructure.

### 3. HTTP Server

A minimal HTTP server implemented from scratch using raw sockets. Supports:
- Parsing GET requests
- Serving static content
- Basic 404 response handling

### 4. Secure Socket Communication

Implements a fully custom secure channel over sockets:
- Symmetric encryption using a pedagogical cipher (XOR, LUT, byte rotation)
- Key exchange via Diffie-Hellman
- Hash function to summarize messages
- RSA-based message authentication (MAC)

Communication protocol includes public key exchange and verification of encrypted messages and signatures. Both client and server validate the integrity and origin of messages before processing them.

### 5. SYN Flood Detection (Packet Analysis)

A network forensics tool that analyzes captured traffic (PCAP format) to detect SYN flood attacks. Features:
- Packet-level inspection using Scapy
- Tracks unmatched SYN requests per IP
- Filters and flags IP addresses with potential attack behavior
- Can compare results against a known attacker list

## Technologies Used

- Python 3
- socket, threading, select
- Scapy
- Custom crypto (RSA, XOR, hashing)
- Wireshark (used externally for verification and analysis)
- ipaddress module (for IP range handling)

## Course Reference

These projects were developed as part of the *Advanced Network Communication* course at **Jerusalem College of Technology**, under the instruction of **Barak Gonen**.

## Disclaimer

This repository is intended for educational use only. The SYN flood detection script is designed for passive analysis of captured network traffic. No code here should be used for offensive or unauthorized activity.

## Author

**Esti Rosen**  
Jerusalem College of Technology  
2024–2025

