# YogSec Payload Universe

**Your Complete Arsenal for Bug Bounty & Penetration Testing**

[![GitHub stars](https://img.shields.io/github/stars/yogsec/payloads?style=social)](https://github.com/yogsec/payloads/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/yogsec/payloads?style=social)](https://github.com/yogsec/payloads/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yogsec/payloads/graphs/commit-activity)

> **⚠️ LEGAL DISCLAIMER:** This repository is for **educational purposes only**. All payloads and techniques described here are meant for authorized security testing, CTF competitions, and learning. Unauthorized access to computer systems is illegal. Use responsibly and only on systems you own or have explicit permission to test.

## 📋 Purpose

This repository serves as a **comprehensive, battle-tested payload collection** for bug bounty hunters, penetration testers, and security researchers. Every payload here has been curated from real-world findings, CTF solutions, and proven bypass techniques.

### Why this repo exists:
- 🎯 **One-stop resource** for all vulnerability testing scenarios
- ⚡ **Ready-to-use payloads** for quick copy-paste during assessments
- 🔬 **Categorized by attack type** for efficient searching
- 🛡️ **Includes bypass techniques** for WAF and filters
- 📚 **Continuously updated** with new vectors and techniques

---
```
## 📂 Repository Structure

https://github.com/yogsec/payloads/
│
├── README.md                          # Main documentation (already provided above)
│
├── 📂 Tier 1: Core Essentials
│   ├── sqli.md                        # SQL Injection payloads
│   ├── xss.md                         # Cross-Site Scripting payloads
│   ├── command-injection.md           # OS Command Injection payloads
│   ├── ssrf.md                        # Server-Side Request Forgery payloads
│   ├── lfi-path-traversal.md          # LFI & Path Traversal payloads
│   ├── xxe.md                         # XML External Entity payloads
│   ├── ssti.md                        # Server-Side Template Injection payloads
│   ├── open-redirect.md               # Open Redirect payloads
│   ├── auth-bypass.md                 # Authentication Bypass payloads
│   └── idor.md                        # IDOR / BOLA payloads
│
├── 📂 Tier 2: Advanced Arsenal
│   ├── http-smuggling.md              # HTTP Request Smuggling payloads
│   ├── crlf.md                        # CRLF Injection payloads
│   ├── cors.md                        # CORS Misconfiguration payloads
│   ├── jwt.md                         # JWT Attacks payloads
│   ├── deserialization.md             # Insecure Deserialization payloads
│   ├── graphql.md                     # GraphQL Attacks payloads
│   ├── host-header.md                 # Host Header Injection payloads
│   ├── csv-injection.md               # CSV Injection payloads
│   ├── mass-assignment.md             # Mass Assignment payloads
│   └── log4shell.md                   # Log4Shell (JNDI) payloads
│
└── 📂 Tier 3: Specialized & Niche
    ├── ldap.md                        # LDAP Injection payloads
    ├── xpath.md                       # XPATH Injection payloads
    ├── email-injection.md             # Email Header Injection payloads
    ├── websocket.md                   # WebSocket Attacks payloads
    ├── race-condition.md              # Race Condition (TOCTOU) payloads
    └── api-specific.md                # API Testing payloads
```
---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/yogsec/payloads.git
cd payloads

---

# Example: Search for SQLi payloads
cat sqli.md | grep "Union"

# Example: Find XSS bypass techniques
cat xss.md | grep "bypass"
