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

## 📂 Repository Structure

All payloads are organized in separate markdown files for easy reference:
payloads/
├── README.md # You are here
├── sqli.md # SQL Injection payloads
├── xss.md # Cross-Site Scripting payloads
├── command-injection.md # OS Command Injection
├── ssrf.md # Server-Side Request Forgery
├── lfi-path-traversal.md # LFI & Path Traversal
├── xxe.md # XML External Entity
├── ssti.md # Server-Side Template Injection
├── open-redirect.md # Open Redirect
├── auth-bypass.md # Authentication Bypass
├── idor.md # IDOR / BOLA
├── http-smuggling.md # HTTP Request Smuggling
├── crlf.md # CRLF Injection
├── cors.md # CORS Misconfiguration
├── jwt.md # JWT Attacks
├── deserialization.md # Insecure Deserialization
├── graphql.md # GraphQL Attacks
├── host-header.md # Host Header Injection
├── csv-injection.md # CSV Injection
├── mass-assignment.md # Mass Assignment
├── log4shell.md # Log4Shell (JNDI)
├── ldap.md # LDAP Injection
├── xpath.md # XPATH Injection
├── email-injection.md # Email Header Injection
├── websocket.md # WebSocket Attacks
├── race-condition.md # Race Condition (TOCTOU)
└── api-specific.md # API Testing Payloads


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
