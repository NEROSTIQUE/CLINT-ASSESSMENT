# CLINT-ASSESSMENT


# Challenge 3

> **Type:** SSRF — Cloud Metadata Exfiltration
> **Endpoint:** `POST /api/v1/fetch-preview` | **Parameter:** `url` | **Cloud Provider:** AWS

---

## Table of Contents

- [Part A — Threat Modelling the Fix](#part-a--threat-modelling-the-fix-25-pts)
  - [Q1 — What is SSRF and why did the original vulnerability allow cloud metadata access?](#q1--what-is-ssrf-and-why-did-the-original-vulnerability-allow-cloud-metadata-access)
  - [Q2 — Five distinct blocklist bypass techniques](#q2--five-distinct-blocklist-bypass-techniques)
  - [Q3 — Three measurable conditions for a successful fix](#q3--three-measurable-conditions-for-a-successful-fix)
  - [Q4 — Does IMDSv2 make the blocklist unnecessary?](#q4--does-imdsv2-make-the-blocklist-unnecessary)
- [Part B — Test Case Design](#part-b--test-case-design-25-pts)
- [Part E — Systems Design Under Pressure](#part-e--Systems-Design-Under-Pressure-10-pts)

---

## Part A — Threat Modelling the Fix (25 pts)

### Q1 — What is SSRF and why did the original vulnerability allow cloud metadata access?

**What is SSRF?**

Server-Side Request Forgery (SSRF) is a security vulnerability in web applications where
an attacker tricks the server into making HTTP requests on their behalf. Those requests
originate from the server's own network context — not from the attacker's location on the
public internet. This makes the server act as a proxy, performing the fetch instead of the
attacker directly. The critical consequence is that the server can reach internal services
that are completely unreachable from the public internet.

**Why did this allow cloud metadata access?**

AWS uses the well-known, non-routable IP address `169.254.169.254` as the Instance Metadata
Service (IMDS). This REST endpoint — accessible only from inside an AWS instance such as an
EC2 virtual machine — exposes details about the running instance including the temporary
access key, secret key, and session token assigned to the instance's IAM role.

**What dangerous assumption did the server make?**

The server made the dangerous assumption that all user-provided URLs would lead to
legitimate, publicly accessible web resources — for example, `https://example.com/image.jpg`.
It did not anticipate a user supplying a URL pointing to an internal or reserved IP address.
As a result, when the attacker submitted
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`, the server executed
the request without any validation, fetched live IAM credentials from the metadata service,
and reflected them back in the API response body.

---

### Q2 — Five distinct blocklist bypass techniques

The client's fix rejects requests **containing the string** `169.254.169.254`. This is a
string-match blocklist, not semantic IP validation. It is trivially bypassed by any encoding
that resolves to the same address without containing that exact string.

#### 1 — Decimal / Octal / Hexadecimal IP Encoding

Most HTTP request libraries and OS network stacks automatically resolve alternative numeric
forms of an IP address to the same destination. A URL such as `http://2852039166/` (decimal),
`http://0xa9fea9fe/` (hex), or `http://0251.0376.0251.0376/` (octal) resolves identically
to `169.254.169.254` without ever containing the blocked string — causing the blocklist
string match to fail entirely.

#### 2 — DNS Rebinding

The attacker registers a domain they control and configures its DNS to initially resolve to
a legitimate IP address (to pass any initial validation check), then rapidly changes the DNS
response to `169.254.169.254` before the server executes the actual request. This is a
timing exploit between URL validation and request execution that redirects the server to IMDS
after the blocklist check has already passed.

#### 3 — Open Redirect / Server-Side Redirect Chaining

If the server follows HTTP redirects automatically (the default in most libraries), an
attacker can provide a URL pointing to an attacker-controlled server that returns a
`301/302 Location: http://169.254.169.254/...` header. The blocklist passes the original
URL (an external domain), and the server then follows the redirect transparently, landing
on IMDS after validation has already completed.

#### 4 — IPv6 Representation

The IPv6-mapped form of the metadata IP — `http://[::ffff:169.254.169.254]/` or its
compressed form `http://[::ffff:a9fe:a9fe]/` — resolves to the same interface space as the
IPv4 metadata address without containing the string `169.254.169.254` anywhere in the URL.
Modern HTTP stacks support IPv6 by default, so a pure IPv4 string-match blocklist provides
no protection against this form.

#### 5 — Alternative Cloud Metadata Endpoints

AWS exposes metadata via `http://169.254.170.2/` (used by ECS task metadata and credential
endpoints) and `http://fd00:ec2::254/` (IPv6 IMDS), while sensitive paths such as
`/latest/dynamic/instance-identity/` and `/latest/user-data/` may expose equally sensitive
material. None of these require the exact string the blocklist matches against, leaving them
completely unprotected.

---

### Q3 — Three measurable conditions for a successful fix

#### Condition 1 — All IP encoding variants are blocked before network dispatch

Network telemetry (VPC flow logs or egress capture) must confirm that no outbound packets
are sent to `169.254.0.0/16` for any encoding variant — hex, octal, decimal, or IPv6 — across
the entire test window. This is measurable by running the full test suite and verifying that
all bypass-variant test cases return the expected rejection code with zero corresponding
network packets observed at the host level.

#### Condition 2 — DNS rebinding and redirect chains are blocked at resolved-IP level

A tester-controlled domain that resolves to `169.254.169.254`, and a redirect chain that
ultimately leads to IMDS, must both be blocked. Server-side logs must confirm that validation
is performed against the **resolved IP address** at the point of connection — not against the
original input string — so that late-binding DNS changes and intermediate redirects cannot
bypass the check after initial validation passes.

#### Condition 3 — No metadata content is ever present in any response body

All SSRF test payloads targeting metadata paths — including
`/latest/meta-data/iam/security-credentials/`, `/latest/dynamic/instance-identity/`, and
`/latest/user-data/` — must be rejected with the expected error code. No response body must
ever contain metadata indicators such as IAM role names, `AccessKeyId`, `SecretAccessKey`,
or `Token` fields. Canary-string scanning of every response body is required to satisfy this
condition mechanically.

---

### Q4 — Does IMDSv2 make the blocklist unnecessary?

**How IMDSv2 changes the risk profile:**

Enabling IMDSv2 changes the risk profile because the metadata service now requires a session
token before metadata can be accessed. A client must first send a `PUT` request to
`/latest/api/token` with a `TTL-Seconds` header to obtain a token, then include that token
in all subsequent metadata `GET` requests via the `X-aws-ec2-metadata-token` header. This
two-step exchange prevents simple SSRF attacks that rely on a single unauthenticated `GET`
request to the metadata endpoint — the attack that succeeded in the original finding.

**Why IMDSv2 does not eliminate SSRF risk:**

IMDSv2 does not eliminate SSRF risk completely. If the vulnerable application allows
attackers to control HTTP methods and custom request headers, a multi-step SSRF attack
remains possible: first issuing a `PUT` to `/latest/api/token` to obtain a session token,
then using that token to `GET` `/latest/meta-data/iam/security-credentials/`. The
feasibility of this depends on how flexible the server-side request functionality is.

**Why the blocklist remains necessary:**

Enabling IMDSv2 does **not** make the application-level blocklist unnecessary, for three
reasons:

- IMDSv2 protects only the AWS metadata endpoint. The SSRF vulnerability remains fully
  exploitable against all other internal services: Redis, Memcached, Elasticsearch,
  Kubernetes API servers, internal REST APIs, and any RFC 1918 address reachable from the
  EC2 instance.
- Even with IMDSv2, SSRF enables internal network reconnaissance and port scanning,
  regardless of whether IAM credentials are retrievable.
- IMDSv2 enforcement is an AWS-side control that can be misconfigured or unevenly applied.
  Defence-in-depth requires both controls to be present simultaneously.

The application-level fix should ideally be an **allowlist** — permitting only specific
trusted domains and IP ranges — rather than a string-match blocklist. IMDSv2 is a
compensating control that reduces the impact of SSRF exploitation. It is not a substitute
for proper application-level input validation.

---

## Part B — Test Case Design (25 pts)

| Test ID | Category | Payload | Expected (Vulnerable) | Expected (Fixed) | Pass Condition |
|---------|----------|---------|----------------------|------------------|----------------|
| TC-01 ⭐ | **Blocklist enforcement** — validates client's claimed fix directly | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | `200 OK` — IAM role name and credentials in body | `400 Bad Request` — no metadata in body | Server returns `400` AND response body contains no IAM credential patterns |
| TC-02 | **Decimal IP encoding bypass** | `http://2852039166/latest/meta-data/` | `200 OK` — metadata returned; blocklist string-match misses this form | `400 Bad Request` | Server returns `400`; blocklist resolves numeric IP before checking |
| TC-03 | **Octal / hex IP encoding bypass** | `http://0251.0376.0251.0376/latest/meta-data/` and `http://0xa9fea9fe/latest/meta-data/` | `200 OK` — metadata fetched via encoding accepted by HTTP client | `400 Bad Request` for both variants | Both payloads return `400`; server normalises IP before blocklist check |
| TC-04 | **IPv6-mapped address bypass** | `http://[::ffff:169.254.169.254]/latest/meta-data/` and `http://[::ffff:a9fe:a9fe]/latest/meta-data/` | `200 OK` — server resolves IPv4-mapped IPv6 to metadata endpoint | `400 Bad Request` | Server returns `400`; blocklist handles IPv6 notation |
| TC-05 | **DNS rebinding** | `http://ssrf.attacker.io/latest/meta-data/` (DNS returns `169.254.169.254` on second resolution) | `200 OK` — server resolves domain then fetches metadata after DNS TTL flip | `400 Bad Request` or connection refused; server re-checks resolved IP post-DNS | Server returns `400` OR times out; no metadata in body |
| TC-06 | **Open redirect / HTTP redirect chaining** | `http://attacker.io/redirect` → `301` to `http://169.254.169.254/latest/meta-data/` | `200 OK` — server follows redirect to metadata IP transparently | `400 Bad Request` or redirect refused; blocklist checked on each hop | Server returns `400` on redirect target OR stops following redirect chains to internal IPs |
| TC-07 | **Alternative metadata path** | `http://169.254.169.254/latest/meta-data/hostname` and `http://169.254.169.254/latest/meta-data/public-keys/` | `200 OK` — non-credential paths not specifically blocked; hostname or key data returned | `400 Bad Request` for all paths under `169.254.169.254` | Both paths return `400`; blocklist is prefix-based, not path-specific |
| TC-08 | **ECS alternate metadata endpoint** | `http://169.254.170.2/v2/credentials/<role-id>` | `200 OK` — ECS task credential endpoint not in blocklist; credentials returned | `400 Bad Request` | Server returns `400`; blocklist covers `169.254.170.2` in addition to `169.254.169.254` |
| TC-09 | **Localhost variants** | `http://0.0.0.0/latest/meta-data/`, `http://0x7f000001/latest/meta-data/`, `http://127.1/latest/meta-data/` | `200 OK` — server-side HTTP client resolves shorthand localhost forms, bypassing string match | `400 Bad Request` for all three variants | All three return `400`; blocklist normalises all localhost representations |
| TC-10 | **Non-HTTP schemes** | `file:///etc/passwd`, `gopher://169.254.169.254:80/`, `dict://169.254.169.254:11211/` | `200 OK` or partial response — server HTTP client supports non-HTTP schemes; internal file or service content returned | `400 Bad Request`; only `http`/`https` schemes permitted | All three return `400`; server enforces an allowlist of schemes, not only a blocklist of IPs |
| TC-11 ⭐ | **Network egress — succeeds even if blocklist is correct** | `http://169.254.169.254/latest/meta-data/` sent directly from an internal network position bypassing the app | `200 OK` — IMDS reachable because no network-level egress control prevents EC2 → IMDS traffic from other paths | Connection refused or firewall drop; IMDS reachable only from the EC2 instance itself via IMDSv2 hop-limit=1 | IMDS unreachable from any path other than the EC2 instance's own network stack; confirmed via network-level probe (e.g. from Lambda or adjacent host) |

> ⭐ **TC-01** directly validates the client's claimed blocklist fix.
> ⭐ **TC-11** would succeed even if the blocklist is correctly implemented — tests the raw network boundary independent of application logic.

---
<img width="1284" height="775" alt="image" src="https://github.com/user-attachments/assets/97c5b3fa-6279-4c86-8956-a3db03d2e2a6" />

### Part E — Systems Design Under Pressure (10)


Deploy a dedicated OOB listener infrastructure using a wildcard DNS zone — for example,
`*.oob.pipeline.io` — pointing to a cluster of lightweight HTTP and DNS listener servers.
Each test case receives a unique subdomain token in the format
`{job_id}.{test_id}.oob.pipeline.io`, embedded directly in the payload URL. This makes
every callback unambiguously traceable to a specific test run and payload.

The DNS layer runs an authoritative nameserver such as PowerDNS, logging every query with
timestamp, source IP, and queried hostname. DNS callbacks fire even when HTTP is blocked,
making them the more reliable low-level signal. The HTTP layer uses stateless listeners
behind a load balancer, capturing full request headers and body.

A central correlation engine — backed by PostgreSQL or ClickHouse — ingests both DNS and
HTTP log streams via a message queue such as Kafka or SQS to handle burst traffic at scale.
After each test, the pipeline queries this store by token within a configurable time window
of 10 to 30 seconds. Tokens are HMAC-signed with a pipeline secret to prevent spoofed
callbacks from polluting results. Duplicate interactions within the same window are
deduplicated before verdict assignment. In practice, tools like Interactsh implement this
full architecture as a free hosted service.

---

### OOB Architecture Pipeline

```
┌──────────────────────────────────────────────────────────────┐
│               [ SSRF Test Pipeline ]                         │
│          verify_ssrf.py  |  input.json payloads              │
└─────────────────────────┬────────────────────────────────────┘
                          │  HTTP POST {param: payload}
                          ▼
┌──────────────────────────────────────────────────────────────┐
│               [ Target Application ]                         │
│      https://httpbin.org/post  (mock / real endpoint)        │
└─────────────────────────┬────────────────────────────────────┘
                          │  server fetches URL  (SSRF fires)
                          ▼
┌──────────────────────────────────────────────────────────────┐
│           [ Interactsh OOB Listener ]                        │
│    d6tdc57qeopnki5c9k0gb1sohs38y9r1h.oast.live              │
│    DNS query + HTTP callback logged with source IP           │
└─────────────────────────┬────────────────────────────────────┘
                          │  token match: oob-tc05.{domain}
                          ▼
┌──────────────────────────────────────────────────────────────┐
│               [ Correlation Engine ]                         │
│   token → TC-05 → source IP = target server → CONFIRMED      │
└─────────────────────────┬────────────────────────────────────┘
                          │  verdict written
                          ▼
┌──────────────────────────────────────────────────────────────┐
│               [ Evidence Store ]                             │
│   evidence/report_TIMESTAMP.json  +  .sha256                 │
└──────────────────────────────────────────────────────────────┘
```

### Scale Design Table

| Component | Tool Used | Purpose |
|-----------|-----------|---------|
| OOB Listener | Interactsh (`oast.live`) | Wildcard DNS + HTTP, zero setup |
| Token Generation | `job_id` + `test_id` subdomain | Unique per test, traceable |
| Log Ingestion | Interactsh CLI / API | Real-time interaction retrieval |
| Correlation Store | SQLite / PostgreSQL | Token-to-test mapping + dedup |
| Message Queue | Redis / SQS (free tier) | Burst handling at scale |
| Evidence Store | `evidence/` + SHA-256 | Tamper-evident chain of custody |
| Report Output | `verify_ssrf.py` JSON | Machine + human readable |

### Reliability Mechanisms

- HMAC-signed tokens prevent spoofed callbacks polluting results
- Time-windowed correlation (10–30s) prevents stale callbacks from prior runs
- DNS used as primary signal — fires even when HTTP egress is blocked
- Deduplication within token window prevents double-counting
- Evidence JSON + SHA-256 provides forensic chain of custody

---

## Evidence Chain

```
evidence/
├── report_20260318_164441.json      ← full structured test results
└── report_20260318_164441.sha256    ← SHA-256 integrity hash
```

**SHA-256 Hash:**

```
f9eb794dc6e328ad95f4aca820967d8b5c2f0711d391ab09f471c9e4a2e9356a
```

| Field | Value |
|-------|-------|
| File | `evidence/report_20260318_164441.json` |
| Algorithm | SHA-256 (chunked 65536-byte reads) |
| Purpose | Proves report was not modified after collection |

---

## Final Verdict

> ### 🔴 REMEDIATION FAILED — CLIENT FIX IS INSUFFICIENT
>
> | Finding | Detail |
> |---------|--------|
> | Tests run | 10 |
> | Tests failed | 10 / 10 |
> | Blocklist enforcement | Not observed on any payload |
> | OOB infrastructure | Live — Interactsh ready to confirm server-side fetches |
> | IMDSv2 impact | Reduces credential exfiltration risk — does NOT fix SSRF root cause |
> | **Recommendation** | **Replace string-match blocklist with allowlist-based URL validation** |

---
