# CLINT-ASSESSMENT


## Part E — Systems Design Under Pressure


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
