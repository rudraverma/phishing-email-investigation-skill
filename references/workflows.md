# Investigation Workflows

## Full Phishing Kill-Chain Investigation

```
EML FILE RECEIVED
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: EMAIL HEADER ANALYSIS                               │
│  • Parse From / To / Subject / Date / Message-ID            │
│  • Check DKIM / SPF / DMARC results                         │
│  • Inspect Received chain (bottom-up = chronological)       │
│  • Flag Reply-To ≠ From mismatch                            │
│  • Extract originating IP                                    │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: DNS VALIDATION                                       │
│  • dig SPF TXT record for sender domain                     │
│  • dig DMARC TXT _dmarc.<domain>                            │
│  • dig MX records                                            │
│  • whois originating IP → country / org / abuse contact     │
│  • Reverse DNS on originating IP                            │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: URL EXTRACTION                                       │
│  • Extract all URLs from plain text and HTML parts          │
│  • Extract IPs referenced in body                           │
│  • Note upstream S3/CDN gate URLs (used as Referer)         │
└─────────────────────────────────────────────────────────────┘
      │
      ▼ (for EACH url)
┌─────────────────────────────────────────────────────────────┐
│ STEP 4: LIVE URL FETCH ← NEVER SKIP                         │
│  • curl -sk -L with browser UA + correct Referer            │
│  • Save HTML to decoded/lure_page.html                      │
│  • Save response headers to decoded/response_headers.txt    │
│  • Note: Server, CF-RAY, X-Robots-Tag, Cache-Control        │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 5: JAVASCRIPT DEOBFUSCATION                            │
│  • Extract all <script> blocks                              │
│  • Grep for: /api/, fetch(, device, user_code, SID=, API=   │
│  • Grep for: password, credential, webhook, telegram        │
│  • Grep for: evilginx, proxy, relay, session cookie         │
│  • Decode any base64 strings                                │
│  • Reconstruct JS logic flow                                │
└─────────────────────────────────────────────────────────────┘
      │
      ├──────────────────────────┬─────────────────────────────
      │                          │                            │
      ▼ device_code              ▼ credential_harvest         ▼ aitm
┌───────────────┐       ┌─────────────────┐        ┌──────────────────┐
│ DEVICE CODE   │       │ CRED HARVEST    │        │ AiTM PROXY       │
│ Deep Dive     │       │ Deep Dive       │        │ Deep Dive        │
│               │       │                 │        │                  │
│ Extract:      │       │ Extract:        │        │ Identify:        │
│ • SID         │       │ • POST endpoint │        │ • Proxy domain   │
│ • API base    │       │ • Exfil target  │        │ • Real target    │
│ • user_code   │       │ • Webhook URL   │        │ • Cookie relay   │
│ • poll_path   │       │ • Bot token     │        │ • JS injection   │
│ • oauth URL   │       │ • Tracking pixel│        │                  │
└───────┬───────┘       └────────┬────────┘        └────────┬─────────┘
        │                        │                           │
        ▼                        └──────────────┬────────────┘
┌─────────────────────────────────────────────────────────────┐
│ STEP 6: API BACKEND PROBING                                 │
│  Probe these paths on every discovered API host:           │
│  /health → victim count, server stats (often unauthed)      │
│  /api/status/{SID} → session state (pending/captured)       │
│  /api/generate → create session (unauthed = OpSec fail)     │
│  /api/sessions, /api/tokens → enumerate victims             │
│  /admin → dashboard leak                                    │
│  /metrics → Prometheus stats                                │
│                                                             │
│  Enumerate adjacent SIDs (±10) → gauge campaign density     │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 7: IOC EXTRACTION + DEFANGING                          │
│  • All IPs (filter RFC1918)                                 │
│  • All domains                                              │
│  • All URLs                                                 │
│  • File hashes (EML + any attachments)                      │
│  • User codes / Session IDs                                 │
│  • Defang: http→hxxp, .→[.]                                 │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 8: WRITE CASE ARTIFACTS                                │
│  notes.md  → hashes, timeline, hypothesis                  │
│  iocs.md   → defanged IOC table with confidence levels      │
│  timeline.md → event reconstruction                         │
│  report.md → TLP:AMBER, full findings, recommendations      │
└─────────────────────────────────────────────────────────────┘
```

---

## Device Code Phishing Kill Chain (Attacker Perspective)

Understanding how the attack works helps you know what to look for.

```
ATTACKER                    VICTIM                     MICROSOFT
    │                           │                           │
    │ POST /api/generate         │                           │
    │──────────────────────────▶│ (API creates device code) │
    │                           │                           │
    │◀── session_id: 433124     │                           │
    │    user_code: FM624XDF7   │                           │
    │    verification_uri: ...  │                           │
    │                           │                           │
    │  (page served to victim)  │                           │
    │                          phishing email arrives       │
    │                           │◀──────────────────────────│
    │                           │                           │
    │  GET /api/status/433124   │  Victim sees "Adobe Sign" │
    │  ← {"status":"pending"}   │  page with code FM624XDF7 │
    │  (polling every 3s...)    │                           │
    │                           │ Clicks "Review & Sign"    │
    │                           │ Code copied to clipboard  │
    │                           │                           │
    │                           │ Opens: login.microsoft.   │
    │                           │ com/common/oauth2/        │
    │                           │ deviceauth                │
    │                           │                           │
    │                           │ Pastes FM624XDF7          │
    │                           │──────────────────────────▶│
    │                           │                           │ Validates code
    │                           │ "You're signed in!"       │ Issues token
    │                           │◀──────────────────────────│
    │                           │                           │
    │ GET /api/status/433124 ──────────────────────────────▶│ (backend poll)
    │ ← {"status":"captured",   │                           │
    │    "email":"victim@co.nz"}│                           │
    │                           │                           │
    │ NOW HAS VALID             │                           │
    │ ACCESS TOKEN              │                           │
    │ MFA BYPASSED ✓            │                           │
```

---

## Referrer-Gated Phishing (S3 Captcha Gate Pattern)

Many kits serve a decoy page to direct visits. Always include the upstream URL as Referer.

```
1. Email contains: https://bucket.s3.amazonaws.com/.../gate.html
                              ↓ (Referer: S3 URL required)
2. Gate redirects to:   https://auth.evil.com/lp/<token>
                              ↓ (Referer: gate URL required)
3. Lure page served:    HTML with device code / cred form
                              ↓ (if visited without Referer)
4. Decoy page served:   404 / benign content / redirect to google.com
```

Fetch chain:
```bash
# Step 1: Fetch gate to get redirect target
curl -sk -L -D - "https://bucket.s3.amazonaws.com/.../gate.html"

# Step 2: Fetch lure WITH gate URL as Referer
curl -sk -L \
  -H "Referer: https://bucket.s3.amazonaws.com/.../gate.html" \
  -D decoded/response_headers.txt \
  -o decoded/lure_page.html \
  "https://auth.evil.com/lp/<token>"
```
