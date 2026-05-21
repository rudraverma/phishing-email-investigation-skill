---
name: phishing-email-deep-investigation
description: >
  Full kill-chain phishing investigation: email header authentication, URL extraction,
  live page fetching with browser fingerprinting, JavaScript deobfuscation, API endpoint
  probing, device code phishing detection, AiTM pattern recognition, backend infrastructure
  mapping, IOC extraction, and MITRE ATT&CK-mapped reporting. Use when a reported phishing
  email requires depth beyond header analysis — every URL in the email must be fetched,
  deconstructed, and its backend interrogated.
domain: cybersecurity
subdomain: phishing-investigation
tags:
  - phishing
  - email-forensics
  - device-code-phishing
  - oauth-token-theft
  - aitm
  - javascript-deobfuscation
  - ioc-extraction
  - incident-response
  - mfa-bypass
  - credential-harvesting
version: '1.0'
author: CyberHawk
license: Apache-2.0
mitre_attack:
  - T1566.001
  - T1566.002
  - T1528
  - T1550.001
  - T1111
  - T1598.003
  - T1056.003
  - T1583.006
nist_csf:
  - DE.AE-02
  - RS.AN-01
  - RS.AN-03
  - RS.MA-01
  - DE.CM-01
  - ID.RA-01
---

# Phishing Email Deep Investigation

## Overview

Header analysis alone catches maybe 20% of a phishing attack's story. The real intelligence
lives in the live page: the JavaScript, the API backend, the device codes, the victim session
count, the unauthenticated endpoints that expose the entire operation. This skill covers the
full kill-chain — from raw EML to backend infrastructure teardown.

## When to Use

- Any reported phishing email that contains URLs (do not stop at header analysis)
- When a user clicked a link and you need to know exactly what the page did
- Suspected OAuth Device Code Phishing (fake DocuSign, Adobe Sign, Microsoft security alerts)
- AiTM (Adversary-in-The-Middle) proxy-based attacks
- When you need to enumerate the scale of an active campaign (victim count from `/health` endpoints)
- When building detection rules — the JS polling loops, API patterns, and session IDs become YARA/Sigma signatures

**Do NOT use** for spam/marketing email without URLs. Route those to email admin for filter tuning.

## Prerequisites

- Raw EML file in `/workspace/upload/`
- `curl` installed (available in core container)
- `python3` with `email`, `re`, `json`, `subprocess` (all stdlib — no installs needed)
- Network access from Docker container to reach live phishing infrastructure
- Case folder created at `/workspace/investigations/YYYY-MM-DD/<case-name>/`

## Workflow

### Step 1: Parse Email Headers + Authentication

```bash
python3 << 'EOF'
import email, re
from email import policy

with open('/workspace/upload/sample.eml', 'r', errors='replace') as f:
    msg = email.message_from_file(f, policy=policy.default)

print("=== KEY HEADERS ===")
print("From:        ", msg['From'])
print("To:          ", msg['To'])
print("Subject:     ", msg['Subject'])
print("Date:        ", msg['Date'])
print("Reply-To:    ", msg.get('Reply-To', 'NOT PRESENT'))
print("Return-Path: ", msg.get('Return-Path', 'NOT PRESENT'))
print("Orig IP:     ", msg.get('x-ms-exchange-organization-originalclientipaddress', msg.get('X-Originating-IP', 'NOT PRESENT')))

print("\n=== RECEIVED CHAIN (chronological) ===")
for i, h in enumerate(reversed(msg.get_all('Received') or [])):
    print(f"Hop {i+1}: {h.strip()[:200]}")

print("\n=== AUTHENTICATION ===")
auth = msg.get('authentication-results', 'NOT PRESENT')
print(auth)
print("DKIM-Signature:", msg.get('DKIM-Signature', 'NONE'))
print("Received-SPF:  ", msg.get('Received-SPF', 'NOT PRESENT'))

print("\n=== FROM/REPLY-TO MISMATCH CHECK ===")
import email.utils
from_addr = email.utils.parseaddr(msg['From'])[1]
reply_to  = email.utils.parseaddr(msg.get('Reply-To', msg['From']))[1]
print(f"From:     {from_addr}")
print(f"Reply-To: {reply_to}")
print(f"MATCH:    {from_addr == reply_to}")
EOF
```

**What to check:**
- `dkim=none` → message not signed (attacker could have spoofed headers)
- `dmarc=none` with `p=none` → domain can be freely spoofed, no enforcement
- `Reply-To != From` → classic BEC/phishing mismatch
- Originating IP country vs claimed sender country

---

### Step 2: DNS Validation of Sender Domain

```bash
# SPF record
dig TXT <sender-domain> +short | grep "v=spf1"

# DMARC policy
dig TXT _dmarc.<sender-domain> +short

# MX records
dig MX <sender-domain> +short

# Reverse DNS of originating IP
dig -x <originating-ip> +short

# WHOIS key fields
whois <originating-ip> | grep -iE "(netname|country|org|descr|inetnum)"
```

**Flags:**
- `p=none` DMARC → no enforcement, weak posture
- Originating IP country mismatch vs sender domain country → possible compromise or spoofing
- No SPF `-all` enforcement → domain can send from any IP

---

### Step 3: Extract All URLs from Email Body

```bash
python3 << 'EOF'
import email, re
from email import policy

with open('/workspace/upload/sample.eml', 'r', errors='replace') as f:
    msg = email.message_from_file(f, policy=policy.default)

full = ''
for part in msg.walk():
    ct = part.get_content_type()
    if ct in ('text/plain', 'text/html'):
        try:
            full += part.get_content()
        except:
            full += str(part.get_payload(decode=True) or '')

urls = sorted(set(re.findall(r'https?://[^\s<>"\'\\]+', full)))
print(f"Found {len(urls)} URLs:")
for u in urls:
    print(" ", u)

# Also extract IPs referenced in body text
ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', full))
ips = {ip for ip in ips if not ip.startswith(('127.','0.','255.'))}
print(f"\nIPs referenced in body: {ips}")
EOF
```

---

### Step 4: Fetch Every URL — Live Page Analysis (CRITICAL)

**Never skip this step.** The lure page contains the full attack mechanism.

```bash
# Basic fetch with browser headers and correct Referer
curl -sk -L --max-time 30 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Referer: <upstream-url-if-known>" \
  -D /workspace/investigations/<case>/decoded/response_headers.txt \
  -o /workspace/investigations/<case>/decoded/lure_page.html \
  "https://<phishing-url>"

# View response headers
cat /workspace/investigations/<case>/decoded/response_headers.txt

# Quick preview of page content
head -c 1000 /workspace/investigations/<case>/decoded/lure_page.html
```

**Response headers to analyse immediately:**
| Header | Significance |
|---|---|
| `Server: cloudflare` | Attacker using Cloudflare as proxy/shield — origin hidden |
| `X-Robots-Tag: noindex,nofollow,noarchive` | Actively hiding from search engines and web archives |
| `Cache-Control: no-store,no-cache` | Preventing caching — evidence destruction |
| `Referrer-Policy: no-referrer` | Hiding downstream traffic |
| `CF-RAY` | Cloudflare edge node — encodes origin region |
| `X-Frame-Options: DENY` | Anti-iframe — deliberate kit design |

---

### Step 5: JavaScript Extraction + Deobfuscation

```bash
# Extract ALL script blocks
python3 << 'EOF'
import re

html = open('/workspace/investigations/<case>/decoded/lure_page.html').read()

scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.IGNORECASE)
for i, s in enumerate(scripts):
    s = s.strip()
    if s:
        print(f"\n{'='*50}")
        print(f"=== SCRIPT BLOCK {i} ===")
        print(f"{'='*50}")
        print(s)
EOF

# Grep for high-value patterns
echo "=== API ENDPOINTS ===" && grep -Eo '(https?://[^"'"'"' >]+|/api/[^"'"'"' >]+)' /workspace/investigations/<case>/decoded/lure_page.html
echo "=== DEVICE CODE PATTERNS ===" && grep -E "(device|user_code|deviceauth|SID|pollStatus|captured|verification_uri)" /workspace/investigations/<case>/decoded/lure_page.html
echo "=== FETCH/XHR CALLS ===" && grep -E "(fetch\(|XMLHttpRequest|axios)" /workspace/investigations/<case>/decoded/lure_page.html
echo "=== CREDENTIAL FIELDS ===" && grep -iE "(password|passwd|email.*input|type.*password|credential)" /workspace/investigations/<case>/decoded/lure_page.html
echo "=== SESSION/TRACKING IDS ===" && grep -Eo "(session_id|SID|campaign|track)[^;,\"']{0,60}" /workspace/investigations/<case>/decoded/lure_page.html
```

**Pattern signatures by attack type:**

| Pattern | Attack Type |
|---|---|
| `deviceauth`, `user_code`, `verification_uri`, `pollStatus` | **Device Code Phishing** |
| `type="password"`, POST to `/login`, credential `fetch()` | **Credential Harvesting** |
| `evilginx`, reverse proxy headers, session cookie relay | **AiTM Proxy** |
| `input type="email"`, fake MFA prompt, OTP field | **MFA Token Harvesting** |
| `<iframe>`, `postMessage`, cross-origin relay | **OAuth Consent Phishing** |

---

### Step 6: Identify Device Code Phishing (if detected)

Device Code Phishing bypasses MFA. Treat it as CRITICAL.

```bash
python3 << 'EOF'
import re

html = open('/workspace/investigations/<case>/decoded/lure_page.html').read()
scripts = '\n'.join(re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.IGNORECASE))

print("=== DEVICE CODE ARTIFACTS ===")

# Session ID
sid = re.search(r'(?:const|var)\s+SID\s*=\s*(\d+)', scripts)
print(f"Session ID:   {sid.group(1) if sid else 'NOT FOUND'}")

# C2 API base
api = re.search(r"(?:const|var)\s+API\s*=\s*['\"]([^'\"]+)['\"]", scripts)
print(f"API base:     {api.group(1) if api else 'NOT FOUND'}")

# User code displayed to victim
code = re.search(r'id=["\']userCode["\'][^>]*>([A-Z0-9]+)<', html)
print(f"User code:    {code.group(1) if code else 'NOT FOUND'}")

# Poll path
poll = re.search(r"(?:SPATH|spath)\s*=\s*['\"]([^'\"]+)['\"]", scripts)
print(f"Poll path:    {poll.group(1) if poll else 'NOT FOUND'}")

# Post-capture redirect
clure = re.search(r"(?:CLURE|clure)\s*=\s*['\"]([^'\"]*)['\"]", scripts)
print(f"Post-capture redirect: {clure.group(1) if clure else 'NONE (shows success message)'}")

# OAuth URL
oauth = re.search(r"(https://login\.microsoftonline\.com[^\s'\"]+)", html)
print(f"OAuth URL:    {oauth.group(1) if oauth else 'NOT FOUND'}")
EOF
```

---

### Step 7: Probe Backend API Endpoints

```bash
API_BASE="https://api.example.com:8443"   # from JS analysis

# Paths to probe
for path in /health /api/ /api/status /api/generate /api/sessions /api/tokens /admin /status /metrics; do
  code=$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "${API_BASE}${path}")
  if [ "$code" != "000" ] && [ "$code" != "404" ]; then
    echo "[${code}] ${path}"
    # Get content for non-404s
    curl -sk --max-time 10 "${API_BASE}${path}" | head -c 500
    echo
  fi
done

# Check /health for victim count leak
curl -sk "${API_BASE}/health" | python3 -m json.tool

# Check session status (use SID from JS)
SID=433124
curl -sk "${API_BASE}/api/status/${SID}"

# Test session generation (NO AUTH required if misconfigured)
curl -sk -X POST "${API_BASE}/api/generate" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -m json.tool

# Enumerate adjacent session IDs (±10) to gauge campaign scale
for i in $(seq $((SID-5)) $((SID+5))); do
  result=$(curl -sk --max-time 5 "${API_BASE}/api/status/${i}")
  echo "SID ${i}: ${result}"
done
```

**High-value API responses:**
| Response | Significance |
|---|---|
| `/health` returns `active_tokens: N` | Number of active victim sessions in the campaign |
| `/api/generate` returns 200 | Session creation is unauthenticated — attacker OpSec failure |
| Status `captured` on a SID | That victim has completed the OAuth flow — token stolen |
| Status `pending` on hundreds of SIDs | Active, live campaign with victims in progress |

---

### Step 8: Extract + Defang All IOCs

```bash
python3 << 'EOF'
import re

html = open('/workspace/investigations/<case>/decoded/lure_page.html').read()

def defang(s):
    return s.replace('http', 'hxxp').replace('.', '[.]')

# IPs
ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', html))
ips = {ip for ip in ips if not ip.startswith(('127.','0.','255.','192.168.','10.'))}

# Domains from URLs
domains = set(re.findall(r'https?://([a-zA-Z0-9.-]+)', html))

# All URLs
urls = set(re.findall(r'https?://[^\s"\'<>]+', html))

print("=== IPs ===")
for ip in sorted(ips): print(f"  {defang(ip)}")

print("\n=== DOMAINS ===")
for d in sorted(domains): print(f"  {defang(d)}")

print("\n=== URLS ===")
for u in sorted(urls): print(f"  {defang(u)}")
EOF
```

---

### Step 9: Write Case Artifacts

```bash
CASE_DIR="/workspace/investigations/$(date +%Y-%m-%d)/<case-name>"

# notes.md   — created by create_case, update with findings
# iocs.md    — defanged IOC table with confidence levels
# timeline.md — event reconstruction
# report.md  — TLP:AMBER, full findings
# decoded/lure_page.html   — saved lure page
# decoded/response_headers.txt
```

---

## Key Concepts

| Concept | Description |
|---|---|
| **Device Code Phishing** | Attacker generates Microsoft OAuth device code, tricks victim into entering it on the legitimate Microsoft auth page, receives access token. Bypasses MFA entirely. |
| **AiTM (Adversary-in-the-Middle)** | Reverse proxy sits between victim and real service, relaying credentials and session cookies in real time |
| **PhaaS (Phishing-as-a-Service)** | Hosted phishing kit with web dashboard, API backend, victim tracking, Telegram notification of captured tokens |
| **Defanging** | Rendering IOCs inert for safe sharing: `http` → `hxxp`, `.` → `[.]` |
| **Session polling** | JS loop calling `/api/status/{SID}` every 3 seconds waiting for `captured` state — confirms token theft |
| **Referrer-gating** | Phishing page checks `Referer` header, serves decoy content to direct visits — always include correct Referer when fetching |
| **Cloudflare-shielded infra** | Attacker hides origin IP behind Cloudflare proxy — note CF-RAY region, report to Cloudflare abuse |
| **Sequential SIDs** | Integer session IDs allow enumeration of adjacent victims — gauge campaign scale |

---

## Tools Used

| Tool | Purpose |
|---|---|
| `curl -sk -L -D -` | Fetch live URLs with headers, follow redirects, dump response headers |
| `python3 email` | Parse EML, extract headers, authentication, body text |
| `grep -E` | Pattern match JS blocks, API endpoints, device code artefacts |
| `dig` | DNS: SPF, DKIM, DMARC, MX, reverse lookup |
| `whois` | IP/domain registration, country, org, abuse contact |
| `python3 re` | JS extraction, URL/IP/domain regex from HTML |
| `python3 -m json.tool` | Pretty-print API responses |

---

## Common Phishing Kit Signatures

### Device Code Phishing Kit
```
Indicators: deviceauth, user_code, pollStatus, SID=, API=, SPATH=, captured
OAuth URL:  login.microsoftonline.com/common/oauth2/deviceauth
Lure brand: Adobe Acrobat Sign, DocuSign, Microsoft, SharePoint
Bypass:     MFA completely bypassed — access token stolen directly
```

### EvilGinx / AiTM Proxy Kit
```
Indicators: Transparent proxy, real domain in browser, session cookie relay
Headers:    X-Forwarded-For, custom CORS headers
Bypass:     Session cookie stolen after MFA completion
```

### Credential Harvesting
```
Indicators: <input type="password">, POST /login, fake O365/Google login
Bypass:     None — relies on catching password before MFA prompt
```

### QR Code Phishing (Quishing)
```
Indicators: PNG/SVG in email body, no URLs in text (bypasses URL scanners)
Action:     Decode QR → submit decoded URL to investigation workflow
```

---

## Output Format

```
PHISHING INVESTIGATION REPORT — <CASE-ID>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CLASSIFICATION: TLP:AMBER

Email:
  From:      attacker@evil[.]com (DKIM: none, DMARC: p=none)
  Subject:   Document Requires Your Review
  Orig IP:   203.0.113.45 (AS12345 — SomeCDN, US)

Attack Type: DEVICE CODE PHISHING (MFA BYPASSED)
Severity:    CRITICAL

Lure Infrastructure:
  URL:       hxxps://auth[.]loadingdocuments[.]uk/lp/xYV2pMw6crY
  IP:        104[.]21[.]94[.]211 (Cloudflare proxy)
  Brand:     Adobe Acrobat Sign (impersonation)
  User code: FM624XDF7  → login.microsoftonline.com/common/oauth2/deviceauth

Backend API:
  URL:       hxxps://api[.]loadingdocuments[.]uk:8443
  /health:   active_tokens: 2795, revoked_tokens: 1022 (UNAUTHENTICATED)
  /api/generate: UNAUTHENTICATED session creation — OpSec failure
  Campaign scale: ~3,817 total victims targeted

MITRE ATT&CK:
  T1566.002 — Phishing: Spearphishing Link
  T1528     — Steal Application Access Token
  T1550.001 — Use Alternate Authentication Material
  T1111     — MFA Interception

IOCs (defanged):
  hxxps://auth[.]loadingdocuments[.]uk/lp/xYV2pMw6crY  [HIGH]
  hxxps://api[.]loadingdocuments[.]uk:8443              [HIGH]
  104[.]21[.]94[.]211                                   [MEDIUM]

Recommendations:
  [CRITICAL] Report OAuth app to Microsoft MSRC
  [CRITICAL] Block loadingdocuments[.]uk at DNS/proxy
  [CRITICAL] Audit Azure AD for device code sign-in events
  [HIGH]     Restrict device code flow via Conditional Access
```
