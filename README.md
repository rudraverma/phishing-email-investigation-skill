<div align="center">

<img src="https://media.cyberhawkthreatintel.com/general/1771234479938-y9566.png" width="80" alt="CyberHawk Logo" />

# phishing-email-deep-investigation

**A CyberHawk Threat Intel Skill**

Full kill-chain phishing investigation — from raw EML to backend infrastructure teardown.
Header analysis is not enough. This skill fetches live URLs, deobfuscates JavaScript,
probes unauthenticated API backends, detects Device Code Phishing, and maps
every finding to MITRE ATT&CK.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Domain](https://img.shields.io/badge/domain-Phishing%20Investigation-red.svg)]()
[![MITRE](https://img.shields.io/badge/MITRE-T1528%20%7C%20T1566%20%7C%20T1111-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Docker%20%7C%20Linux-lightgrey.svg)]()

[🌐 Website](https://www.cyberhawkthreatintel.com) •
[🚀 App](https://app.cyberhawkthreatintel.com) •
[▶️ YouTube](https://youtube.com/@cyberhawkconsultancy) •
[✉️ Telegram](https://t.me/cyberhawkthreatintel) •
[𝕏 Twitter](https://twitter.com/cyberhawkintel)

</div>

---

## What This Skill Does

Most phishing investigations stop at email headers. That catches maybe 20% of the story.

The real intelligence — the JavaScript polling loops, the OAuth device codes, the
unauthenticated backend APIs leaking active victim counts, the session IDs that enumerate
an entire campaign — all of that lives inside the live phishing page.

This skill covers the full kill-chain:

```
EML file → Header auth → DNS validation → URL extraction
        → Live page fetch → JS deobfuscation → API probing
        → Attack classification → IOC extraction → MITRE mapping → Report
```

### Attack Types Detected

| Type | Severity | MFA Bypass |
|---|---|---|
| OAuth Device Code Phishing | 🔴 CRITICAL | ✅ Yes — token stolen directly |
| AiTM Reverse Proxy | 🔴 CRITICAL | ✅ Yes — session cookie stolen |
| Credential Harvesting | 🟠 HIGH | ❌ No |
| QR Code Phishing (Quishing) | 🟠 HIGH | ❌ No |
| HTML Attachment Phishing | 🟠 HIGH | ❌ No |

---

## Package Structure

```
phishing-email-deep-investigation/
├── SKILL.md                        ← Full 9-step investigation methodology
├── README.md                       ← This file
├── LICENSE                         ← Apache 2.0
├── scripts/
│   ├── agent.py                    ← Full investigation agent (CLI)
│   └── process.py                  ← Quick IOC extractor (lightweight)
├── references/
│   ├── workflows.md                ← Kill-chain diagrams, referrer-gate fetch chain
│   ├── attack-patterns.md          ← JS signatures for all attack types
│   └── api-reference.md            ← curl, dig, whois, regex, Azure KQL reference
└── assets/
    └── template.md                 ← TLP:AMBER investigation report template
```

---

## Quick Start

### Prerequisites
- Python 3.8+ (stdlib only — no pip installs required)
- `curl` (standard on Linux/macOS, available in Docker)
- `dig` and `whois` for DNS/IP lookups
- Network access to reach live phishing infrastructure

### Run the full investigation

```bash
# Full investigation — fetches live URLs, probes APIs, writes JSON report
python3 scripts/agent.py /workspace/upload/sample.eml

# With custom output directory
python3 scripts/agent.py /workspace/upload/sample.eml \
  --output-dir /workspace/investigations/2026-01-01/my-case

# Output full JSON report to stdout
python3 scripts/agent.py /workspace/upload/sample.eml --json
```

### Quick IOC extraction only (no live fetch)

```bash
python3 scripts/process.py /workspace/upload/sample.eml
```

### Output files

| File | Contents |
|---|---|
| `investigation_report.json` | Full structured report — all findings, IOCs, MITRE, recommendations |
| `decoded/lure_<hash>.html` | Saved live phishing page HTML |
| `decoded/headers_<hash>.txt` | HTTP response headers from lure page |

---

## Step-by-Step Investigation Workflow

### Step 1 — Parse Headers + Authentication

```bash
python3 -c "
import email, re
from email import policy

with open('sample.eml', 'r', errors='replace') as f:
    msg = email.message_from_file(f, policy=policy.default)

print('From:  ', msg['From'])
print('Subject:', msg['Subject'])

auth = msg.get('authentication-results', '')
for proto in ('dkim', 'spf', 'dmarc'):
    m = re.search(rf'{proto}=(\w+)', auth)
    print(f'{proto.upper():5}: {m.group(1) if m else \"none\"}')
"
```

**Red flags:**
- `dkim=none` — not signed (spoofing possible)
- `dmarc=none` with `p=none` — no enforcement, domain can be freely spoofed
- `Reply-To ≠ From` — BEC/phishing mismatch

### Step 2 — DNS Validation

```bash
# SPF, DMARC, reverse DNS of originating IP
dig TXT <sender-domain> +short | grep "v=spf1"
dig TXT _dmarc.<sender-domain> +short
dig -x <originating-ip> +short
whois <originating-ip> | grep -iE "(netname|country|org|descr)"
```

### Step 3 — Extract URLs

```bash
python3 -c "
import email, re
from email import policy
with open('sample.eml', 'r', errors='replace') as f:
    msg = email.message_from_file(f, policy=policy.default)
body = ''.join(str(p.get_payload(decode=True) or b'') for p in msg.walk())
for u in sorted(set(re.findall(r'https?://[^\s<>\"]+', body))):
    print(u)
"
```

### Step 4 — Fetch Live URL *(never skip)*

```bash
curl -sk -L --max-time 30 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "Accept: text/html,application/xhtml+xml" \
  -H "Referer: <upstream-gate-url-if-known>" \
  -D decoded/response_headers.txt \
  -o decoded/lure_page.html \
  "https://<phishing-url>"
```

**Response headers that scream phishing kit:**

```
Server: cloudflare                          → origin IP hidden
X-Robots-Tag: noindex,nofollow,noarchive   → hiding from web archives
Cache-Control: no-store,no-cache           → preventing evidence preservation
Referrer-Policy: no-referrer               → hiding downstream traffic
```

### Step 5 — JavaScript Deobfuscation

```bash
# Extract all script blocks
python3 -c "
import re
html = open('decoded/lure_page.html').read()
for i, s in enumerate(re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)):
    if s.strip(): print(f'=== BLOCK {i} ===\n{s.strip()}')
"

# Grep for high-value patterns
grep -E "(const SID|const API|SPATH|pollStatus|captured|deviceauth|user_code)" decoded/lure_page.html
grep -E "(fetch\(|/api/|verification_uri|login\.microsoftonline)" decoded/lure_page.html
grep -E "(type.*password|webhook|telegram|discord)" decoded/lure_page.html
```

### Step 6 — Identify Device Code Phishing

If you see `deviceauth`, `user_code`, `pollStatus`, or `const SID` — this is Device Code Phishing.
**MFA is bypassed entirely.** Treat as CRITICAL.

```bash
python3 -c "
import re
t = open('decoded/lure_page.html').read()
for label, pat in [
    ('Session ID', r'const SID\s*=\s*(\d+)'),
    ('API base',   r\"const API\s*=\s*['\\\"](https?://[^'\\\"]+)\"),
    ('User code',  r'id=[\"\\']userCode[\"\\'][^>]*>([A-Z0-9]+)<'),
    ('OAuth URL',  r'(https://login\.microsoftonline\.com[^\s\\'\"<>]+)'),
]:
    m = re.search(pat, t, re.I)
    print(f'{label:12}: {m.group(1) if m else \"not found\"}')
"
```

### Step 7 — Probe API Backend

```bash
API="https://api.evil.com:8443"

# Check for unauthenticated victim count leak
curl -sk "${API}/health" | python3 -m json.tool

# Check session status
curl -sk "${API}/api/status/433124"

# Try unauthenticated session generation (OpSec failure if this works)
curl -sk -X POST "${API}/api/generate" \
  -H "Content-Type: application/json" -d '{}'

# Probe common endpoints
for path in /health /api/ /api/sessions /api/tokens /admin /metrics; do
  code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${API}${path}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "[${code}] ${path}"
done
```

### Step 8 — Extract + Defang IOCs

```bash
python3 -c "
import re

def defang(s): return s.replace('http','hxxp').replace('.','[.]')

html = open('decoded/lure_page.html').read()
for t, pat in [
    ('URL',    r'https?://[^\s\"<>]+'),
    ('IP',     r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    ('Domain', r'https?://([a-zA-Z0-9.-]+)'),
]:
    for v in sorted(set(re.findall(pat, html))):
        if t == 'IP' and v.startswith(('127.','0.','192.168.')): continue
        print(f'[{t}] {defang(v)}')
"
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Scenario |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Email with phishing URL |
| Steal Application Access Token | T1528 | Device code OAuth token theft |
| Use Alternate Auth Material: Token | T1550.001 | Attacker uses stolen token |
| MFA Interception | T1111 | Device code / AiTM bypass |
| Adversary-in-the-Middle | T1557 | Reverse proxy (Evilginx) |
| Steal Web Session Cookie | T1539 | AiTM post-auth cookie relay |
| Input Capture: Web Portal | T1056.003 | Credential harvesting page |
| Phishing for Information | T1598.003 | Credential/token collection |
| Acquire Infrastructure: Web Services | T1583.006 | Cloudflare + S3 hosting |

---

## Device Code Phishing — What It Is

> "The victim never types a password. They enter a code. MFA never fires."

```
Attacker pre-generates a Microsoft device code via their C2 API.
Victim sees a fake Adobe / DocuSign page with a "verification code."
Victim clicks → Microsoft's real auth page opens → code auto-copied to clipboard.
Victim pastes the code, completes "verification."
Attacker's backend polls Microsoft — on success, receives a valid OAuth access token.
MFA was never required. The token is live. The account is compromised.
```

**Scale indicator:** The `/health` API endpoint on PhaaS backends often leaks
`active_tokens` and `revoked_tokens` counts — revealing the full campaign scope
with a single unauthenticated GET request.

---

## PhaaS OpSec Failure Checklist

When you find a backend API, always probe these:

| Check | Command | Win condition |
|---|---|---|
| Victim count | `GET /health` | `active_tokens: N` — full campaign size |
| Unauthed generation | `POST /api/generate` | Returns 200 — no auth required |
| Adjacent victims | `GET /api/status/N±10` | Status of neighbouring sessions |
| Admin panel | `GET /admin` | Full dashboard exposed |
| Metrics | `GET /metrics` | Prometheus stats |
| CORS wildcard | Check `Access-Control-Allow-Origin` | `*` = full API access from any origin |

---

## Contributing

Built and maintained by [CyberHawk Threat Intel](https://www.cyberhawkthreatintel.com).

Follow for threat intel, phishing teardowns, and investigation walkthroughs:

| Platform | Handle |
|---|---|
| 🎥 YouTube | [@cyberhawkconsultancy](https://youtube.com/@cyberhawkconsultancy) |
| 🎥 YouTube | [@cyberhawkk](https://youtube.com/@cyberhawkk) |
| 📱 TikTok | [@cyberhawkthreatintel](https://tiktok.com/@cyberhawkthreatintel) |
| 𝕏 Twitter/X | [@cyberhawkintel](https://twitter.com/cyberhawkintel) |
| ✉️ Telegram | [@cyberhawkthreatintel](https://t.me/cyberhawkthreatintel) |

#cyberhawkthreatintel #cyberhawkconsultancy #cyberhawkk

---

<div align="center">

**[CyberHawk Threat Intel](https://www.cyberhawkthreatintel.com)**
*Investigate deeper. Stop at nothing.*

</div>
