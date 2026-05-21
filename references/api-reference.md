# API & Tool Reference

## curl — Live URL Fetching

```bash
# Full fetch with browser fingerprint, save HTML + headers
curl -sk -L --max-time 30 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Referer: <upstream-gate-url>" \
  -D response_headers.txt \
  -o lure_page.html \
  "https://phishing-url"

# Fetch and print headers + body together (for quick inspection)
curl -sk -L -D - "https://phishing-url"

# Probe endpoint and get HTTP status code only
curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "https://api/endpoint"

# POST JSON to API endpoint
curl -sk -X POST "https://api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -m json.tool

# Fetch via IP directly with SNI hostname (when DNS is down)
curl -sk --resolve "hostname:443:1.2.3.4" "https://hostname/path"
```

### curl flag reference

| Flag | Purpose |
|---|---|
| `-s` | Silent (no progress bar) |
| `-k` | Skip TLS cert verification |
| `-L` | Follow redirects |
| `-D -` | Dump response headers to stdout |
| `-D file` | Dump response headers to file |
| `-o file` | Save response body to file |
| `-w "%{http_code}"` | Print HTTP status code after response |
| `--max-time N` | Timeout in seconds |
| `--resolve h:p:ip` | Override DNS — connect to IP for hostname |
| `-H "Header: value"` | Add request header |
| `-X POST` | Set request method |
| `-d 'body'` | Request body |

---

## Python `email` — EML Parsing

```python
import email
from email import policy

# Parse EML file
with open('sample.eml', 'r', errors='replace') as f:
    msg = email.message_from_file(f, policy=policy.default)

# Access headers
msg['From']              # Sender display name + address
msg['Subject']
msg['Date']
msg['Message-ID']
msg.get('Reply-To', '')  # Safely get optional headers
msg.get_all('Received')  # Returns list of all Received headers

# Walk MIME parts
for part in msg.walk():
    ct   = part.get_content_type()       # 'text/html', 'text/plain', etc.
    disp = part.get_content_disposition() # 'attachment', 'inline', None
    
    if ct == 'text/html':
        body = part.get_content()        # Decoded unicode string
    
    if disp == 'attachment':
        raw  = part.get_payload(decode=True)  # Raw bytes
        name = part.get_filename()
```

### Authentication-Results parsing

```python
auth = msg.get('authentication-results', '')
# auth = "dkim=pass header.d=example.com; spf=pass; dmarc=pass action=none"

import re
dkim  = re.search(r'dkim=(\w+)',  auth)  # pass / fail / none / permerror
spf   = re.search(r'spf=(\w+)',   auth)
dmarc = re.search(r'dmarc=(\w+)', auth)
```

---

## dig — DNS Investigation

```bash
# SPF record
dig TXT example.com +short | grep "v=spf1"

# DMARC policy
dig TXT _dmarc.example.com +short
# Output: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"

# DKIM selector (selector comes from DKIM-Signature header d= and s= fields)
dig TXT <selector>._domainkey.<domain> +short

# MX records
dig MX example.com +short

# Reverse DNS
dig -x 203.0.113.45 +short

# Use specific resolver
dig TXT example.com @8.8.8.8 +short
```

### DMARC policy values

| Value | Meaning |
|---|---|
| `p=none` | Monitoring only — no action on failures. Weak posture. |
| `p=quarantine` | Failures go to spam folder |
| `p=reject` | Failures are rejected outright |
| `pct=N` | Apply policy to N% of messages |
| `rua=mailto:x` | Aggregate report destination |

---

## whois — IP/Domain Intelligence

```bash
# IP whois
whois 203.0.113.45 | grep -iE "(netname|country|org|descr|inetnum|abuse-mailbox)"

# Domain whois
whois evil-domain.com | grep -iE "(registrar|creation|expiry|registrant|name.server)"

# Key fields to note:
# inetnum    → IP range assigned to the organisation
# netname    → Short name for the network block
# country    → Country code of the registrant
# org-name   → Organisation name
# abuse-mailbox → Who to report abuse to
```

---

## Python `re` — Pattern Extraction

```python
import re

# Extract all URLs from HTML/text
urls = re.findall(r'https?://[^\s<>"\'\\]+', html)

# Extract all IPv4 addresses
ips  = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

# Extract all <script> blocks
scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.IGNORECASE)

# Extract all href values
hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)

# Extract base64 strings
b64 = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)

# Extract JS constants
sid = re.search(r'(?:const|var)\s+SID\s*=\s*(\d+)', scripts_text)
api = re.search(r"(?:const|var)\s+API\s*=\s*['\"]([^'\"]+)['\"]", scripts_text)
```

---

## Response Header Analysis

### Cloudflare-shielded infrastructure

| Header | Significance |
|---|---|
| `Server: cloudflare` | Origin IP hidden behind Cloudflare proxy |
| `CF-RAY: <hash>-<IATA>` | IATA airport code = Cloudflare PoP location (approximates origin region) |
| `cf-cache-status: DYNAMIC` | Not cached — dynamic content, phishing kit |
| `Server-Timing: cfEdge; cfOrigin` | Origin server latency — cfOrigin high = geographically distant server |

### Anti-forensics headers (red flags)

| Header | Significance |
|---|---|
| `X-Robots-Tag: noindex,nofollow,noarchive,noimageindex` | Hiding from Google, web archives, screenshot services |
| `Cache-Control: no-store,no-cache,must-revalidate,private` | Preventing any caching — evidence destruction |
| `Referrer-Policy: no-referrer` | Hiding downstream traffic, preventing referrer analysis |
| `X-Frame-Options: DENY` | Deliberate kit design — not a default setting |
| `X-Content-Type-Options: nosniff` | Kit is security-aware |

All of these together = professional phishing kit with active anti-forensics.

---

## Defanging Reference

Always defang IOCs before including them in reports or sharing externally.

| Original | Defanged | Rule |
|---|---|---|
| `http://evil.com/path` | `hxxp://evil[.]com/path` | `http` → `hxxp`, `.` → `[.]` |
| `https://evil.com` | `hxxps://evil[.]com` | same |
| `203.0.113.45` | `203[.]0[.]113[.]45` | `.` → `[.]` in IPs |
| `evil.com` | `evil[.]com` | `.` → `[.]` in domains |

```python
def defang(s):
    return s.replace('http', 'hxxp').replace('.', '[.]')
```

---

## Microsoft Azure AD — Post-Investigation Queries

### Find device code flow sign-ins (KQL for Sentinel / Log Analytics)

```kql
SigninLogs
| where AuthenticationRequirement == "singleFactorAuthentication"
| where ClientAppUsed == "Device Code Flow"
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, Status
| sort by TimeGenerated desc
```

### Find sign-ins from phishing domain IPs

```kql
SigninLogs
| where IPAddress in ("104.21.94.211", "172.67.140.80")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType
```

### Check for OAuth app consent grants

```kql
AuditLogs
| where OperationName == "Consent to application"
| where TimeGenerated > ago(7d)
| extend AppName = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, AppName, Result
```
