<div align="center">

<img src="https://media.cyberhawkthreatintel.com/general/1771234479938-y9566.png" width="80" alt="CyberHawk Logo" />

# phishing-email-deep-investigation

**A CyberHawk Threat Intel Skill for Claude Code**

Drop a phishing email. Claude does the rest — live URL fetch, JavaScript teardown,
backend API probe, Device Code detection, IOC extraction, MITRE mapping.
Header analysis is just the beginning.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Domain](https://img.shields.io/badge/domain-Phishing%20Investigation-red.svg)]()
[![MITRE](https://img.shields.io/badge/MITRE-T1528%20%7C%20T1566%20%7C%20T1111-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Claude%20Code-blueviolet.svg)]()

[🌐 Website](https://www.cyberhawkthreatintel.com) •
[🚀 App](https://app.cyberhawkthreatintel.com) •
[▶️ YouTube](https://youtube.com/@cyberhawkconsultancy) •
[✉️ Telegram](https://t.me/cyberhawkthreatintel) •
[𝕏 Twitter](https://twitter.com/cyberhawkintel)

</div>

---

## What This Skill Does

When you report a phishing email to Claude, Claude reads this skill and automatically
runs a full kill-chain investigation — no commands needed from you.

**Without this skill**, Claude does header analysis and stops. With it, Claude goes further:

| Without skill | With this skill |
|---|---|
| Reads email headers | Reads headers + validates DNS (SPF/DKIM/DMARC) |
| Notes "suspicious URL found" | Fetches the live URL inside a sandboxed container |
| Skips JavaScript | Extracts and deobfuscates every script block |
| Misses the backend | Probes API endpoints — finds victim counts, session leaks |
| Marks it as phishing | Classifies attack type: Device Code / AiTM / Credential Harvest |
| Lists IOCs manually | Auto-extracts and defangs all IOCs |
| Generic recommendation | MITRE-mapped findings + prioritised containment steps |

---

## Installation

### Option A — CyberHawk Platform (Docker skill system)

If you're running the CyberHawk investigation platform, copy the skill into the
Docker skill library on your server:

```bash
# On cyberhawk-server-ubuntu
cp -r phishing-email-deep-investigation \
  ~/docker/compose-files/cyberhawk-docker/.agents/skills/

# Rebuild the API container so the skill is registered
cd ~/docker/compose-files/cyberhawk-docker
docker compose build cyberhawk-api
docker compose up -d cyberhawk-api
```

Claude will then auto-select this skill via `mcp__cyberhawk__list_skills` whenever
a phishing EML is triaged.

### Option B — Claude Code (global skill install)

Install directly into Claude Code's skill directory so it's available in any project:

```bash
# Clone the repo
git clone https://github.com/rudraverma/phishing-email-investigation-skill.git

# Install into Claude Code's global skills folder
cp -r phishing-email-investigation-skill/phishing-email-deep-investigation \
  ~/.claude/skills/
```

That's it. No configuration required. Claude Code will automatically read
`SKILL.md` and apply this skill's methodology whenever a phishing investigation
is triggered.

---

## How to Use It

### In Claude Code — just describe the task

Once installed, you don't invoke it manually. Claude recognises the context and
applies the skill automatically. Examples of what triggers it:

> *"Investigate this phishing email"*
> *"I got a suspicious EML, run a full investigation"*
> *"Analyse this email — I think it's a phishing attempt"*
> *"Something's off about this DocuSign notification, check it"*

Claude will then walk through the full investigation — fetching live URLs,
deobfuscating JS, probing APIs — and return a structured report with IOCs
and MITRE ATT&CK mappings.

### On the CyberHawk Platform — upload and go

1. Drop your `.eml` file into `/workspace/upload/` via the CyberHawk UI
2. Tell Claude: *"New evidence uploaded, investigate"*
3. Claude triages → lists skills → selects this one → runs the full chain
4. Case artifacts are written to `/workspace/investigations/YYYY-MM-DD/<case>/`

---

## What Claude Investigates Automatically

Once triggered, Claude works through the full kill-chain without you needing
to issue any commands:

```
1. Email header authentication      DKIM / SPF / DMARC / Reply-To mismatch
2. DNS validation                   SPF record, DMARC policy, originating IP WHOIS
3. URL extraction                   Every link from plain text and HTML body
4. Live URL fetch                   Browser-realistic headers + correct Referer
5. JavaScript deobfuscation         All <script> blocks extracted and analysed
6. Attack type classification       Device Code / AiTM / Credential Harvest / QR
7. API backend probing              /health, /api/status, /api/generate + more
8. IOC extraction                   IPs, domains, URLs — all defanged
9. Structured report                TLP:AMBER, MITRE ATT&CK, prioritised recommendations
```

---

## Attack Types Detected

| Attack Type | Severity | MFA Bypassed | What Claude Finds |
|---|---|---|---|
| **OAuth Device Code Phishing** | 🔴 CRITICAL | ✅ Yes | Session ID, user code, API backend, victim count from `/health` |
| **AiTM Reverse Proxy** | 🔴 CRITICAL | ✅ Yes | Proxy domain, session cookie relay, JS injection |
| **Credential Harvesting** | 🟠 HIGH | ❌ No | POST endpoint, exfil target (Telegram bot, Discord webhook) |
| **QR Code Phishing** | 🟠 HIGH | ❌ No | Decoded QR URL, downstream lure page |
| **HTML Attachment** | 🟠 HIGH | ❌ No | Inline phishing page, base64 payloads, exfil calls |

---

## Example Output

```
PHISHING INVESTIGATION REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CLASSIFICATION: TLP:AMBER

From:         "Finance Team" <noreply@loadingdocuments.uk>
Subject:      Document Requires Your Review
Orig IP:      202.14.107.1 (Health New Zealand, NZ)

Verdict:      PHISHING — DEVICE CODE (MFA BYPASSED)
Severity:     CRITICAL

Lure page:    hxxps://auth[.]loadingdocuments[.]uk/lp/xYV2pMw6crY
Brand:        Adobe Acrobat Sign (impersonation)
User code:    FM624XDF7 → login.microsoftonline.com/common/oauth2/deviceauth

Backend API:  hxxps://api[.]loadingdocuments[.]uk:8443
/health:      active_tokens: 2,795  revoked_tokens: 1,022  (UNAUTHENTICATED)
/api/generate UNAUTHENTICATED — OpSec failure confirmed

MITRE ATT&CK:
  T1566.002 — Phishing: Spearphishing Link
  T1528     — Steal Application Access Token
  T1550.001 — Use Alternate Authentication Material
  T1111     — MFA Interception

Recommendations:
  [CRITICAL] Report OAuth app to Microsoft MSRC
  [CRITICAL] Block loadingdocuments[.]uk at DNS/proxy
  [CRITICAL] Audit Azure AD for device code sign-in events
  [HIGH]     Add Conditional Access policy restricting device code flow
```

---

## Package Contents

```
phishing-email-deep-investigation/
├── README.md                   ← You are here
├── SKILL.md                    ← Claude's investigation instructions (not for humans)
├── LICENSE                     ← Apache 2.0
├── scripts/
│   ├── agent.py                ← Full investigation agent (Claude executes this)
│   └── process.py              ← Quick IOC extractor
├── references/
│   ├── workflows.md            ← Kill-chain diagrams Claude references
│   ├── attack-patterns.md      ← JS signatures for each attack type
│   └── api-reference.md        ← curl, dig, whois, Azure KQL patterns
└── assets/
    └── template.md             ← TLP:AMBER report template
```

> **Note:** `SKILL.md` is instructions written for Claude — not a manual for humans.
> Claude reads it and follows the methodology automatically. You don't need to read it
> to use this skill.

---

## Requirements

| Requirement | Notes |
|---|---|
| Claude Code | Any version |
| Python 3.8+ | stdlib only — zero pip installs required |
| `curl` | Standard on Linux/macOS; included in CyberHawk Docker container |
| `dig` / `whois` | For DNS and IP lookups |
| Network access | Container must be able to reach live phishing infrastructure |

---

## Contributing & Contact

Built and maintained by [CyberHawk Threat Intel](https://www.cyberhawkthreatintel.com).

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
