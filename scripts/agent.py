#!/usr/bin/env python3
"""
Phishing Email Deep Investigation Agent
Full kill-chain: headers → DNS → URL fetch → JS deobfuscation → API probe → IOC extraction
"""

import argparse
import email
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
from datetime import datetime
from email import policy

# ── Attack pattern signatures ──────────────────────────────────────────────────

DEVICE_CODE_PATTERNS = [
    r'deviceauth', r'user_code', r'device_code', r'devicelogin',
    r'oauth2/deviceauth', r'verification_uri', r'pollStatus',
    r'status.*captured', r'const\s+SID\s*=', r'const\s+API\s*=',
    r'const\s+SPATH', r'navigator\.clipboard\.writeText',
]

CREDENTIAL_HARVEST_PATTERNS = [
    r'type=["\']password["\']', r'name=["\']password["\']',
    r'id=["\']password["\']', r'POST.*login', r'submitCredential',
    r'stealCreds', r'exfil', r'webhook.*discord', r'telegram.*bot',
]

AITM_PATTERNS = [
    r'evilginx', r'modlishka', r'muraena', r'phishlet',
    r'relay.*cookie', r'session.*forward', r'proxy.*auth',
]

QR_PHISH_PATTERNS = [
    r'<img[^>]+\.png', r'<img[^>]+qr', r'data:image/png;base64',
]

# Paths to always probe on discovered API backends
API_PROBE_PATHS = [
    '/health', '/status', '/metrics',
    '/api/', '/api/status', '/api/generate', '/api/start',
    '/api/sessions', '/api/tokens', '/api/create', '/api/init',
    '/api/device', '/api/capture', '/admin',
]

BROWSER_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)


# ── Utility ────────────────────────────────────────────────────────────────────

def defang(s):
    return s.replace('http', 'hxxp').replace('.', '[.]')


def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return '', 'TIMEOUT', -1
    except Exception as e:
        return '', str(e), -1


def curl_get(url, referer=None, save_path=None, max_time=30):
    """Fetch URL with browser headers. Returns (headers_str, body_str, status_code)."""
    cmd = [
        'curl', '-sk', '-L', f'--max-time {max_time}',
        '-H', f'User-Agent: {BROWSER_UA}',
        '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        '-H', 'Accept-Language: en-US,en;q=0.9',
        '-D', '-',  # dump response headers to stdout before body
    ]
    if referer:
        cmd += ['-H', f'Referer: {referer}']
    if save_path:
        cmd += ['-o', save_path]
    cmd.append(url)

    stdout, stderr, rc = run(cmd, timeout=max_time + 5)

    # Split response headers from body
    headers_str, body = '', stdout
    for sep in ['\r\n\r\n', '\n\n']:
        if sep in stdout:
            headers_str, body = stdout.split(sep, 1)
            break

    status = 0
    m = re.search(r'HTTP/[\d.]+ (\d+)', headers_str)
    if m:
        status = int(m.group(1))

    return headers_str, body, status


# ── Email parsing ──────────────────────────────────────────────────────────────

def parse_eml(path):
    with open(path, 'r', errors='replace') as f:
        msg = email.message_from_file(f, policy=policy.default)

    auth_raw = msg.get('authentication-results', '')

    def auth_result(proto):
        m = re.search(rf'{proto}=(\w+)', auth_raw)
        return m.group(1) if m else 'none'

    body_parts = []
    attachments = []
    for part in msg.walk():
        ct = part.get_content_type()
        disp = part.get_content_disposition()
        if disp == 'attachment':
            payload = part.get_payload(decode=True) or b''
            attachments.append({
                'filename': part.get_filename('unknown'),
                'size': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
                'content_type': ct,
            })
        elif ct in ('text/plain', 'text/html'):
            try:
                body_parts.append(part.get_content())
            except Exception:
                body_parts.append(str(part.get_payload(decode=True) or b'', errors='replace'))

    full_body = '\n'.join(body_parts)
    full_raw  = str(msg)

    urls = sorted(set(re.findall(r'https?://[^\s<>"\'\\]+', full_body)))
    ips  = {ip for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', full_raw)
            if not ip.startswith(('127.', '0.', '255.', '192.168.', '10.'))}

    from_addr   = email.utils.parseaddr(msg.get('From', ''))[1]
    reply_to    = email.utils.parseaddr(msg.get('Reply-To', msg.get('From', '')))[1]
    received    = msg.get_all('Received') or []

    return {
        'from':         msg.get('From', ''),
        'from_addr':    from_addr,
        'to':           msg.get('To', ''),
        'subject':      msg.get('Subject', ''),
        'date':         msg.get('Date', ''),
        'message_id':   msg.get('Message-ID', ''),
        'reply_to':     msg.get('Reply-To', 'NOT PRESENT'),
        'reply_to_addr': reply_to,
        'return_path':  msg.get('Return-Path', 'NOT PRESENT'),
        'originating_ip': msg.get(
            'x-ms-exchange-organization-originalclientipaddress',
            msg.get('X-Originating-IP', 'NOT PRESENT')
        ),
        'auth': {
            'dkim':  auth_result('dkim'),
            'spf':   auth_result('spf'),
            'dmarc': auth_result('dmarc'),
            'raw':   auth_raw,
        },
        'reply_to_mismatch': from_addr != reply_to,
        'received_hops':  len(received),
        'received_chain': [h.strip()[:300] for h in reversed(received)],
        'urls':           urls,
        'ips_in_body':    list(ips),
        'attachments':    attachments,
        'body_preview':   full_body[:500],
    }


# ── DNS checks ─────────────────────────────────────────────────────────────────

def dns_check(domain, originating_ip=None):
    results = {}

    def dig(query):
        out, _, _ = run(['dig', query, '+short'], timeout=10)
        return out.strip()

    results['spf']   = dig(f'TXT {domain}')
    results['dmarc'] = dig(f'TXT _dmarc.{domain}')
    results['mx']    = dig(f'MX {domain}')

    if originating_ip and originating_ip != 'NOT PRESENT':
        results['rdns_originating'] = dig(f'-x {originating_ip}')
        out, _, _ = run(['whois', originating_ip], timeout=15)
        whois_fields = {}
        for line in out.splitlines():
            for field in ('netname', 'country', 'org-name', 'descr', 'inetnum', 'abuse-mailbox'):
                if line.lower().startswith(field):
                    whois_fields[field] = line.split(':', 1)[-1].strip()
        results['whois_originating'] = whois_fields

    return results


# ── Live URL investigation ─────────────────────────────────────────────────────

def classify_phishing_type(body, scripts_text):
    combined = body + scripts_text
    hits = {}
    for ptype, patterns in [
        ('device_code',        DEVICE_CODE_PATTERNS),
        ('credential_harvest', CREDENTIAL_HARVEST_PATTERNS),
        ('aitm',               AITM_PATTERNS),
        ('qr_phishing',        QR_PHISH_PATTERNS),
    ]:
        matched = [p for p in patterns if re.search(p, combined, re.IGNORECASE)]
        if matched:
            hits[ptype] = matched

    primary = max(hits, key=lambda k: len(hits[k])) if hits else 'unknown'
    return primary, hits


def extract_device_code_artifacts(body, scripts_text):
    arts = {}
    combined = scripts_text

    for label, pattern in [
        ('session_id',   r'(?:const|var)\s+SID\s*=\s*(\d+)'),
        ('api_base',     r"(?:const|var)\s+API\s*=\s*['\"]([^'\"]+)['\"]"),
        ('poll_path',    r"(?:SPATH|spath)\s*=\s*['\"]([^'\"]+)['\"]"),
        ('post_capture', r"(?:CLURE|clure)\s*=\s*['\"]([^'\"]*)['\"]"),
        ('user_code',    r'id=["\']userCode["\'][^>]*>([A-Z0-9]+)<'),
        ('oauth_url',    r'(https://login\.microsoftonline\.com[^\s\'"<>]+)'),
    ]:
        src = body if label in ('user_code', 'oauth_url') else combined
        m = re.search(pattern, src, re.IGNORECASE)
        arts[label] = m.group(1) if m else None

    return arts


def probe_api(api_base, session_id=None):
    results = {}
    parsed  = urllib.parse.urlparse(api_base)
    base    = f"{parsed.scheme}://{parsed.netloc}"

    for path in API_PROBE_PATHS:
        url  = base + path
        cmd  = ['curl', '-sk', '--max-time', '10', '-o', '/dev/null', '-w', '%{http_code}', url]
        out, _, _ = run(cmd, timeout=15)
        code = out.strip()
        if code and code not in ('000', '404', ''):
            body_cmd = ['curl', '-sk', '--max-time', '10', url]
            body, _, _ = run(body_cmd, timeout=15)
            results[path] = {'status': code, 'preview': body[:800]}

    if session_id:
        sid_url = f"{base}/api/status/{session_id}"
        body, _, _ = run(['curl', '-sk', '--max-time', '10', sid_url], timeout=15)
        results[f'/api/status/{session_id}'] = {'status': 'direct', 'preview': body}

        # Probe ±5 adjacent SIDs to estimate campaign density
        adjacent = {}
        sid_int = int(session_id)
        for delta in range(-5, 6):
            probe = f"{base}/api/status/{sid_int + delta}"
            b, _, _ = run(['curl', '-sk', '--max-time', '5', probe], timeout=10)
            try:
                adjacent[sid_int + delta] = json.loads(b).get('status', 'unknown')
            except Exception:
                adjacent[sid_int + delta] = b[:50] if b else 'error'
        results['adjacent_sessions'] = adjacent

    return results


def investigate_url(url, referer=None, output_dir='/tmp'):
    os.makedirs(output_dir, exist_ok=True)
    slug     = hashlib.md5(url.encode()).hexdigest()[:8]
    html_out = os.path.join(output_dir, f'lure_{slug}.html')
    hdr_out  = os.path.join(output_dir, f'headers_{slug}.txt')

    result = {
        'url':              url,
        'defanged':         defang(url),
        'status_code':      None,
        'content_length':   0,
        'saved_to':         html_out,
        'phishing_type':    'unknown',
        'phishing_hits':    {},
        'device_code':      {},
        'api_probe':        {},
        'iocs':             [],
        'scripts':          [],
        'error':            None,
    }

    headers_str, body, status = curl_get(url, referer=referer, save_path=html_out)

    # Write headers file separately
    with open(hdr_out, 'w') as f:
        f.write(headers_str)

    result['status_code']    = status
    result['content_length'] = len(body)

    if not body:
        result['error'] = 'Empty response or connection refused'
        return result

    # Script extraction
    scripts      = re.findall(r'<script[^>]*>([\s\S]*?)</script>', body, re.IGNORECASE)
    scripts      = [s.strip() for s in scripts if s.strip()]
    scripts_text = '\n'.join(scripts)
    result['scripts'] = scripts

    # Classify attack type
    phish_type, hits = classify_phishing_type(body, scripts_text)
    result['phishing_type'] = phish_type
    result['phishing_hits'] = hits

    # Device code deep-dive
    if phish_type == 'device_code' or hits.get('device_code'):
        dc = extract_device_code_artifacts(body, scripts_text)
        result['device_code'] = dc
        if dc.get('api_base'):
            result['api_probe'] = probe_api(dc['api_base'], session_id=dc.get('session_id'))

    # IOC extraction
    iocs = []
    raw_ips     = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body + scripts_text)
    raw_domains = re.findall(r'https?://([a-zA-Z0-9][a-zA-Z0-9.-]{1,61}\.[a-zA-Z]{2,})', body)
    raw_urls    = re.findall(r'https?://[^\s"\'<>]+', body)

    for ip in set(raw_ips):
        if not ip.startswith(('127.', '0.', '255.', '192.168.', '10.')):
            iocs.append({'type': 'ip', 'value': ip, 'defanged': defang(ip)})
    for d in set(raw_domains):
        iocs.append({'type': 'domain', 'value': d, 'defanged': defang(d)})
    for u in set(raw_urls):
        iocs.append({'type': 'url', 'value': u, 'defanged': defang(u)})

    result['iocs'] = iocs
    return result


# ── Main investigation orchestrator ───────────────────────────────────────────

def investigate(eml_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    decoded_dir = os.path.join(output_dir, 'decoded')
    os.makedirs(decoded_dir, exist_ok=True)

    report = {
        'timestamp':        datetime.utcnow().isoformat() + 'Z',
        'evidence':         eml_path,
        'email':            {},
        'dns':              {},
        'url_investigations': [],
        'assessment':       {},
        'iocs':             [],
        'mitre_attack':     [],
        'recommendations':  [],
    }

    # ── Step 1: Email parse ──
    print('[*] Parsing email headers and authentication...')
    report['email'] = parse_eml(eml_path)
    ea = report['email']
    print(f'    From:    {ea["from"]}')
    print(f'    Subject: {ea["subject"]}')
    print(f'    DKIM: {ea["auth"]["dkim"]}  SPF: {ea["auth"]["spf"]}  DMARC: {ea["auth"]["dmarc"]}')
    print(f'    Reply-To mismatch: {ea["reply_to_mismatch"]}')
    print(f'    URLs found: {len(ea["urls"])}')

    # ── Step 2: DNS validation ──
    if ea['from_addr']:
        domain = ea['from_addr'].split('@')[-1]
        print(f'[*] DNS checks for {domain}...')
        report['dns'] = dns_check(domain, ea['originating_ip'])

    # ── Steps 3–7: Live URL investigation ──
    for url in ea['urls']:
        print(f'\n[*] Investigating URL: {url}')
        inv = investigate_url(url, output_dir=decoded_dir)
        report['url_investigations'].append(inv)
        print(f'    Status: {inv["status_code"]}  Type: {inv["phishing_type"]}  Bytes: {inv["content_length"]}')
        if inv['device_code'].get('session_id'):
            print(f'    Device code SID: {inv["device_code"]["session_id"]}')
            print(f'    API base: {inv["device_code"].get("api_base")}')
            health = inv['api_probe'].get('/health', {})
            if health:
                print(f'    /health: {health.get("preview","")[:200]}')

    # ── Step 8: Aggregate IOCs ──
    all_iocs = []
    for inv in report['url_investigations']:
        all_iocs.extend(inv.get('iocs', []))
    for ip in ea['ips_in_body']:
        all_iocs.append({'type': 'ip', 'value': ip, 'defanged': defang(ip), 'source': 'email_header'})
    report['iocs'] = all_iocs

    # ── Assessment ──
    phish_types  = [i['phishing_type'] for i in report['url_investigations']]
    primary_type = ('device_code'        if 'device_code'        in phish_types else
                    'credential_harvest' if 'credential_harvest' in phish_types else
                    'aitm'               if 'aitm'               in phish_types else
                    phish_types[0]       if phish_types else 'header_only')

    severity = ('CRITICAL' if primary_type in ('device_code', 'aitm') else 'HIGH')

    report['assessment'] = {
        'verdict':           'PHISHING',
        'primary_type':      primary_type,
        'severity':          severity,
        'mfa_bypassed':      primary_type in ('device_code', 'aitm'),
        'urls_investigated': len(report['url_investigations']),
        'auth_summary':      ea['auth'],
        'reply_to_mismatch': ea['reply_to_mismatch'],
    }

    # ── MITRE ATT&CK ──
    techniques = ['T1566.002 — Phishing: Spearphishing Link']
    if primary_type == 'device_code':
        techniques += [
            'T1528     — Steal Application Access Token',
            'T1550.001 — Use Alternate Authentication Material: Token',
            'T1111     — MFA Interception',
            'T1583.006 — Acquire Infrastructure: Web Services',
        ]
    elif primary_type == 'credential_harvest':
        techniques += [
            'T1056.003 — Input Capture: Web Portal Capture',
            'T1598.003 — Phishing for Information: Spearphishing Link',
        ]
    elif primary_type == 'aitm':
        techniques += [
            'T1557     — Adversary-in-the-Middle',
            'T1539     — Steal Web Session Cookie',
            'T1111     — MFA Interception',
        ]
    report['mitre_attack'] = techniques

    # ── Recommendations ──
    recs = []
    if primary_type == 'device_code':
        recs += [
            {'p': 'CRITICAL', 'a': 'Report OAuth app to Microsoft MSRC — device code flow for this app can be revoked'},
            {'p': 'CRITICAL', 'a': 'Block phishing domain at DNS/proxy across all O365 tenants immediately'},
            {'p': 'CRITICAL', 'a': 'Audit Azure AD sign-in logs for device code flow events referencing this domain'},
            {'p': 'HIGH',     'a': 'Add Conditional Access policy restricting device code OAuth to managed/compliant devices'},
            {'p': 'HIGH',     'a': 'Enable Identity Protection risky sign-in alerts for device code auth events'},
        ]
    elif primary_type == 'credential_harvest':
        recs += [
            {'p': 'CRITICAL', 'a': 'Force password reset for any users who visited the lure page'},
            {'p': 'HIGH',     'a': 'Check proxy logs for POST requests to phishing domain — confirms credential submission'},
        ]
    elif primary_type == 'aitm':
        recs += [
            {'p': 'CRITICAL', 'a': 'Revoke all active sessions for exposed users — AiTM steals authenticated session cookies'},
            {'p': 'CRITICAL', 'a': 'Enable Continuous Access Evaluation (CAE) to invalidate stolen tokens faster'},
        ]
    recs += [
        {'p': 'HIGH',   'a': 'Block all discovered IOC domains and IPs at perimeter firewall, proxy, and DNS'},
        {'p': 'HIGH',   'a': 'Report domain to Cloudflare abuse and hosting registrar'},
        {'p': 'MEDIUM', 'a': 'Notify affected/at-risk users with clear guidance on what to watch for'},
        {'p': 'MEDIUM', 'a': 'Submit IOCs to threat intel platform (MISP / ThreatConnect / OTX)'},
    ]
    report['recommendations'] = [{'priority': r['p'], 'action': r['a']} for r in recs]

    # ── Write JSON report ──
    report_path = os.path.join(output_dir, 'investigation_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    return report, report_path


# ── CLI output ─────────────────────────────────────────────────────────────────

def print_summary(report):
    ea  = report['email']
    asm = report['assessment']
    SEP = '━' * 60

    print(f'\n{SEP}')
    print('PHISHING INVESTIGATION SUMMARY')
    print(f'{SEP}')
    print(f'From:         {ea["from"]}')
    print(f'Subject:      {ea["subject"]}')
    print(f'Orig IP:      {ea["originating_ip"]}')
    print(f'\nVerdict:      {asm["verdict"]}')
    print(f'Attack type:  {asm["primary_type"]}')
    print(f'Severity:     {asm["severity"]}')
    print(f'MFA bypassed: {asm["mfa_bypassed"]}')
    print(f'\nAuthentication:')
    auth = asm['auth_summary']
    print(f'  DKIM:  {auth["dkim"]}')
    print(f'  SPF:   {auth["spf"]}')
    print(f'  DMARC: {auth["dmarc"]}')
    print(f'  Reply-To mismatch: {asm["reply_to_mismatch"]}')

    for inv in report['url_investigations']:
        print(f'\nURL: {inv["defanged"]}')
        print(f'  Status: {inv["status_code"]}  Type: {inv["phishing_type"]}')
        dc = inv.get('device_code', {})
        if dc.get('session_id'):
            print(f'  Device code SID:  {dc["session_id"]}')
            print(f'  User code shown:  {dc.get("user_code")}')
            print(f'  API base:         {dc.get("api_base")}')
            health = inv.get('api_probe', {}).get('/health', {})
            if health:
                try:
                    h = json.loads(health.get('preview', '{}'))
                    db = h.get('checks', {}).get('database', {})
                    if db:
                        print(f'  Active victims:   {db.get("active_tokens", "?")}')
                        print(f'  Captured tokens:  {db.get("revoked_tokens", "?")}')
                except Exception:
                    pass

    print(f'\nMITRE ATT&CK:')
    for t in report['mitre_attack']:
        print(f'  {t}')

    print(f'\nTop Recommendations:')
    for r in report['recommendations'][:4]:
        print(f'  [{r["priority"]}] {r["action"]}')

    unique_ioc_domains = {i['defanged'] for i in report['iocs'] if i['type'] == 'domain'}
    print(f'\nIOC domains ({len(unique_ioc_domains)}):')
    for d in sorted(unique_ioc_domains)[:10]:
        print(f'  {d}')


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Phishing Email Deep Investigation Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 agent.py /workspace/upload/sample.eml
  python3 agent.py /workspace/upload/sample.eml --output-dir /workspace/investigations/2026-01-01/case1
  python3 agent.py /workspace/upload/sample.eml --json
        '''
    )
    parser.add_argument('eml_path', help='Path to EML file')
    parser.add_argument('--output-dir', default='/tmp/phishing_investigation',
                        help='Output directory (default: /tmp/phishing_investigation)')
    parser.add_argument('--json', action='store_true', help='Print full JSON report to stdout')
    args = parser.parse_args()

    if not os.path.isfile(args.eml_path):
        print(f'[!] File not found: {args.eml_path}', file=sys.stderr)
        sys.exit(1)

    report, report_path = investigate(args.eml_path, args.output_dir)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_summary(report)
        print(f'\n[✓] Full JSON report: {report_path}')


if __name__ == '__main__':
    main()
