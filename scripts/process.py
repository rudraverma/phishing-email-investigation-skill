#!/usr/bin/env python3
"""
Phishing Email Quick Processor
Lightweight version: extracts IOCs, classifies attack type, outputs JSON.
No live URL fetching — use agent.py for full investigation.
"""

import email
import hashlib
import json
import re
import sys
from email import policy

DEVICE_CODE_PATTERNS = [
    r'deviceauth', r'user_code', r'verification_uri', r'pollStatus',
    r'const\s+SID\s*=', r'const\s+API\s*=',
]
CRED_HARVEST_PATTERNS = [
    r'type=["\']password["\']', r'POST.*login', r'stealCreds',
]
AITM_PATTERNS = [
    r'evilginx', r'modlishka', r'relay.*cookie',
]


def defang(s):
    return s.replace('http', 'hxxp').replace('.', '[.]')


def quick_process(eml_path):
    with open(eml_path, 'r', errors='replace') as f:
        msg = email.message_from_file(f, policy=policy.default)

    # Hash the file
    with open(eml_path, 'rb') as f:
        raw = f.read()
    file_hashes = {
        'md5':    hashlib.md5(raw).hexdigest(),
        'sha1':   hashlib.sha1(raw).hexdigest(),
        'sha256': hashlib.sha256(raw).hexdigest(),
    }

    # Auth
    auth_raw = msg.get('authentication-results', '')
    def auth_val(p):
        m = re.search(rf'{p}=(\w+)', auth_raw)
        return m.group(1) if m else 'none'

    # Body
    body = ''
    for part in msg.walk():
        ct = part.get_content_type()
        if ct in ('text/plain', 'text/html'):
            try:
                body += part.get_content()
            except Exception:
                body += str(part.get_payload(decode=True) or b'', errors='replace')

    urls  = sorted(set(re.findall(r'https?://[^\s<>"\'\\]+', body)))
    ips   = {ip for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(msg))
             if not ip.startswith(('127.', '0.', '255.', '192.168.', '10.'))}

    # Quick phishing classification from body text alone
    def classify(text):
        for ptype, pats in [
            ('device_code', DEVICE_CODE_PATTERNS),
            ('credential_harvest', CRED_HARVEST_PATTERNS),
            ('aitm', AITM_PATTERNS),
        ]:
            if any(re.search(p, text, re.IGNORECASE) for p in pats):
                return ptype
        return 'unknown'

    phish_type = classify(body)

    # IOCs
    iocs = (
        [{'type': 'url',    'value': u, 'defanged': defang(u)} for u in urls] +
        [{'type': 'ip',     'value': ip, 'defanged': defang(ip)} for ip in sorted(ips)] +
        [{'type': 'domain', 'value': m, 'defanged': defang(m)}
         for m in sorted(set(re.findall(r'https?://([a-zA-Z0-9.-]+)', body)))]
    )

    return {
        'file':         eml_path,
        'hashes':       file_hashes,
        'from':         msg.get('From', ''),
        'subject':      msg.get('Subject', ''),
        'date':         msg.get('Date', ''),
        'auth': {
            'dkim':  auth_val('dkim'),
            'spf':   auth_val('spf'),
            'dmarc': auth_val('dmarc'),
        },
        'urls':         urls,
        'phish_type':   phish_type,
        'iocs':         iocs,
        'note':         'Run agent.py for live URL fetch and full investigation',
    }


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else '/workspace/upload/sample.eml'
    result = quick_process(path)
    print(json.dumps(result, indent=2))
