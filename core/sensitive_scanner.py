"""Scan JWT payloads for accidentally-included sensitive data.

JWTs are signed but NOT encrypted. base64-decoding them is trivial.
People keep putting credit cards, SSNs, passwords in payloads.
This catches the common cases.

Heuristic-based, not bulletproof. Better to false-positive than miss stuff.
"""

import re
import logging
from typing import Dict

logger = logging.getLogger(__name__)


# Patterns I've seen in the wild. Ordered by severity.
PATTERNS = {
    'credit_card': {
        'pattern': r'\b(?:\d[ -]*?){13,19}\b',
        'validator': '_luhn_check',
        'severity': 'CRITICAL',
        'description': 'Credit card number',
    },
    'ssn_us': {
        'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
        'severity': 'CRITICAL',
        'description': 'US Social Security Number',
    },
    'aws_access_key': {
        'pattern': r'\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b',
        'severity': 'CRITICAL',
        'description': 'AWS Access Key ID',
    },
    'private_key': {
        'pattern': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'severity': 'CRITICAL',
        'description': 'Private key material',
    },
    'nested_jwt': {
        'pattern': r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+',
        'severity': 'HIGH',
        'description': 'Nested JWT (token smuggling / confusion risk)',
    },
    'jwt_bearer': {
        'pattern': r'Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'severity': 'HIGH',
        'description': 'Bearer token string in payload',
    },
    'email': {
        'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'severity': 'MEDIUM',
        'description': 'Email address (PII depending on jurisdiction)',
    },
    'phone_us': {
        'pattern': r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'severity': 'MEDIUM',
        'description': 'US phone number',
    },
    'iban': {
        'pattern': r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b',
        'severity': 'HIGH',
        'description': 'IBAN (bank account)',
    },
    'password_field': {
        # catches: "password": "hunter2", password=foo, etc.
        'pattern': r'(?i)(password|passwd|pwd|secret|api_?key|access_?token)\s*["\':=]\s*["\']?([^\s"\'}{,]{4,})',
        'severity': 'HIGH',
        'description': 'Password/secret field with value',
    },
    'ipv4': {
        'pattern': r'\b(?:(?:25[0-5]|2[0-4]\d|?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|?\d\d?)\b',
        'severity': 'LOW',
        'description': 'IPv4 address',
    },
}


def _luhn_check(number: str) -> bool:
    """Luhn algorithm - what credit card numbers must satisfy."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = sum(digits[-1::-2])
    checksum += sum(sum(divmod(d * 2, 10)) for d in digits[-2::-2])
    return checksum % 10 == 0


def scan_payload_for_secrets(payload: dict) -> Dict:
    """Walk the payload recursively and flag any sensitive-looking values.

    Args:
        payload: the decoded JWT claims (dict)

    Returns:
        dict with findings grouped by severity + a human-readable summary
    """
    findings = {
        'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []
    }

    def walk(value, path=""):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, f"{path}.{k}" if path else k)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                walk(item, f"{path}[{i}]")
        elif isinstance(value, str):
            _check_value(value, path, findings)
        # ints, floats, bools, None - skip

    walk(payload)

    total = sum(len(v) for v in findings.values())
    return {
        'total_findings': total,
        'has_critical': bool(findings['CRITICAL']),
        'findings_by_severity': findings,
        'recommendation': (
            'JWT payloads are base64, not encrypted. Anyone with the token '
            'can read everything. Strip sensitive data before signing, or '
            'use opaque tokens + server-side sessions for sensitive stuff.'
            if total > 0 else
            'Nothing obviously sensitive. Still, audit what you actually need in the payload.'
        ),
    }


def _check_value(value: str, path: str, findings: dict):
    for name, cfg in PATTERNS.items():
        match = re.search(cfg['pattern'], value)
        if not match:
            continue

        # Some patterns have a validator (Luhn for credit cards)
        if cfg.get('validator') == '_luhn_check':
            if not _luhn_check(value):
                continue  # Random 16 digits aren't actually a card

        findings[cfg['severity']].append({
            'type': name,
            'description': cfg['description'],
            'field': path,
            'matched_text': match.group(0)[:20] + ('...' if len(match.group(0)) > 20 else ''),
            'severity': cfg['severity'],
        })
        # Don't return - check all patterns, one string might match multiple