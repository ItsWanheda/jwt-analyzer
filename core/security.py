"""Security vulnerability checks for JWTs.

Each function returns a dict describing the issue, or None/False if clean.
Kept stateless - no class needed.
"""

import jwt
import time
import logging
from typing import Optional
from config import Config

logger = logging.getLogger(__name__)


def check_none_algorithm(token: str) -> bool:
    """Detect 'none' algorithm - the classic JWT bypass (CVE-2015-9235).

    Some servers also accept 'None', 'NONE', 'nOnE'. We lowercase and compare.
    """
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get('alg', '')
        return alg.lower() == 'none'
    except Exception as e:
        # If we can't parse the header, that's its own problem but not 'none'
        logger.debug(f"Failed to parse header: {e}")
        return False


def check_algorithm_confusion(token: str) -> dict:
    """Check if token is vulnerable to HS/RS algorithm confusion.

    The attack: server expects RS256 (asymmetric), attacker sends HS256
    token signed with the public key as the HMAC secret. Vulnerable libs
    happily verify it.

    Returns dict with details about the algorithm in use.
    """
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get('alg', '')

        return {
            'algorithm': alg,
            'is_symmetric': alg in Config.SUPPORTED_SYMMETRIC_ALGORITHMS,
            'is_asymmetric': alg in Config.SUPPORTED_ASYMMETRIC_ALGORITHMS,
            # Asymmetric tokens can be attacked if server doesn't pin algorithm
            'vulnerable_to_confusion': alg in Config.SUPPORTED_ASYMMETRIC_ALGORITHMS,
        }
    except Exception as e:
        return {'error': str(e)}


def check_kid_injection(token: str) -> dict:
    """Check if the 'kid' (key ID) header is vulnerable to injection.

    Common attacks:
    - SQLi: kid = "' OR 1=1--"
    - Path traversal: kid = "../../../dev/null"  (signs with empty string!)
    - Command injection: kid = "key.pem; rm -rf /"

    Returns dict with vulnerability details.
    """
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get('kid', '')

        vulns = []

        # SQLi markers - not exhaustive but catches the common ones
        if any(p in kid.lower() for p in ["'", '"', ' or ', ' and ', ' union ', ' select ', '--', ';']):
            vulns.append('SQL_INJECTION')

        # Path traversal
        if '..' in kid or '%2e%2e' in kid.lower():
            vulns.append('PATH_TRAVERSAL')

        # Command injection markers
        if any(c in kid for c in ['`', '$', '|', '&', '\n', '\r']):
            vulns.append('COMMAND_INJECTION')

        return {
            'kid_present': bool(kid),
            'kid_value': kid[:100],  # truncate for logging safety
            'vulnerable': bool(vulns),
            'vulnerability_types': vulns,
        }
    except Exception as e:
        return {'error': str(e)}


def brute_force_secret(token: str, wordlist: list,
                       algorithms: Optional[list] = None,
                       timeout: int = 300) -> Optional[str]:
    """Try each secret in wordlist against the token.

    IMPORTANT: only tests symmetric algorithms (HS256/384/512).
    Asymmetric algs use keys, not secrets - feeding them a wordlist
    doesn't make sense and was actually a bug in v1.0.

    Returns the matching secret, or None.
    """
    if algorithms is None:
        algorithms = Config.SUPPORTED_SYMMETRIC_ALGORITHMS

    start = time.time()
    attempts = 0

    for secret in wordlist:
        if time.time() - start > timeout:
            logger.warning(f"Brute force timed out after {attempts} attempts")
            return None

        for alg in algorithms:
            attempts += 1
            try:
                jwt.decode(token, secret, algorithms=[alg])
                logger.info(f"Cracked in {attempts} attempts using {alg}")
                return secret
            except jwt.InvalidTokenError:
                continue  # expected - just wrong secret
            except Exception as e:
                # Unexpected errors (e.g., bad token format) - log and keep going
                logger.debug(f"Unexpected error on {alg}: {e}")
                continue

    return None