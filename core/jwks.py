"""JWKS (JSON Web Key Set) support - fetch public keys from a URL.

Most modern auth providers expose /.well-known/jwks.json. This lets you
verify tokens without having the public key file locally.

Has a simple in-memory cache so we don't hammer the endpoint on every call.
"""

import jwt
import logging
import time
import requests
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class _JWKSCache:
    """Tiny TTL cache. Not thread-safe but good enough for CLI usage."""

    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self._store: Dict[str, tuple] = {}  # url -> (data, fetched_at)

    def get(self, url: str) -> Optional[dict]:
        if url not in self._store:
            return None
        data, ts = self._store[url]
        if time.time() - ts > self.ttl:
            del self._store[url]
            return None
        return data

    def set(self, url: str, data: dict):
        self._store[url] = (data, time.time())

    def clear(self):
        self._store.clear()


_cache = _JWKSCache()


def clear_cache():
    """For tests. Call between test cases."""
    _cache.clear()


def fetch_jwks(url: str, timeout: int = 10, verify_ssl: bool = True) -> dict:
    """Fetch JWKS from URL, with caching.

    Raises:
        ConnectionError: network/SSL issues
        ValueError: response isn't valid JSON
    """
    cached = _cache.get(url)
    if cached:
        logger.debug(f"JWKS cache hit: {url}")
        return cached

    logger.info(f"Fetching JWKS: {url}")
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=verify_ssl,
            headers={'User-Agent': 'jwt-analyzer/1.1'},
        )
        resp.raise_for_status()
    except requests.exceptions.SSLError as e:
        raise ConnectionError(
            f"SSL verification failed for {url}. "
            f"Use --no-verify-ssl if this is intentional (it usually isn't)."
        ) from e
    except requests.exceptions.Timeout:
        raise ConnectionError(f"Timeout fetching {url} after {timeout}s")
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to fetch {url}: {e}")

    try:
        data = resp.json()
    except ValueError as e:
        raise ValueError(f"JWKS response isn't valid JSON: {e}")

    if 'keys' not in data or not isinstance(data['keys'], list):
        raise ValueError(f"JWKS response missing 'keys' array: {url}")

    _cache.set(url, data)
    logger.info(f"Got {len(data['keys'])} keys from {url}")
    return data


def _find_key(jwks: dict, kid: str):
    """Find a key in the JWKS by kid."""
    for key in jwks.get('keys', []):
        if key.get('kid') == kid:
            return key
    return None


def verify_with_jwks(token: str, jwks_url: str,
                     algorithms: Optional[list] = None,
                     verify_ssl: bool = True) -> dict:
    """Verify a JWT against keys fetched from a JWKS URL.

    The token's 'kid' header tells us which key to use.
    """
    if algorithms is None:
        algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')

        if not kid:
            return {"status": "error", "error": "Token has no 'kid' header - can't look up key"}

        jwks = fetch_jwks(jwks_url, verify_ssl=verify_ssl)
        key_data = _find_key(jwks, kid)

        if not key_data:
            available = [k.get('kid', '<no kid>') for k in jwks.get('keys', [])]
            return {
                "status": "error",
                "error": f"kid '{kid}' not found in JWKS. Available: {available}"
            }

        # Convert JWK to a key object PyJWT can use
        key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data) if key_data.get('kty') == 'RSA' \
              else jwt.algorithms.ECAlgorithm.from_jwk(key_data)

        payload = jwt.decode(token, key, algorithms=algorithms)
        return {"status": "valid", "payload": payload, "kid": kid}

    except jwt.InvalidTokenError as e:
        return {"status": "invalid", "error": str(e)}
    except (ConnectionError, ValueError) as e:
        return {"status": "error", "error": str(e)}
    except Exception as e:
        logger.exception("Unexpected error in verify_with_jwks")
        return {"status": "error", "error": f"Unexpected: {e}"}