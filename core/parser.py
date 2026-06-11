import jwt
import time
import base64
import json
from datetime import datetime

def _base64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def parse_jwt(token: str) -> dict:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format.")
        
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        
        expiry_info = {}
        if 'exp' in payload:
            exp_timestamp = payload['exp']
            current_time = time.time()
            remaining = exp_timestamp - current_time
            expiry_info = {
                'exp_timestamp': exp_timestamp,
                'remaining_seconds': remaining,
                'is_expired': remaining < 0,
                'exp_datetime': datetime.utcfromtimestamp(exp_timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            }
        
        return {
            'header': header,
            'payload': payload,
            'expiry_info': expiry_info
        }
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in JWT: {e}")
    except Exception as e:
        raise ValueError(f"JWT Parse Error: {e}")