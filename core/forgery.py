import jwt
import json
from core.parser import _base64url_decode

def forge_token(token: str, new_payload: dict, secret: str, algorithm: str = "HS256") -> str:
    try:
        # Decode original header to preserve typ and other standard fields
        parts = token.split('.')
        original_header = json.loads(_base64url_decode(parts[0]))
        
        # Create new header
        header = {
            "alg": algorithm,
            "typ": "JWT"
        }
        
        # Encode new payload
        encoded_payload = jwt.encode(new_payload, secret, algorithm=algorithm)
        
        # Extract the payload part from the encoded string (it's just the payload encoded)
        # jwt.encode returns header.payload.signature
        new_token_parts = encoded_payload.split('.')
        new_payload_part = new_token_parts[1]
        
        # Construct the new token manually to ensure we only change the payload
        # Note: jwt.encode handles the signature calculation
        forged_token = jwt.encode(new_payload, secret, algorithm=algorithm)
        
        return forged_token
    except Exception as e:
        raise ValueError(f"Forgery failed: {e}")