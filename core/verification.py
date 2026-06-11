import jwt
import json

def verify_with_public_key(token: str, key_content: str, algorithms: list = None) -> dict:
    if algorithms is None:
        algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
        
    try:
        key_content = key_content.strip()
        
        if key_content.startswith('{'):
            key = jwt.algorithms.RSAAlgorithm.from_jwk(key_content)
        else:
            key = jwt.algorithms.RSAAlgorithm.from_pem(key_content.encode())
            
        payload = jwt.decode(token, key, algorithms=algorithms)
        return {"status": "valid", "payload": payload}
        
    except jwt.InvalidTokenError as e:
        return {"status": "invalid", "error": str(e)}
    except Exception as e:
        return {"status": "error", "error": str(e)}