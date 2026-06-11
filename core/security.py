import jwt
from config import Config

def check_none_algorithm(token: str) -> bool:
    try:
        header = jwt.get_unverified_header(token)
        return header.get('alg', '').lower() == 'none'
    except Exception:
        return False

def brute_force_secret(token: str, wordlist: list) -> str | None:
    algorithms = Config.get_supported_algorithms()
    for secret in wordlist:
        try:
            jwt.decode(token, secret, algorithms=algorithms)
            return secret
        except jwt.InvalidTokenError:
            continue
    return None