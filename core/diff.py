from core.parser import parse_jwt

def compare_payloads(token1: str, token2: str) -> dict:
    parsed1 = parse_jwt(token1)
    parsed2 = parse_jwt(token2)
    
    payload1 = parsed1['payload']
    payload2 = parsed2['payload']
    
    keys1 = set(payload1.keys())
    keys2 = set(payload2.keys())
    
    common_keys = keys1 & keys2
    only_in_1 = keys1 - keys2
    only_in_2 = keys2 - keys1
    
    changes = {}
    for key in common_keys:
        if payload1[key] != payload2[key]:
            changes[key] = {'old': payload1[key], 'new': payload2[key]}
            
    return {
        'added': {k: payload2[k] for k in only_in_2},
        'removed': {k: payload1[k] for k in only_in_1},
        'changed': changes
    }