import os

def read_token_from_file(file_path: str) -> str:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Token file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        token = f.read().strip()
    
    if token.count('.') != 2:
        raise ValueError("Invalid JWT format: Expected two dots separating header, payload, signature.")
    
    return token

def read_text_file(file_path: str) -> str:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()