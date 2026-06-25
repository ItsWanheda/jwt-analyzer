# JWT Analyzer v1.0.0

A professional, modular, and secure CLI-based tool for analyzing, verifying, and testing JSON Web Tokens (JWTs).

## Features

*   **Algorithm & Metadata Parser**: Extracts `alg`, `typ`, and standard claims.
*   **Time-Sensitive Validator**: Automatically calculates remaining validity time.
*   **Security Testing Suite**: Detects 'none' algorithm vulnerabilities.
*   **Brute-Force Hook**: Integrates wordlist-based signature verification.
*   **Payload Comparison**: Diffs two JWT payloads to identify state changes.
*   **RSA/JWK Verification**: Verifies tokens against public keys (RS256/ES256).
*   **Token Forgery**: Modifies payloads and re-signs tokens for active testing.
*   **Automated Reports**: Generates JSON reports for documentation.

## Installation
```bash
git clone https://github.com/yourusername/jwt-analyzer.git
cd jwt_analyzer
pip install -r requirements.txt
```
---

## Project Structure
```text

BUILD/jwt_analyzer/
├── core/
│   ├── __init__.py
│   ├── diff.py
│   ├── forgery.py
│   ├── parser.py
│   ├── security.py
│   └── verification.py
├── tests/
├── utils/
│   ├── __init__.py
│   ├── io.py
│   └── wordlists/
├── .gitignore
├── CHANGELOG.md
├── config.py
├── CONTRIBUTING.md
├── LICENSE
├── main.py
├── README.md
├── requirements.txt
├── sample_token.txt
└── SECURITY.md

```
---

## Usage

### Analyze a Token
```bash
python main.py analyze --token-file token.txt
```

### Verify with Public Key
```bash
python main.py verify-rsa --token-file token.txt --public-key public.pem
```

### Forge a Token
```bash 
python main.py forge --token-file original.txt --payload-file new_payload.json --secret mysecret
```

### Brute-Force Secret
```bash 
python main.py brute-force --token-file token.txt --wordlist wordlists/common_secrets.txt
```

### diff
```bash
python main.py diff --token1 <path_to_token1.txt> --token2 <path_to_token2.txt>
or 
python main.py diff --token1 old_token.txt --token2 new_token.txt
```
### Output:
```text 
Payload Differences
┌──────────┬──────────────┬──────────────┐
│ Key      │ Old Value    │ New Value    │
├──────────┼──────────────┼──────────────┤
│ role     │ user         │ admin        │
│ exp      │ 1678890000   │ 1678893600   │
└──────────┴──────────────┴──────────────┘
```

### verify-rsa
```bash
python main.py verify-rsa --token-file token.txt --public-key public_key.pem
```
### Output:
```text 
✅ Token is valid!
Payload: {'sub': '1234567890', 'name': 'John Doe'}

If invalid:
❌ Token verification failed: Invalid signature.

With Report:
python main.py verify-rsa --token-file token.txt 
--public-key public_key.pem --output report.json
```
---
## Advanced Usage
Using Environment Variables
```text
You can customize the tool's behavior using environment variables:

JWT_ANALYZER_WORDLIST_PATH: Path to a custom wordlist.

JWT_ANALYZER_TIMEOUT: Timeout for brute-force operations (in seconds).

JWT_ANALYZER_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR).

JWT_ANALYZER_ENABLE_RICH: Enable/disable Rich formatting (true/false).

Example:
JWT_ANALYZER_WORDLIST_PATH=/path/to/my/wordlist.txt python main.py brute-force --token-file token.txt

Generating Help
To see all available commands and options:
python main.py --help

To see help for a specific command:
python main.py analyze --help
```
---

## Troubleshooting
*ModuleNotFoundError:* Ensure you have installed the dependencies (pip install -r requirements.txt).

*FileNotFoundError:* Check that the paths to your token, wordlist, and public key files are correct.

*Invalid JWT format:* Ensure the token file contains only the JWT string (no extra whitespace or newlines).

*Invalid signature:* When using verify-rsa, ensure the public key matches the private key used to sign the token.

---
## Example Workflow

* ** Analyze a token to see its contents and expiration.**
* **Check security to ensure it's not using the 'none' algorithm.**
* **Verify the token using the server's public key to ensure it's legitimate.**
* **Compare it with another token to see what claims have changed.**
* **Forge a new token with elevated privileges (e.g., role: admin) to test if the application properly validates the signature.**
* **Generate a report for documentation purposes.**
---
## Contributing
We welcome contributions! Please see CONTRIBUTING.md for details on how to submit your ideas, bug reports, or pull requests.

---

## License
This project is licensed under the LICENSE file.
