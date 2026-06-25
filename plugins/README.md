# 🔌 Plugins

Extend jwt-analyzer with custom security checks without touching the core
codebase. Drop a file in this directory, restart the tool, and your checks
run alongside the built-in ones.

## Quick Example

**1. Create a file** (must end in `_plugin.py`):

```python
# plugins/required_claims_plugin.py

class RequiredClaimsPlugin:
    name = "required_claims"
    description = "Verifies the token has all claims we expect"

    REQUIRED = ["sub", "iat", "exp", "tenant_id"]

    def check(self, token: str) -> dict | None:
        import jwt
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            return {
                "severity": "INFO",
                "title": "Could not decode token",
                "description": str(e),
                "remediation": "Token is malformed."
            }

        missing = [c for c in self.REQUIRED if c not in payload]
        if missing:
            return {
                "severity": "HIGH",
                "title": f"Missing required claims: {missing}",
                "description": "Token is missing claims our app requires.",
                "remediation": f"Ensure your issuer always sets: {', '.join(missing)}"
            }
        return None  # No issues found


def register():
    return RequiredClaimsPlugin()
```

**2. That's it.** The next time you run `jwt-analyzer audit`, your plugin
runs automatically. No config, no registration, no imports to wire up.

```bash
$ python main.py audit --token-file token.txt

Audit Summary
  Critical: 0
  High:     1    ← from your plugin!
  Medium:   0
  Low:      0
```

---

## 📁 Where Do Plugins Go?

```
jwt-analyzer/
└── plugins/
    ├── README.md                   ← you are here
    ├── plugins.py                  ← the loader (don't modify)
    ├── required_claims_plugin.py   ← your plugin
    ├── tenant_isolation_plugin.py  ← another plugin
    └── ...
```

**Rules:**
- Files **must** end in `_plugin.py` (the loader uses a glob)
- Module name (without `.py`) is what gets imported — keep it descriptive
- One plugin class per file is the convention, but not strictly required
- Anything else in this directory is ignored

---

## 🔧 Plugin Interface

Every plugin module must expose a `register()` function that returns a
plugin object with two things: a `.name` and a `.check(token)` method.

### The bare minimum

```python
class MyPlugin:
    name = "my_plugin"

    def check(self, token: str):
        # your logic here
        ...
        return None  # or a findings dict

def register():
    return MyPlugin()
```

### The `name` attribute

- **Required**: yes
- **Type**: string
- **Used for**: logging, identifying findings, dedup
- **Must be unique** across all loaded plugins

```python
name = "tenant_isolation"     # ✅ good
name = "plugin1"              # ❌ not descriptive
name = "my_organizations_jwt" # ⚠️ verbose but okay
```

### The `check(token)` method

**Signature:** `check(self, token: str) -> dict | None`

**Args:**
- `token`: the raw JWT string (not decoded — decode it yourself)

**Returns:**
- `None` or `{}` → no findings, move on
- A findings dict (see format below) → gets added to the report

**Notes:**
- Should be **safe to fail** — if your plugin crashes, jwt-analyzer logs
  the error and continues. Other plugins still run.
- Don't print to stdout — use the `logging` module
- Keep it fast — this runs on every audit

---

## 📋 Return Value Format

To integrate cleanly with the main `audit` command, return a dict matching
this schema:

```python
{
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
    "title": "Short headline (under 60 chars)",
    "description": "What's wrong and why it matters",
    "remediation": "How to fix it (optional but recommended)",
    # Any extra keys you want to include will be preserved in the report
}
```

| Severity | When to use |
|----------|-------------|
| `CRITICAL` | Direct security risk (auth bypass, leaked secrets) |
| `HIGH` | Significant issue but not immediately exploitable |
| `MEDIUM` | Best practice violation or hygiene issue |
| `LOW` | Cosmetic / informational |
| `INFO` | Just noting something, no action needed |

The `audit` command's exit code is based on the highest severity across
all findings (including your plugin's). CRITICAL → exit 2.

---

## 📚 Real-World Examples

### Example 1: Revocation list check

```python
# plugins/revocation_check_plugin.py
"""Check if the token's jti (JWT ID) is in our revocation list."""
import os
import jwt
import requests

REVOCATION_API = os.getenv("REVOCATION_API_URL", "https://internal/revoked-jtis")
TIMEOUT = 5


class RevocationCheckPlugin:
    name = "revocation_check"
    description = "Verifies the token's jti is not in our revocation list"

    def check(self, token: str) -> dict | None:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None  # malformed tokens handled by core checks

        jti = payload.get("jti")
        if not jti:
            return None  # no jti = can't check, skip silently

        try:
            resp = requests.get(f"{REVOCATION_API}/{jti}", timeout=TIMEOUT)
        except requests.RequestException as e:
            # Fail closed or open? Your call. I'm going open here.
            return {
                "severity": "INFO",
                "title": "Could not reach revocation API",
                "description": f"Revocation check skipped: {e}",
            }

        if resp.status_code == 200:
            return {
                "severity": "CRITICAL",
                "title": "Token has been revoked",
                "description": f"jti '{jti}' is in the revocation list.",
                "remediation": "Force the user to re-authenticate immediately.",
            }

        return None


def register():
    return RevocationCheckPlugin()
```

### Example 2: Tenant isolation check

```python
# plugins/tenant_isolation_plugin.py
"""Enforce that tokens carry our tenant_id and that it matches the request."""
import os
import jwt


class TenantIsolationPlugin:
    name = "tenant_isolation"

    # In a real plugin you'd pull this from config or env
    EXPECTED_TENANT = os.getenv("EXPECTED_TENANT_ID")

    def check(self, token: str) -> dict | None:
        if not self.EXPECTED_TENANT:
            # Plugin not configured, skip
            return None

        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None

        actual = payload.get("tenant_id")
        if not actual:
            return {
                "severity": "HIGH",
                "title": "Token has no tenant_id",
                "description": "Multi-tenant systems must scope tokens by tenant.",
                "remediation": "Add tenant_id claim at token issuance time.",
            }

        if actual != self.EXPECTED_TENANT:
            return {
                "severity": "HIGH",
                "title": f"Token for wrong tenant (got: {actual})",
                "description": "Token was issued for a different tenant than expected.",
                "remediation": "Reject tokens whose tenant_id doesn't match the request scope.",
            }

        return None


def register():
    return TenantIsolationPlugin()
```

### Example 3: Issuer allowlist

```python
# plugins/issuer_allowlist_plugin.py
"""Only accept tokens from our known issuers."""
import os
import jwt


class IssuerAllowlistPlugin:
    name = "issuer_allowlist"
    description = "Enforces that the iss claim is in our allowlist"

    ALLOWED = set(filter(None, os.getenv(
        "ALLOWED_ISSUERS",
        "https://auth.example.com,https://auth-staging.example.com"
    ).split(",")))

    def check(self, token: str) -> dict | None:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None

        iss = payload.get("iss")
        if not iss:
            return {
                "severity": "MEDIUM",
                "title": "Token has no iss claim",
                "description": "Issuer-less tokens can't be attributed to a trusted source.",
                "remediation": "Always set iss claim when issuing tokens.",
            }

        if iss not in self.ALLOWED:
            return {
                "severity": "HIGH",
                "title": f"Token from unknown issuer: {iss}",
                "description": f"Allowed issuers: {sorted(self.ALLOWED)}",
                "remediation": "Reject tokens from untrusted issuers at the gateway.",
            }

        return None


def register():
    return IssuerAllowlistPlugin()
```

---

## 🧪 Testing Your Plugin

Before shipping a plugin, test it with a known-good and a known-bad token:

```python
# test_my_plugin.py (throwaway script, not part of the repo)
import importlib

# Hack to import plugins as a package
import sys
sys.path.insert(0, ".")

mod = importlib.import_module("plugins.required_claims_plugin")
plugin = mod.register()

# Test with a token that's missing claims
bad_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.fake"
result = plugin.check(bad_token)
print(result)
# Should print: {'severity': 'HIGH', 'title': "Missing required claims: [...]", ...}

# Test with a complete token
good_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OSwidGVuYW50X2lkIjoidGVuYW50MSJ9.fake"
result = plugin.check(good_token)
print(result)
# Should print: None
```

You can also verify the plugin loads properly:

```bash
python -c "from plugins.plugins import PluginManager; pm = PluginManager(); pm.load_plugins(); print(pm.plugins)"
```

If your plugin appears in the dict, it's loaded. If you see a traceback,
fix it before running the full audit.

---

## ⚠️ Gotchas

| Gotcha | Why it bites you | Fix |
|--------|------------------|-----|
| Filename doesn't end in `_plugin.py` | Loader silently skips it | Always name files `<something>_plugin.py` |
| `register()` not defined | Loader logs an error and skips the plugin | Always include the `register()` function |
| Two plugins have the same `name` | Second one wins, first is overwritten | Use unique, descriptive names |
| Plugin does `print()` instead of `logging` | Clutters the CLI output, breaks JSON output | Use `logger = logging.getLogger(__name__)` |
| Plugin hangs (network call without timeout) | Audit never finishes | Always set timeouts on external calls |
| Plugin raises an exception | That single plugin fails, but others run | Wrap risky code in try/except |
| Plugin modifies the token | Don't. Just read it. | Treat `token` as immutable input |
| Heavy import in module top-level | Slows down every audit, even ones that don't use it | Lazy-import inside `check()` |

---

## 🚧 Limitations

The current plugin API is intentionally simple. Here's what it **can't** do:

- ❌ Modify the JWT payload (by design — too dangerous)
- ❌ Add new CLI commands (use Click groups if you need that)
- ❌ Run before/after specific built-in checks (no hook ordering yet)
- ❌ Receive config other than env vars
- ❌ Persist state between runs (no plugin-level storage)

If you need any of these, open an issue — the loader was kept simple on
purpose but could grow.

---

## 📦 Sharing Your Plugin

Made something useful? A few options:

1. **Internal use**: Just commit it to your fork's `plugins/` directory
2. **Team use**: Package as a separate pip-installable plugin package
   (would require extending the loader to support entry_points — open an issue)
3. **Public**: For now, paste it in a GitHub Gist or discussion thread

There's no official plugin registry yet. If you build something that should
be shared widely, let us know and we'll figure out a proper distribution
mechanism.

---

## 🆘 Debugging

**Plugin not loading?**

```bash
# Check the loader can find it
python -c "from pathlib import Path; print(list(Path('plugins').glob('*_plugin.py')))"

# Check it imports without errors
python -c "import plugins.my_plugin_plugin"

# Check the register() function works
python -c "from plugins.my_plugin_plugin import register; print(register())"
```

**Plugin crashes silently?**

Look at the logs with debug enabled:

```bash
python main.py --verbose audit --token-file token.txt
```

Plugin errors show up as:
```
ERROR plugins.plugins: Plugin my_plugin failed: <error here>
```

**Plugin loads but doesn't fire?**

- Make sure `check()` returns a dict, not a list, not `True`
- Make sure `name` doesn't collide with another plugin
- Add a `logger.debug("plugin fired")` at the top of `check()` to confirm
  it's being called

---

## 📚 See Also

- [Main README](../README.md) — for the tool overview
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) — for what to check
- [PyJWT docs](https://pyjwt.readthedocs.io/) — for decoding tokens in your plugin