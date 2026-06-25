"""Configuration handling.

Priority: defaults < config file < env vars.
Loaded lazily on first access.
"""

import os
from pathlib import Path


class Config:
    # Defaults - these get overridden by env vars or config files
    DEFAULT_WORDLIST_PATH = os.getenv(
        "JWT_ANALYZER_WORDLIST_PATH",
        str(Path(__file__).parent / "wordlists" / "common_secrets.txt")
    )

    # I'm being explicit about which algs are HMAC vs asymmetric
    # because the brute force function needs to know the difference
    SUPPORTED_SYMMETRIC_ALGORITHMS = ["HS256", "HS384", "HS512"]
    SUPPORTED_ASYMMETRIC_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

    BRUTE_FORCE_TIMEOUT = int(os.getenv("JWT_ANALYZER_TIMEOUT", "300"))
    LOG_LEVEL = os.getenv("JWT_ANALYZER_LOG_LEVEL", "INFO").upper()
    ENABLE_RICH_FORMATTING = os.getenv("JWT_ANALYZER_ENABLE_RICH", "true").lower() == "true"

    @classmethod
    def get_wordlist_path(cls) -> str:
        return cls.DEFAULT_WORDLIST_PATH

    @classmethod
    def get_supported_algorithms(cls) -> list:
        return cls.SUPPORTED_SYMMETRIC_ALGORITHMS + cls.SUPPORTED_ASYMMETRIC_ALGORITHMS

    @classmethod
    def is_rich_enabled(cls) -> bool:
        return cls.ENABLE_RICH_FORMATTING