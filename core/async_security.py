"""Parallel brute force using threads.

For small wordlists (<1k) sequential is actually faster due to thread overhead.
Switch to this for 5k+ secrets. Default 8 workers works well on most boxes.
"""

import jwt
import time
import logging
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import Config

logger = logging.getLogger(__name__)


def brute_force_parallel(token: str, wordlist: List[str],
                         workers: int = 8,
                         algorithms: Optional[List[str]] = None,
                         timeout: int = 300) -> Optional[str]:
    """Brute force using a thread pool. Returns secret or None.

    Args:
        token: target JWT
        wordlist: list of candidate secrets
        workers: thread count (default 8)
        algorithms: which algs to try (default: all symmetric)
        timeout: give up after N seconds

    Returns:
        the matching secret, or None
    """
    if algorithms is None:
        algorithms = Config.SUPPORTED_SYMMETRIC_ALGORITHMS

    if not wordlist:
        logger.warning("Empty wordlist")
        return None

    # If wordlist is tiny, don't bother with threads
    if len(wordlist) < 100:
        workers = 1

    found_secret = None
    start = time.time()
    attempts = 0
    stop_flag = [False]  # mutable flag for workers to check

    def try_one(secret: str) -> Optional[str]:
        nonlocal attempts
        if stop_flag:
            return None
        for alg in algorithms:
            attempts += 1
            try:
                jwt.decode(token, secret, algorithms=[alg])
                return secret
            except jwt.InvalidTokenError:
                continue
            except Exception:
                continue
        return None

    # Using 'with' so threads get cleaned up on exception
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(try_one, s): s for s in wordlist}

        try:
            for future in as_completed(futures):
                if time.time() - start > timeout:
                    logger.warning(f"Timeout after {attempts} attempts")
                    stop_flag = True
                    break

                result = future.result()
                if result:
                    found_secret = result
                    elapsed = time.time() - start
                    logger.info(
                        f"Cracked '{result}' in {attempts} attempts "
                        f"({elapsed:.1f}s, {attempts/elapsed:.0f}/s)"
                    )
                    stop_flag = True
                    break  # pool shutdown via 'with' block
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            stop_flag = True
            raise

    return found_secret