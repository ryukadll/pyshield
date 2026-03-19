import os
import hashlib


def uid(n: int = 8) -> str:
    return "_" + os.urandom(n).hex()


def uid_seed(seed: str) -> str:
    h = hashlib.sha256((seed + os.urandom(8).hex()).encode()).hexdigest()[:16]
    return "_" + h


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
