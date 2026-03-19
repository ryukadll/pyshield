import hashlib
import sys
import zlib
import marshal
import types
import os


def _derive_py_half(name: str) -> bytes:
    h = 0x811C9DC5
    for c in name.encode():
        h ^= c
        h = (h * 0x01000193) & 0xFFFFFFFF
    out = bytearray(32)
    for i in range(32):
        h ^= (h >> 8)
        h = (h * 0x01000193) & 0xFFFFFFFF
        out[i] = h & 0xFF
    return bytes(out)


def _machine_fingerprint() -> bytes:
    mfp = bytearray(16)
    try:
        import uuid
        mac = uuid.getnode()
        for i in range(6):
            mfp[i] = (mac >> (8 * (5 - i))) & 0xFF
    except Exception:
        pass
    try:
        import socket
        hn = socket.gethostname().encode()
        h = 0x811C9DC5
        for c in hn:
            h ^= c
            h = (h * 0x01000193) & 0xFFFFFFFF
        mfp[8]  = (h >> 24) & 0xFF
        mfp[9]  = (h >> 16) & 0xFF
        mfp[10] = (h >> 8)  & 0xFF
        mfp[11] =  h        & 0xFF
    except Exception:
        pass
    return bytes(mfp)


def _anti_debug():
    try:
        import sys
        if sys.gettrace() is not None:
            raise SystemExit("protected")
        if sys.getprofile() is not None:
            raise SystemExit("protected")
        # Check for common debugging modules
        for mod in ('pydevd', 'pdb', '_pydev_bundle', 'IPython.core.debugger'):
            if mod in sys.modules:
                raise SystemExit("protected")
    except SystemExit:
        raise
    except Exception:
        pass


def run_payload(name: str, file: str, c_half: bytes, payload: bytes,
                license_hash: bytes = b'\x00' * 16) -> None:
    _anti_debug()

    py_half = _derive_py_half(name)
    mfp     = _machine_fingerprint()

    combined = bytes(
        c_half[i] ^ py_half[i] ^ mfp[i % 16] ^ license_hash[i % 16]
        for i in range(32)
    )
    real_key = hashlib.sha256(combined).digest()

    dec = bytes(payload[i] ^ real_key[i % 32] for i in range(len(payload)))

    # Decompress
    plain = zlib.decompress(dec)

    # Unmarshal and execute
    code = marshal.loads(plain)
    g = _get_caller_globals()
    exec(code, g)


def _get_caller_globals():
    import sys
    frame = sys._getframe(2)
    return frame.f_globals
