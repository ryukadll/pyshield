import base64
import hashlib
import marshal
import os
import random
import zlib

from .utils import uid, xor_bytes


# ── per-layer encoding functions 

def _layer_xor_zlib_b85(payload: bytes, label: str, key: bytes) -> bytes:
    """Layer A: provided key XOR → zlib → base85 → exec(compile(...))"""
    enc      = xor_bytes(zlib.compress(payload, 9), key)
    blob_str = base64.b85encode(enc).decode()
    csize    = random.randint(55, 85)
    chunks   = [blob_str[i:i + csize] for i in range(0, len(blob_str), csize)]
    blob     = " +\n    ".join(repr(c) for c in chunks)
    vd, vk, vz, vb = uid(4), uid(4), uid(4), uid(4)
    vj1 = uid(4); vj2 = uid(4)
    jitter_max = round(random.uniform(0.0005, 0.003), 6)
    src = (
        f"import zlib as {vz}, base64 as {vb}, time as {vj1}, random as {vj2}\n"
        f"{vj1}.sleep({vj2}.uniform(0, {jitter_max}))\n"
        f"del {vj1}, {vj2}\n"
        f"{vd} = (\n    {blob}\n)\n"
        f"{vk} = bytes({list(key)})\n"
        f"exec(compile({vz}.decompress("
        f"bytes(b ^ {vk}[i % {len(key)}] for i, b in "
        f"enumerate({vb}.b85decode({vd})))), {repr(label)}, 'exec'))\n"
    )
    return src.encode()


def _layer_marshal_zlib(payload: bytes, label: str, key: bytes) -> bytes:
    try:
        code       = compile(payload.decode(), label, "exec")
        raw        = xor_bytes(zlib.compress(marshal.dumps(code), 9), key)
        encoded    = base64.b85encode(raw).decode()
        csize      = random.randint(55, 85)
        chunks     = [encoded[i:i + csize] for i in range(0, len(encoded), csize)]
        blob       = " +\n    ".join(repr(c) for c in chunks)
        vm, vz, vb, vk = uid(4), uid(4), uid(4), uid(4)
        src = (
            f"import marshal as {vm}, zlib as {vz}, base64 as {vb}\n"
            f"{vk} = bytes({list(key)})\n"
            f"exec({vm}.loads({vz}.decompress("
            f"bytes(b ^ {vk}[i % {len(key)}] for i, b in "
            f"enumerate({vb}.b85decode(\n    {blob}\n))))))\n"
        )
        return src.encode()
    except SyntaxError:
        return _layer_xor_zlib_b85(payload, label, key)


def _layer_bytearray_eval(payload: bytes, label: str, key: bytes) -> bytes:
    enc      = xor_bytes(zlib.compress(payload, 9), key)
    blob_str = base64.b85encode(enc).decode()
    csize    = random.randint(55, 85)
    chunks   = [blob_str[i:i + csize] for i in range(0, len(blob_str), csize)]
    blob     = " +\n    ".join(repr(c) for c in chunks)
    vd, vk2, vz, vb, vi, vbt = uid(4), uid(4), uid(4), uid(4), uid(4), uid(4)
    src = (
        f"import zlib as {vz}, base64 as {vb}\n"
        f"{vd} = (\n    {blob}\n)\n"
        f"{vk2} = bytes({list(key)})\n"
        f"{vi} = {vb}.b85decode({vd})\n"
        f"{vbt} = bytes(__b ^ {vk2}[__i % {len(key)}] "
        f"for __i, __b in enumerate({vi}))\n"
        f"exec(compile({vz}.decompress({vbt}), {repr(label)!r}, 'exec'))\n"
    )
    return src.encode()


# ── non-linear key derivation 

def _derive_key(prev_ciphertext: bytes, salt: bytes, length: int = 16) -> bytes:
    return hashlib.sha256(prev_ciphertext + salt).digest()[:length]


# ── orchestrator 

def create_heterogeneous_wrapper(source_code: str) -> str:
    static_salt  = os.urandom(32)
    base_key     = os.urandom(16)     

    layer_fns = [_layer_xor_zlib_b85, _layer_marshal_zlib, _layer_bytearray_eval]
    random.shuffle(layer_fns)

    current      = source_code.encode("utf-8")
    prev_cipher  = base_key           
    keys         = []
    ciphertexts  = []

    for depth, fn in enumerate(layer_fns):
        if depth == 0:
            key = base_key
        else:
            key = _derive_key(ciphertexts[-1], static_salt)

        result = fn(current, f"<L{depth}>", key)
        keys.append(key)
        ciphertexts.append(result)  
        current = result

    salt_line = f"# {base64.b85encode(static_salt).decode()}\n"
    return salt_line + current.decode("utf-8")
