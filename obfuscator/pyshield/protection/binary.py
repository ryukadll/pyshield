import ast
import base64
import importlib.util
import marshal
import os
import struct
import zlib

from ..utils import uid, xor_bytes
from ..wrapper import create_heterogeneous_wrapper

_HEADER_SIZE = 16
_MAGIC       = importlib.util.MAGIC_NUMBER


# ── encryption helpers 

def _encrypt_body(marshalled: bytes) -> tuple[bytes, bytes]:
    key        = os.urandom(32)
    compressed = zlib.compress(marshalled, level=9)
    cipher     = xor_bytes(compressed, key)
    return cipher, key


def _mangle_header(header_key: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    real_header = _MAGIC + b"\x00" * (_HEADER_SIZE - len(_MAGIC))
    if header_key is None:
        header_key = os.urandom(_HEADER_SIZE)
    mangled = xor_bytes(real_header, header_key)
    return mangled, real_header, header_key


# ── loader stub generator 

def _build_loader_stub(
    mangled_header: bytes,
    header_key:     bytes,
    encrypted_body: bytes,
    body_key:       bytes,
) -> str:
    mh_enc  = base64.b85encode(mangled_header).decode()
    hk_enc  = base64.b85encode(header_key).decode()
    eb_enc  = base64.b85encode(encrypted_body).decode()
    bk_enc  = base64.b85encode(body_key).decode()

    v_mh  = uid(4)   
    v_hk  = uid(4)   
    v_eb  = uid(4)   
    v_bk  = uid(4)   
    v_rh  = uid(4)   
    v_rb  = uid(4)   
    v_co  = uid(4)  
    v_b64 = uid(4)   
    v_zl  = uid(4)   
    v_ma  = uid(4)   
    v_i   = uid(4)   
    v_b   = uid(4)   
    v_a   = uid(4)  

    stub = (
        f"import base64 as {v_b64}, zlib as {v_zl}, marshal as {v_ma}\n"
        f"{v_mh} = {v_b64}.b85decode({repr(mh_enc)})\n"
        f"{v_hk} = {v_b64}.b85decode({repr(hk_enc)})\n"
        f"{v_eb} = {v_b64}.b85decode({repr(eb_enc)})\n"
        f"{v_bk} = {v_b64}.b85decode({repr(bk_enc)})\n"
        f"{v_rh} = bytes({v_a} ^ {v_hk}[{v_i}] for {v_i}, {v_a} in enumerate({v_mh}))\n"
        f"{v_rb} = bytes({v_b} ^ {v_bk}[{v_i} % {len(body_key)}] for {v_i}, {v_b} in enumerate({v_eb}))\n"
        f"{v_co} = {v_ma}.loads({v_zl}.decompress({v_rb}))\n"
        f"exec({v_co})\n"
    )

    return stub


# ── public API 

class BinaryProtector:

    def __init__(self, wrap_stub: bool = True):
        self.wrap_stub = wrap_stub

    def protect_source(self, source: str, filename: str = "<protected>") -> bytes:
        code_obj   = compile(source, filename, "exec")
        marshalled = marshal.dumps(code_obj)

        encrypted_body, body_key = _encrypt_body(marshalled)

        mangled_header, _, header_key = _mangle_header()

        stub = _build_loader_stub(mangled_header, header_key, encrypted_body, body_key)

        if self.wrap_stub:
            stub = create_heterogeneous_wrapper(stub)

        return stub.encode("utf-8")

    def protect_file(self, input_path: str, output_path: str | None = None) -> str:
        if output_path is None:
            base        = input_path[:-3] if input_path.endswith(".py") else input_path
            output_path = base + "_protected.py"

        with open(input_path, "r", encoding="utf-8") as f:
            source = f.read()

        protected = self.protect_source(source, filename=input_path)

        with open(output_path, "wb") as f:
            f.write(protected)

        return output_path

