import ast
import os
import hashlib
from ..utils import uid


# ── Guard source factory (canary is a build-time parameter) 

def make_guard_source(canary: bytes) -> str:
    canary_repr = repr(canary)
    return f"""
import sys as _sys_g, builtins as _bi_g, ctypes as _ct_g, importlib as _il_g
_orig_bi_g = _il_g.import_module('builtins')
if id(_bi_g.exec)    != id(_orig_bi_g.exec):    raise SystemExit(1)
if id(_bi_g.compile) != id(_orig_bi_g.compile): raise SystemExit(1)
if type(_bi_g.exec)    is not type(_bi_g.print): raise SystemExit(1)
if type(_bi_g.compile) is not type(_bi_g.print): raise SystemExit(1)
if _sys_g.gettrace() is not None: raise SystemExit(1)
if _sys_g.getprofile() is not None: raise SystemExit(1)
try:
    _f_g = open('/proc/self/status')
    _d_g = _f_g.read()
    _f_g.close()
    for _L_g in _d_g.splitlines():
        if _L_g.startswith('TracerPid:'):
            if int(_L_g[10:].strip()) != 0: raise SystemExit(1)
            break
    del _f_g, _d_g, _L_g
except (FileNotFoundError, PermissionError, NameError): pass
try:
    if _ct_g.windll.kernel32.IsDebuggerPresent(): raise SystemExit(1)
    _rbdp_g = _ct_g.c_bool(False)
    _ct_g.windll.kernel32.CheckRemoteDebuggerPresent(
        _ct_g.windll.kernel32.GetCurrentProcess(),
        _ct_g.byref(_rbdp_g)
    )
    if _rbdp_g.value: raise SystemExit(1)
    del _rbdp_g
except AttributeError: pass
_canary_g = {canary_repr}
del _sys_g, _bi_g, _ct_g, _il_g, _orig_bi_g
""".strip()

_GUARD_SOURCE = make_guard_source(b'\x00\x00\x00\x00')

_STUB_GUARD_SOURCE = """
if __import__('sys').gettrace() is not None: raise SystemExit(1)
if __import__('sys').getprofile() is not None: raise SystemExit(1)
"""


def make_guard_statements(canary: bytes | None = None) -> list[ast.stmt]:
    src = make_guard_source(canary if canary is not None else b'\x00\x00\x00\x00')
    return ast.parse(src.strip(), mode="exec").body


def make_stub_guard_statements() -> list[ast.stmt]:
    tree = ast.parse(_STUB_GUARD_SOURCE.strip(), mode="exec")
    return tree.body


def make_canary_key_mix_source(key_var: str, canary_var: str = "_canary_g") -> str:
    return (
        f"for __ci in range(4):\n"
        f"    {key_var}[__ci] ^= _canary_g[__ci]\n"
        f"del __ci\n"
    )


# ── Memory wiper 

_WIPER_SOURCE = (
    "def __wipe__(obj):\n"
    "    import ctypes as _c\n"
    "    try:\n"
    "        _c.memset(id(obj) + 32, 0, len(obj))\n"
    "    except Exception:\n"
    "        pass\n"
)

def make_wipe_call(var: str) -> str:
    """Generate a one-liner that wipes var then deletes it."""
    return (
        f"try:\n"
        f"    import ctypes as __wct\n"
        f"    __wct.memset(id({var}) + 32, 0, len({var}))\n"
        f"    del __wct\n"
        f"except: pass\n"
        f"del {var}\n"
    )


def make_wiper_function() -> str:
    return _WIPER_SOURCE.strip()


# ── Non-linear key derivation 

def derive_layer_key(prev_ciphertext: bytes, static_salt: bytes, length: int = 16) -> bytes:
    return hashlib.sha256(prev_ciphertext + static_salt).digest()[:length]


# ── Timing jitter 

_JITTER_SOURCE = r"""
import time as _t, random as _r
_t.sleep(_r.uniform(0, 0.002))
del _t, _r
"""


def make_jitter_statement() -> ast.stmt:
    return ast.parse(_JITTER_SOURCE.strip(), mode="exec").body[0]
