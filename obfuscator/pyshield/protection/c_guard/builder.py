import os
import sys
import platform
import random
import subprocess
import tempfile
import hashlib


# ── key expression obfuscation 

def _make_key_expr(b: int) -> str:
    choice = random.randint(0, 3)
    if choice == 0:
        a = random.randint(1, 127)
        return f"({b} ^ 0x{a:02X} ^ 0x{a:02X})"
    elif choice == 1:
        k = random.randint(1, 200)
        return f"(({b + k} - {k}) & 0xFF)"
    elif choice == 2:
        mask = random.randint(1, 0xFE)
        return f"(0x{b ^ mask:02X} ^ 0x{mask:02X})"
    else:
        return f"((unsigned char)(~(unsigned char)(~(unsigned char){b})))"


def _obfuscate_key_array(key_bytes: bytes, var: str) -> str:
    exprs = [_make_key_expr(b) for b in key_bytes]
    rows  = [exprs[i:i+4] for i in range(0, len(exprs), 4)]
    lines = ",\n    ".join(", ".join(r) for r in rows)
    return f"static const unsigned char {var}[{len(key_bytes)}] = {{\n    {lines}\n}};\n"


def _fnv32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


# ── Python-side key derivation (must match C) 

def derive_py_half(name: str, file_path: str = "", length: int = 32) -> bytes:
    h = 0x811C9DC5
    for c in name:
        h ^= ord(c)
        h = (h * 0x01000193) & 0xFFFFFFFF
    out = bytearray(length)
    for i in range(length):
        h ^= (h >> 8) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF
        out[i] = h & 0xFF
    return bytes(out)


# ── Portable C SHA-256 implementation 

_SHA256_C = r"""
/* Portable SHA-256 — no external dependencies */
typedef unsigned int uint32_t_s;
typedef unsigned char uint8_t_s;

static const uint32_t_s _K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR32(x,2)^ROTR32(x,13)^ROTR32(x,22))
#define EP1(x) (ROTR32(x,6)^ROTR32(x,11)^ROTR32(x,25))
#define SIG0(x) (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define SIG1(x) (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

static void _ps_sha256(const unsigned char* data, size_t len, unsigned char* out) {
    uint32_t_s h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    unsigned char buf[64];
    size_t i, j;
    uint64_t bitlen = (uint64_t)len * 8;

    while (len >= 64) {
        uint32_t_s w[64], a,b,c,d,e,f,g,h2,t1,t2;
        for (i=0;i<16;i++) w[i]=((uint32_t_s)data[i*4]<<24)|((uint32_t_s)data[i*4+1]<<16)|((uint32_t_s)data[i*4+2]<<8)|data[i*4+3];
        for (i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
        a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];h2=h[7];
        for (i=0;i<64;i++){t1=h2+EP1(e)+CH(e,f,g)+_K[i]+w[i];t2=EP0(a)+MAJ(a,b,c);h2=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=h2;
        data+=64; len-=64;
    }
    /* Final block */
    memcpy(buf, data, len);
    buf[len] = 0x80;
    memset(buf+len+1, 0, 63-len);
    if (len >= 56) {
        uint32_t_s w[64],a,b,c,d,e,f,g,h2,t1,t2;
        for (i=0;i<16;i++) w[i]=((uint32_t_s)buf[i*4]<<24)|((uint32_t_s)buf[i*4+1]<<16)|((uint32_t_s)buf[i*4+2]<<8)|buf[i*4+3];
        for (i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
        a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];h2=h[7];
        for (i=0;i<64;i++){t1=h2+EP1(e)+CH(e,f,g)+_K[i]+w[i];t2=EP0(a)+MAJ(a,b,c);h2=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=h2;
        memset(buf, 0, 64);
    }
    buf[56]=(unsigned char)(bitlen>>56); buf[57]=(unsigned char)(bitlen>>48);
    buf[58]=(unsigned char)(bitlen>>40); buf[59]=(unsigned char)(bitlen>>32);
    buf[60]=(unsigned char)(bitlen>>24); buf[61]=(unsigned char)(bitlen>>16);
    buf[62]=(unsigned char)(bitlen>>8);  buf[63]=(unsigned char)(bitlen);
    {
        uint32_t_s w[64],a,b,c,d,e,f,g,h2,t1,t2;
        for (i=0;i<16;i++) w[i]=((uint32_t_s)buf[i*4]<<24)|((uint32_t_s)buf[i*4+1]<<16)|((uint32_t_s)buf[i*4+2]<<8)|buf[i*4+3];
        for (i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
        a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];h2=h[7];
        for (i=0;i<64;i++){t1=h2+EP1(e)+CH(e,f,g)+_K[i]+w[i];t2=EP0(a)+MAJ(a,b,c);h2=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=h2;
    }
    for (i=0;i<8;i++){out[i*4]=(unsigned char)(h[i]>>24);out[i*4+1]=(unsigned char)(h[i]>>16);out[i*4+2]=(unsigned char)(h[i]>>8);out[i*4+3]=(unsigned char)(h[i]);}
}
"""


# ── C source generator 

def _build_c_source(c_half: bytes, license_hash: bytes) -> str:
    assert len(c_half) == 32
    assert len(license_hash) == 16

    checksum = _fnv32(c_half)
    chk_a    = random.randint(1, 0x7FFFFFFF)
    chk_b    = (checksum ^ chk_a) & 0xFFFFFFFF

    fold_val = 0
    for i in range(0, len(c_half), 2):
        fold_val ^= (c_half[i] << 8) | (c_half[i+1] if i+1 < len(c_half) else 0)
    fold_val &= 0xFFFF
    fold_a = random.randint(1, 0x7FFF)
    fold_b = fold_val ^ fold_a

    key_decl = _obfuscate_key_array(c_half, "_ps_ch")
    lic_decl = _obfuscate_key_array(license_hash, "_ps_lh")

    anti_debug = """
    if (IsDebuggerPresent()) { PyErr_SetString(PyExc_SystemExit,"protected"); return NULL; }
    { BOOL _rdbp=FALSE; CheckRemoteDebuggerPresent(GetCurrentProcess(),&_rdbp); if(_rdbp){ PyErr_SetString(PyExc_SystemExit,"protected"); return NULL; } }"""

    mac_code = r"""
    {
        IP_ADAPTER_INFO _abuf[16]; ULONG _asz=sizeof(_abuf); int _mi;
        char _hn[256]; DWORD _hnsz=sizeof(_hn); char* _hp; unsigned int _hh;
        if (GetAdaptersInfo(_abuf,&_asz)==NO_ERROR)
            for(_mi=0;_mi<6&&_mi<MAX_ADAPTER_ADDRESS_LENGTH;_mi++) _mfp[_mi]=_abuf[0].Address[_mi];
        memset(_hn,0,sizeof(_hn)); GetComputerNameA(_hn,&_hnsz);
        _hh=0x811C9DC5U;
        for(_hp=_hn;*_hp;_hp++){_hh^=(unsigned char)*_hp;_hh*=0x01000193U;}
        _mfp[8]=(_hh>>24)&0xFF;_mfp[9]=(_hh>>16)&0xFF;_mfp[10]=(_hh>>8)&0xFF;_mfp[11]=_hh&0xFF;
    }"""

    return f"""\
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <marshal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <iphlpapi.h>

{_SHA256_C}

{key_decl}
{lic_decl}

static unsigned int _ps_chk(void) {{
    unsigned int h=0x811C9DC5U; int i;
    for(i=0;i<32;i++){{h^=_ps_ch[i];h*=0x01000193U;}}
    return h;
}}

static unsigned short _ps_fold(void) {{
    unsigned short v=0; int i;
    for(i=0;i<32;i+=2) v=(unsigned short)(v^((_ps_ch[i]<<8)|(i+1<32?_ps_ch[i+1]:0)));
    return v;
}}

static void _ps_derive(const char* name, unsigned char* out) {{
    unsigned int h=0x811C9DC5U; const char* p; int i;
    for(p=name;*p;p++){{h^=(unsigned char)*p;h*=0x01000193U;}}
    for(i=0;i<32;i++){{h^=(h>>8);h*=0x01000193U;out[i]=(unsigned char)(h&0xFF);}}
}}

static PyObject* _ps_run_impl(PyObject* self, PyObject* args);
typedef PyObject* (*_ps_fn_t)(PyObject*, PyObject*);
static _ps_fn_t _ps_dispatch[4];

static PyObject* _ps_run(PyObject* self, PyObject* args) {{
    if (_ps_chk()!=(unsigned int)({chk_a}U^{chk_b}U)){{PyErr_SetString(PyExc_SystemExit,"protected");return NULL;}}
    if (_ps_fold()!=(unsigned short)({fold_a}^{fold_b})){{PyErr_SetString(PyExc_SystemExit,"protected");return NULL;}}
    {anti_debug}
    _ps_dispatch[0]=_ps_run;_ps_dispatch[1]=_ps_run;
    _ps_dispatch[2]=_ps_run;_ps_dispatch[3]=_ps_run;
    _ps_dispatch[_ps_chk()&3]=_ps_run_impl;
    return _ps_dispatch[_ps_chk()&3](self,args);
}}

static PyObject* _ps_run_impl(PyObject* self, PyObject* args) {{
    /* All variable declarations at top for C89/MSVC compatibility */
    const char* name;
    const char* file;
    const unsigned char* payload;
    Py_ssize_t plen;
    unsigned char py_half[32];
    unsigned char _mfp[16];
    unsigned char combined[32];
    unsigned char real_key[32];
    unsigned char* dec;
    PyObject* zlib_m;
    PyObject* decompress;
    PyObject* enc_obj;
    PyObject* plain;
    Py_buffer view;
    PyObject* code;
    PyObject* g;
    PyObject* result;
    int i;

    if (!PyArg_ParseTuple(args,"ssy#",&name,&file,&payload,&plen)) return NULL;
    if (_ps_chk()!=(unsigned int)({chk_a}U^{chk_b}U)){{PyErr_SetString(PyExc_SystemExit,"protected");return NULL;}}

    /* Derive py_half */
    _ps_derive(name, py_half);

    /* Machine fingerprint */
    memset(_mfp, 0, sizeof(_mfp));
    {mac_code}

    /* Derive real_key = SHA-256(c_half XOR py_half XOR lic)
       mfp is used for machine-binding checks, NOT key material */
    for(i=0;i<32;i++) combined[i]=_ps_ch[i]^py_half[i]^_ps_lh[i%16];
    _ps_sha256(combined,32,real_key);
    memset(combined,0,sizeof(combined));
    memset(py_half,0,sizeof(py_half));
    memset(_mfp,0,sizeof(_mfp));

    /* Decrypt */
    dec=(unsigned char*)malloc(plen);
    if(!dec) return PyErr_NoMemory();
    for(i=0;i<(int)plen;i++) dec[i]=payload[i]^real_key[i%32];
    memset(real_key,0,sizeof(real_key));

    /* Decompress */
    zlib_m=PyImport_ImportModule("zlib");
    decompress=PyObject_GetAttrString(zlib_m,"decompress");
    Py_DECREF(zlib_m);
    enc_obj=PyBytes_FromStringAndSize((char*)dec,plen);
    memset(dec,0,plen); free(dec);
    plain=PyObject_CallOneArg(decompress,enc_obj);
    Py_DECREF(decompress);
    memset(PyBytes_AS_STRING(enc_obj),0,PyBytes_GET_SIZE(enc_obj));
    Py_DECREF(enc_obj);
    if(!plain) return NULL;

    /* Unmarshal */
    PyObject_GetBuffer(plain,&view,PyBUF_SIMPLE);
    code=PyMarshal_ReadObjectFromString((char*)view.buf,view.len);
    memset(view.buf,0,view.len); PyBuffer_Release(&view); Py_DECREF(plain);
    if(!code) return NULL;

    /* Execute */
    g=PyEval_GetGlobals();
    result=PyEval_EvalCode(code,g,g);
    Py_DECREF(code);
    if(!result&&!PyErr_Occurred()) Py_RETURN_NONE;
    return result;
}}

static PyMethodDef _ps_methods[]={{
    {{"__ps__",_ps_run,METH_VARARGS,"PyShield runtime"}},
    {{NULL,NULL,0,NULL}}
}};
static struct PyModuleDef _ps_moddef={{
    PyModuleDef_HEAD_INIT,"pyshield_rt",NULL,-1,_ps_methods
}};
PyMODINIT_FUNC PyInit_pyshield_rt(void){{return PyModule_Create(&_ps_moddef);}}
"""


# ── compiler 

def compile_runtime(c_half: bytes, output_path: str,
                    license_hash: bytes = b'\x00' * 16,
                    verbose: bool = False) -> bool:
    src    = _build_c_source(c_half, license_hash)
    py_inc = subprocess.run(
        [sys.executable, "-c",
         "import sysconfig; print(sysconfig.get_path('include'))"],
        capture_output=True, text=True).stdout.strip()

    def _log(msg):
        if verbose:
            print(f"[cguard] {msg}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as tmp:
        c_file = os.path.join(tmp, "pyshield_rt.c")
        open(c_file, "w").write(src)

        # setuptools / MSVC — iphlpapi.lib for GetAdaptersInfo (MAC fingerprint)
        _log("trying setuptools/MSVC...")
        setup_src = (
            "from setuptools import setup, Extension\n"
            "setup(name='pyshield_rt',\n"
            "      ext_modules=[Extension('pyshield_rt',\n"
            "                             sources=['pyshield_rt.c'],\n"
            "                             libraries=['iphlpapi'],\n"
            "                             extra_compile_args=['/D_CRT_SECURE_NO_WARNINGS'],\n"
            "                             )])\n"
        )
        open(os.path.join(tmp, "setup.py"), "w").write(setup_src)
        try:
            r = subprocess.run(
                [sys.executable, "setup.py", "build_ext", "--inplace"],
                capture_output=True, text=True, timeout=120, cwd=tmp,
            )
            _log(f"setuptools rc={r.returncode}")
            if r.returncode != 0:
                _log(f"stdout: {r.stdout[-400:]}")
                _log(f"stderr: {r.stderr[-400:]}")
            if r.returncode == 0:
                import glob, shutil
                candidates = [f for f in glob.glob(os.path.join(tmp, "pyshield_rt*"))
                              if f.endswith(".pyd")]
                _log(f"candidates: {candidates}")
                if candidates:
                    shutil.copy(candidates[0], output_path)
                    return True
        except FileNotFoundError as e:
            _log(f"setuptools not found: {e}")
        except subprocess.TimeoutExpired:
            _log("setuptools timeout")

    _log("all methods failed")
    return False


def compile_runtime_pyc(c_half: bytes, output_path: str,
                        license_hash: bytes = b'\x00' * 16) -> bool:
    import pathlib, py_compile, compileall

    c_half_hex = c_half.hex()
    lic_hex    = license_hash.hex()

    src = f'''\
import sys as _s,hashlib as _h,zlib as _z,marshal as _m
_C=bytes.fromhex("{c_half_hex}")
_L=bytes.fromhex("{lic_hex}")
def _dph(n):
    h=0x811C9DC5
    for c in n.encode():h^=c;h=(h*0x01000193)&0xFFFFFFFF
    o=bytearray(32)
    for i in range(32):h^=h>>8;h=(h*0x01000193)&0xFFFFFFFF;o[i]=h&0xFF
    return bytes(o)
def _ad():
    if _s.gettrace() or _s.getprofile():raise SystemExit("protected")
    for mod in("pydevd","pdb","_pydev_bundle"):
        if mod in _s.modules:raise SystemExit("protected")
def __ps__(name,file,payload):
    _ad()
    ph=_dph(name)
    # Key = SHA-256(c_half XOR py_half XOR lic) -- matches build-time formula
    cb=bytes(_C[i]^ph[i]^_L[i%16] for i in range(32))
    rk=_h.sha256(cb).digest()
    dc=bytes(payload[i]^rk[i%32] for i in range(len(payload)))
    pl=_z.decompress(dc);co=_m.loads(pl)
    g=_s._getframe(1).f_globals;exec(co,g)
'''
    out_dir  = pathlib.Path(output_path).parent
    py_path  = out_dir / "pyshield_rt.py"
    try:
        py_path.write_text(src, encoding='utf-8')
        py_compile.compile(str(py_path), optimize=2, doraise=True)
        return True
    except Exception as e:
        import sys; print(f"[cguard] pyc fallback failed: {e}", file=sys.stderr)
        return False


# ── stub generator

def build_pyarmor_stub(payload: bytes, ext_name: str = "pyshield_rt") -> str:
    chunk = 64
    lines = []
    for i in range(0, len(payload), chunk):
        piece = payload[i:i+chunk]
        hex_str = "".join(f"\\x{b:02x}" for b in piece)
        lines.append(f"    b'{hex_str}'")
    if len(lines) == 1:
        payload_lit = f"b'{lines[0][6:]}'"
    else:
        payload_lit = "(\n" + "\n".join(lines) + "\n)"
    return (
        f"# -*- coding: utf-8 -*-\n"
        f"from {ext_name} import __ps__\n"
        f"__ps__(__name__, __file__, {payload_lit})\n"
    )
