import sys
import os
import ast
import shutil
import argparse
import subprocess
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from pyshield import PyShieldObfuscator
from pyshield.protection.c_guard import CGuardProtector


def main():
    parser = argparse.ArgumentParser(
        prog="pyshield",
        description="PyShield — Python source protector with C execution engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output format (with C guard, default):
  from pyshield_rt import __ps__
  __ps__(__name__, __file__, b'\\x17\\x16...')

Distribute input_obf.py + pyshield_rt.pyd together.
Use --bundle to produce a standalone .exe via PyInstaller.
""",
    )
    parser.add_argument("input",  help="Path to the .py file to protect")
    parser.add_argument("-o", "--output", default=None,
                        help="Output .py path (default: <input>_obf.py)")
    parser.add_argument("--no-cguard",   action="store_true",
                        help="Skip C guard — pure-Python output, no .pyd required")
    parser.add_argument("--no-strings",  action="store_true",
                        help="Skip string encryption pass")
    parser.add_argument("--no-flow",     action="store_true",
                        help="Skip control flow obfuscation pass")
    parser.add_argument("--vm",           action="store_true",
                        help="Compile functions to custom VM bytecode (strongest protection)")
    parser.add_argument("--no-runtime",  action="store_true",
                        help="Skip per-function runtime encryption")
    parser.add_argument("--bundle",      action="store_true",
                        help="Bundle into a standalone .exe via PyInstaller")
    parser.add_argument("--no-console",  action="store_true",
                        help="Hide console window (use with --bundle for GUI apps)")
    parser.add_argument("--verify",      action="store_true",
                        help="Run original and protected, compare stdout")
    parser.add_argument("--stats",       action="store_true",
                        help="Print size statistics after protection")
    args = parser.parse_args()

    # ── read input 
    if not os.path.isfile(args.input):
        print(f"[error] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    with open(args.input, "r", encoding="utf-8") as f:
        source = f.read()

    # ── output paths 
    if args.output:
        out_path = args.output
    else:
        base     = args.input[:-3] if args.input.endswith(".py") else args.input
        out_path = base + "_obf.py"

    out_dir  = os.path.dirname(os.path.abspath(out_path)) or "."
    out_name = os.path.splitext(os.path.basename(out_path))[0]

    # ── AST obfuscation passes 
    use_cguard = not args.no_cguard
    obf = PyShieldObfuscator(
        encode_strings  = not args.no_strings,
        obfuscate_flow  = not args.no_flow,
        runtime_encrypt = not args.no_runtime,
        wrap_exec       = True,
        c_guard_mode    = use_cguard,
        vm_pass         = args.vm,
    )
    try:
        obfuscated = obf.obfuscate(source, filename=args.input)
    except SyntaxError as e:
        print(f"[error] Syntax error in input:\n  {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[error] Obfuscation failed: {e}", file=sys.stderr)
        import traceback; traceback.print_exc()
        sys.exit(1)

    # ── C guard (PyArmor-style output) 
    rt_out = None
    if use_cguard:
        cg = CGuardProtector()
        if not cg.available:
            print("[warn] No C build tools found — falling back to pure Python")
            print("       To enable the C guard, install Visual Studio Build Tools:")
            print("         https://visualstudio.microsoft.com/visual-cpp-build-tools/")
            print("       (free — select 'Desktop development with C++')")
        else:
            stub_path = out_path
            result = cg.protect(
                obfuscated,
                output_dir  = out_dir,
                name        = out_name,
                module_name = "__main__",
                file_path   = stub_path,
            )
            if result["success"]:
                if result["stub_path"] != out_path:
                    shutil.move(result["stub_path"], out_path)

                # runtime is .pyd or .py (pure-Python fallback)
                rt_path = result.get("runtime_path", "")
                rt_out  = os.path.join(out_dir, "pyshield_rt.pyd")

                if rt_path and os.path.exists(rt_path):
                    rt_ext = os.path.splitext(rt_path)[1]
                    if rt_ext == ".py":
                        rt_out = os.path.join(out_dir, "pyshield_rt.py")
                    if rt_path != rt_out:
                        shutil.copy(rt_path, rt_out)
                    guard_type = "C .pyd" if rt_ext == ".pyd" else "Python guard"
                    print(f"[ok] {out_path}")
                    print(f"[ok] {rt_out}  ← keep alongside the .py  ({guard_type})")
                else:
                    print(f"[ok] {out_path}")
            else:
                print("[warn] C guard failed — falling back to pure Python")
                use_cguard = False

    # ── pure-Python fallback 
    if not use_cguard or rt_out is None:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(obfuscated)
        print(f"[ok] {out_path}  (pure-Python, no .pyd required)")

    _maybe_verify(args, source, out_path, out_dir)
    _maybe_stats(args, source, out_path)

    # ── PyInstaller bundle 
    if args.bundle:
        _bundle(args, source, out_path, out_dir, out_name, rt_out)


# ── spec generator 

def _collect_imports(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])

    imports.update({
        "ctypes", "importlib", "hashlib", "zlib", "marshal",
        "base64", "types", "struct", "pickle",
        "cryptography",
        "cryptography.hazmat",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.ciphers",
        "cryptography.hazmat.primitives.ciphers.aead",
        "cryptography.hazmat.backends",
        "Crypto",
        "Crypto.Cipher",
        "Crypto.Cipher.AES",
        "operator",
    })
    return sorted(imports)


def _generate_spec(
    original_path: str,
    obf_path:      str,
    out_name:      str,
    out_dir:       str,
    rt_path:       str | None,
    hidden_imports: list[str],
    noconsole:     bool,
) -> str:
    if rt_path and os.path.isfile(rt_path):
        rt_filename = os.path.basename(rt_path)
        binaries_line = f"[({repr(rt_path)}, '.')]"
    else:
        binaries_line = "[]"

    hidden_repr = repr(hidden_imports)
    console_val = "False" if noconsole else "True"

    orig_fwd  = original_path.replace("\\", "/")
    obf_fwd   = obf_path.replace("\\", "/")

    return f"""\
# -*- mode: python ; coding: utf-8 -*-
# Auto-generated by PyShield — do not edit manually.
# Re-generate by running: python pyshield.py {orig_fwd} --bundle

from PyInstaller.utils.hooks import collect_all

# Collect everything from cryptography and pycryptodome —
# these live inside the encrypted payload so PyInstaller can't auto-detect them.
crypto_datas, crypto_binaries, crypto_hidden = [], [], []
for _pkg in ('cryptography', 'Crypto'):
    try:
        d, b, h = collect_all(_pkg)
        crypto_datas     += d
        crypto_binaries  += b
        crypto_hidden    += h
    except Exception:
        pass

a = Analysis(
    [{repr(obf_fwd)}],
    pathex=[{repr(out_dir)}],
    binaries={binaries_line} + crypto_binaries,
    datas=[] + crypto_datas,
    hiddenimports={hidden_repr} + crypto_hidden,
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=['unittest', 'pydoc', 'doctest', 'tkinter',
              'test', '_testcapi', 'lib2to3'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name={repr(out_name)},
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console={console_val},
    onefile=True,
)
"""


def _bundle(args, source, out_path, out_dir, out_name, rt_out):
    """Generate a .spec file and invoke PyInstaller."""

    try:
        subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                       capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[error] PyInstaller not found. Install it with:")
        print("          pip install pyinstaller")
        sys.exit(1)

    print("\n[bundle] Analysing imports from original script...")
    hidden = _collect_imports(source)
    print(f"[bundle] Found {len(hidden)} imports: {', '.join(hidden)}")

    spec_path = os.path.join(out_dir, f"{out_name}.spec")
    spec_content = _generate_spec(
        original_path  = os.path.abspath(args.input),
        obf_path       = os.path.abspath(out_path),
        out_name       = out_name,
        out_dir        = out_dir,
        rt_path        = rt_out,
        hidden_imports = hidden,
        noconsole      = args.no_console,
    )

    with open(spec_path, "w", encoding="utf-8") as f:
        f.write(spec_content)
    print(f"[bundle] Spec written → {spec_path}")

    print("[bundle] Running PyInstaller...")
    r = subprocess.run(
        [sys.executable, "-m", "PyInstaller", spec_path, "--distpath",
         os.path.join(out_dir, "dist"), "--workpath",
         os.path.join(out_dir, "build"), "--noconfirm"],
        text=True,
    )

    if r.returncode == 0:
        ext      = ".exe"
        exe_path = os.path.join(out_dir, "dist", f"{out_name}{ext}")
        if os.path.isfile(exe_path):
            size_mb = os.path.getsize(exe_path) / 1024 / 1024
            print(f"\n[bundle] ✓ {exe_path}  ({size_mb:.1f} MB)")
        else:
            print(f"\n[bundle] ✓ Done — check {out_dir}/dist/")
    else:
        print("\n[bundle] ✗ PyInstaller failed — see output above")
        sys.exit(1)


# ── helpers 

def _maybe_verify(args, source, out_path, out_dir):
    if not args.verify:
        return
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(source); tmp = f.name
    try:
        r_orig = subprocess.run([sys.executable, tmp],
                                capture_output=True, text=True, timeout=30)
        r_obf  = subprocess.run([sys.executable, out_path],
                                capture_output=True, text=True, timeout=30,
                                cwd=out_dir)
        if r_orig.stdout.strip() == r_obf.stdout.strip():
            print("[verify] ✓ Output matches")
        else:
            print("[verify] ✗ Output DIFFERS")
            print(f"  original:   {r_orig.stdout[:80]!r}")
            print(f"  protected:  {r_obf.stdout[:80]!r}")
    except subprocess.TimeoutExpired:
        print("[verify] timeout")
    finally:
        os.unlink(tmp)


def _maybe_stats(args, source, out_path):
    if not args.stats:
        return
    out_size = os.path.getsize(out_path)
    print(f"\n[stats]")
    print(f"  Input:   {len(source):>8} bytes ({len(source)/1024:.1f} KB)")
    print(f"  Output:  {out_size:>8} bytes ({out_size/1024:.1f} KB)  "
          f"({out_size/len(source):.1f}x expansion)")


if __name__ == "__main__":
    main()

