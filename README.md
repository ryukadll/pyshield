# PyShield

Python source code protector for Windows. Transforms `.py` files into hardened output that requires reversing multiple independent protection layers to recover any meaningful logic.

---

## Requirements

- **Windows 10 / 11** (x64)
- **Python 3.11 or later** (3.12–3.14 tested)
- `pip install cryptography` — AES-256-GCM runtime stubs
- `pip install setuptools` — required to compile the C guard (`.pyd`)
- **Visual Studio Build Tools** — required to compile the C guard
  - Download free: https://visualstudio.microsoft.com/visual-cpp-build-tools/
  - Select: **Desktop development with C++**
- `pip install pyinstaller` — only needed for `--bundle`

If Visual Studio Build Tools are not installed, PyShield automatically falls back to a pure-Python guard (`.py`) with the same key-split protection — no compiler needed.

---

## Installation

No installation required. Unzip and run directly:

```
pyshield/
├── pyshield.py          ← entry point
├── example_original.py  ← sample script
└── pyshield/            ← library
```

---

## Usage

```bat
:: Standard — C guard (.pyd) + all passes
python pyshield.py myscript.py

:: C guard + custom VM bytecode (strongest)
python pyshield.py myscript.py --vm

:: Pure Python — no .pyd needed
python pyshield.py myscript.py --no-cguard

:: Pure Python + VM
python pyshield.py myscript.py --vm --no-cguard

:: Bundle to a standalone .exe
python pyshield.py myscript.py --vm --bundle

:: Bundle with no console window (GUI apps)
python pyshield.py myscript.py --bundle --no-console

:: Verify output matches original before shipping
python pyshield.py myscript.py --verify

:: Show size statistics
python pyshield.py myscript.py --stats

:: Custom output path
python pyshield.py myscript.py -o protected\myscript.py
```

---

## Output files

With the C guard active (default), PyShield produces two files that must be distributed together:

```
myscript_obf.py      ← the protected script (3 lines)
pyshield_rt.pyd      ← C runtime guard — must stay alongside the .py
```

The protected script contains only an encrypted payload blob and a single call to `__ps__()`. Neither file does anything useful without the other — the decryption key is split between them.

With `--no-cguard` or `--bundle`, a single file is produced.

---

## Protection layers

| Layer | What it does |
|---|---|
| Identifier renaming | Every symbol → random 16-char hex UID, different per build |
| String encryption | Four independent inline strategies, no central decoder |
| Constant masking | Literals replaced with computed expressions |
| Dead code injection | Opaque predicates and unreachable blocks |
| Control flow obfuscation | Varied dispatchers, indirect call indirection |
| AES-256-GCM encryption | Every function body individually encrypted, canary-entangled key |
| Custom VM bytecode (`--vm`) | Function bodies compiled to a per-build randomised instruction set |
| Heterogeneous wrapper | Three structurally distinct `exec` shells |
| C guard (`.pyd`) | Payload split across native binary + protected script — neither half runs alone |

Each layer is independent. Defeating one leaves all the others intact.

---

## Flags

| Flag | Effect |
|---|---|
| `--vm` | Compile sync function bodies to a custom VM with a per-build randomised instruction set. `dis.dis()` on the stored bytecode shows nonsense. Async functions and generators automatically use the AES-GCM path. |
| `--no-cguard` | Skip the C guard. Single self-contained `.py` output, all Python-side passes still applied. |
| `--no-strings` | Skip string encryption. |
| `--no-flow` | Skip control flow obfuscation. |
| `--no-runtime` | Skip per-function AES-256-GCM encryption. |
| `--bundle` | Run PyInstaller and produce a standalone `.exe`. Requires `pip install pyinstaller`. |
| `--no-console` | Hide the console window in the bundled `.exe` (for GUI apps). |
| `--verify` | After protecting, run both the original and protected versions and compare stdout. |
| `--stats` | Print original size, protected size, and expansion ratio. |

---

## How the C guard works

The decryption key is split between two components:

- **`c_half`** — 32 random bytes embedded in `pyshield_rt.pyd` as obfuscated arithmetic expressions
- **`py_half`** — derived at runtime from `__name__` using an FNV hash chain

The payload is encrypted with `XOR(SHA-256(c_half ⊕ py_half ⊕ license_hash))`. Without the `.pyd`, `py_half` alone produces the wrong key. Without the `.py`, `c_half` alone is useless.

The C binary also includes:

- `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` checks
- FNV32 + XOR-fold integrity self-checks that detect key tampering
- Indirect dispatch table — decryption entry point has no fixed address

---

## How the VM works

When `--vm` is used, every synchronous function body is compiled to a custom bytecode format:

- Instruction set is randomly shuffled on every build — opcode numbers are different every time `pyshield.py` runs
- Compiled bytecode is AES-256-GCM encrypted and stored as a blob inside the payload
- At runtime, the embedded `_PSVMInterp` interpreter decrypts and executes it
- `dis.dis()`, `inspect`, and all bytecode analysis tools see only the interpreter dispatch loop — not your logic
- Async functions, generators, and coroutines automatically fall back to the AES-GCM path (they require CPython frame machinery)
- Supports Python 3.11–3.14 opcodes including all 3.14 additions (`CALL_KW`, `CONTAINS_OP`, `IS_OP`, `FORMAT_SIMPLE`, `BINARY_SLICE`, `STORE_FAST_STORE_FAST`, etc.)

---

## Recommended modes

**Maximum protection** — licensed software, internal tools:
```bat
python pyshield.py myscript.py --vm
```
Attacker must: unpack the PE → reverse the C binary → break the key split → decrypt the AES-GCM stubs → reverse a custom VM with an unknown per-build instruction set.

**No compiler available** — quick deploy:
```bat
python pyshield.py myscript.py --vm --no-cguard
```
All Python-side passes applied. Single `.py` output, no `.pyd` required.

**Standalone executable** — distribute to machines without Python:
```bat
python pyshield.py myscript.py --vm --bundle
```
Single `.exe` that includes everything. No Python install required on target machine.

---

## What PyShield does not protect against

- **Determined native reversers** with unlimited time — no obfuscator stops a skilled analyst permanently, it only raises the cost significantly
- **Runtime memory dumps** — if the process runs, the decrypted bytecode exists in memory at some point
- **Cooperative environments** — if the attacker controls the Python interpreter, all Python-side checks can be bypassed

PyShield is designed to make casual copying and automated extraction impractical, and to make targeted reverse engineering expensive enough to deter most threat models.

---

## Troubleshooting

**`[warn] C guard failed — falling back to pure Python`**

MSVC was not found. Install Visual Studio Build Tools (free):
https://visualstudio.microsoft.com/visual-cpp-build-tools/

Select **"Desktop development with C++"** during installation. PyShield automatically produces a `pyshield_rt.py` fallback with the same key-split protection when no compiler is found.

**`[verify] Output DIFFERS`**

The protected output produced different stdout than the original. Common causes:
- The script relies on `__file__` paths that change when the output is renamed
- The script uses `inspect` or `dis` internally
- Check stderr for `[vm] unhandled: OPCODE` warnings — unhandled opcodes emit NOP and may alter behaviour

**`[vm] unhandled: SOME_OPCODE`**

A Python opcode not yet handled by the VM was encountered. It is emitted as NOP and silently skipped. If this causes incorrect output, use `--no-cguard` without `--vm`.

**`ImportError: No module named 'pyshield_rt'`**

`pyshield_rt.pyd` (or `pyshield_rt.py`) must be in the same directory as the protected script. Never distribute `myscript_obf.py` without its matching runtime file.

**`ModuleNotFoundError: No module named 'cryptography'`** in bundled `.exe`

Run `pip install cryptography` before bundling, then re-run with `--bundle`.
