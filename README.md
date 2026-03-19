# pyshield
PyShield, Python source code obfuscator for Windows. Protects .py files with AES-256-GCM encryption, identifier renaming, a custom VM with a per-build randomised instruction set, and a native C guard that splits the decryption key across a .pyd and the protected script. Output can be a standalone .exe via PyInstaller.
