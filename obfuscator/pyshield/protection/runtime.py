import ast
import base64
import marshal
import os
import zlib
from ..utils import uid


# ── AES-256-GCM encryption

def _aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
        return nonce, ct_tag[-16:], ct_tag[:-16]
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return nonce, tag, ct
    except ImportError:
        raise RuntimeError(
            "AES-256-GCM requires 'cryptography' or 'pycryptodome'.\n"
            "  pip install cryptography"
        )


def _encrypt_code(code_obj, canary: bytes = b'\x00\x00\x00\x00') -> tuple[str, str]:
    raw_key     = bytearray(os.urandom(32))
    marshalled  = marshal.dumps(code_obj)
    compressed  = zlib.compress(marshalled, level=9)
    nonce, tag, ct = _aes_encrypt(compressed, bytes(raw_key))
    payload         = nonce + tag + ct
    encoded_payload = base64.b85encode(payload).decode()
    stored_key      = bytearray(raw_key)
    for i in range(4):
        stored_key[i] ^= canary[i]
    encoded_key = base64.b85encode(bytes(stored_key)).decode()
    return encoded_payload, encoded_key


# ── code object extraction 

def _extract_func_code(
    func_node: ast.FunctionDef,
    source_file: str = "<runtime>",
    class_node: ast.ClassDef | None = None,
):
    if class_node is not None:
        mini = ast.Module(body=[class_node], type_ignores=[])
        ast.fix_missing_locations(mini)
        module_code = compile(mini, source_file, "exec")
        for cls_code in module_code.co_consts:
            if not hasattr(cls_code, "co_consts"):
                continue
            for meth_code in cls_code.co_consts:
                if (hasattr(meth_code, "co_name")
                        and meth_code.co_name == func_node.name):
                    return meth_code
        raise ValueError(f"Could not find {func_node.name} in class")
    else:
        mini = ast.Module(body=[func_node], type_ignores=[])
        ast.fix_missing_locations(mini)
        module_code = compile(mini, source_file, "exec")
        for const in module_code.co_consts:
            if isinstance(const, type(module_code)):
                return const
        raise ValueError(f"Could not extract code for {func_node.name}")


def _needs_class_cell(func_node: ast.AST) -> bool:
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "super":
                return True
    return False


# ── stub builder 

def _build_stub(
    func_name:  str,
    encoded:    str,   
    encoded_key: str,  
    args:       ast.arguments,
    is_async:   bool,
    is_method:  bool,
    needs_cell: bool,
    canary:     bytes = b'\x00\x00\x00\x00',
) -> list[ast.stmt]:
    v_pl  = uid(4); v_ka  = uid(4); v_ci  = uid(4); v_raw = uid(4)
    v_non = uid(4); v_tag = uid(4); v_ct  = uid(4); v_dec = uid(4)
    v_co  = uid(4); v_fn  = uid(4); v_res = uid(4); v_b64 = uid(4)
    v_zl  = uid(4); v_ms  = uid(4); v_ty  = uid(4)
    v_cl  = uid(4); v_cell= uid(4); v_aes = uid(4); v_cry = uid(4)

    all_pos = [ast.Name(id=a.arg, ctx=ast.Load()) for a in args.args]
    if args.vararg:
        all_pos.append(ast.Starred(
            value=ast.Name(id=args.vararg.arg, ctx=ast.Load()),
            ctx=ast.Load()
        ))
    kw = [ast.keyword(arg=k.arg, value=ast.Name(id=k.arg, ctx=ast.Load()))
          for k in args.kwonlyargs]
    if args.kwarg:
        kw.append(ast.keyword(
            arg=None,
            value=ast.Name(id=args.kwarg.arg, ctx=ast.Load())
        ))

    decrypt_src = (
        f"import base64 as {v_b64}, zlib as {v_zl}, marshal as {v_ms}, types as {v_ty}\n"
        f"if __import__('sys').gettrace() is not None: raise SystemExit(1)\n"
        f"if __import__('sys').getprofile() is not None: raise SystemExit(1)\n"
        f"{v_ka} = bytearray({v_b64}.b85decode({repr(encoded_key)}))\n"
        f"try:\n"
        f"    for {v_ci} in range(4): {v_ka}[{v_ci}] ^= _canary_g[{v_ci}]\n"
        f"    del {v_ci}\n"
        f"except NameError: raise SystemExit(1)\n"
        f"{v_raw} = {v_b64}.b85decode({repr(encoded)})\n"
        f"{v_non} = bytes({v_raw}[:12])\n"
        f"{v_tag} = bytes({v_raw}[12:28])\n"
        f"{v_ct}  = bytes({v_raw}[28:])\n"
        f"del {v_raw}\n"
        f"try:\n"
        f"    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as {v_aes}\n"
        f"    {v_dec} = {v_aes}(bytes({v_ka})).decrypt({v_non}, {v_ct}+{v_tag}, None)\n"
        f"except ImportError:\n"
        f"    from Crypto.Cipher import AES as {v_cry}\n"
        f"    _c = {v_cry}.new(bytes({v_ka}), {v_cry}.MODE_GCM, nonce={v_non})\n"
        f"    {v_dec} = _c.decrypt_and_verify({v_ct}, {v_tag})\n"
        f"    del _c\n"
        f"{v_co} = {v_ms}.loads({v_zl}.decompress({v_dec}))\n"
        f"del {v_ka}, {v_non}, {v_tag}, {v_ct}, {v_dec}\n"
    )

    stmts = ast.parse(decrypt_src, mode="exec").body

    if needs_cell and is_method and args.args:
        first = args.args[0].arg
        make_cell_src = (
            f"{v_cl} = type({first})\n"
            f"{v_cell} = (lambda {v_cl}=None: (lambda: {v_cl}))({v_cl}).__closure__[0]\n"
            f"{v_fn} = {v_ty}.FunctionType({v_co}, globals(), {repr(func_name)}, "
            f"closure=({v_cell},))\n"
        )
    else:
        make_cell_src = (
            f"{v_fn} = {v_ty}.FunctionType({v_co}, globals(), {repr(func_name)})\n"
        )
    stmts += ast.parse(make_cell_src, mode="exec").body

    if is_method and args.args:
        first     = args.args[0].arg
        self_node = ast.Name(id=first, ctx=ast.Load())
        bound = ast.Call(
            func=ast.Attribute(
                value=ast.Name(id=v_fn, ctx=ast.Load()),
                attr="__get__", ctx=ast.Load(),
            ),
            args=[self_node, ast.Call(ast.Name(id="type", ctx=ast.Load()), [self_node], [])],
            keywords=[],
        )
        rest_pos = [ast.Name(id=a.arg, ctx=ast.Load()) for a in args.args[1:]]
        if args.vararg:
            rest_pos.append(ast.Starred(
                value=ast.Name(id=args.vararg.arg, ctx=ast.Load()),
                ctx=ast.Load()
            ))
        call_expr = ast.Call(func=bound, args=rest_pos, keywords=kw)
    else:
        call_expr = ast.Call(
            func=ast.Name(id=v_fn, ctx=ast.Load()),
            args=all_pos, keywords=kw,
        )

    if is_async:
        call_expr = ast.Await(value=call_expr)

    assign = ast.Assign(
        targets=[ast.Name(id=v_res, ctx=ast.Store())],
        value=call_expr,
    )
    stmts.append(assign)

    del_names = [v_co, v_fn, v_b64, v_zl, v_ms, v_ty]
    if needs_cell and is_method:
        del_names += [v_cl, v_cell]
    stmts.append(ast.Delete(
        targets=[ast.Name(id=n, ctx=ast.Del()) for n in del_names]
    ))
    stmts.append(ast.Return(value=ast.Name(id=v_res, ctx=ast.Load())))
    return stmts


# ── AST transformer 

class RuntimeEncryptor(ast.NodeTransformer):

    _SKIP_NAMES = frozenset({
        "__init_subclass__", "__class_getitem__", "__set_name__",
        "__get__", "__set__", "__delete__", "__missing__",
    })

    def __init__(self, source_file: str = "<runtime>", canary: bytes = b'\x00\x00\x00\x00'):
        self._source_file   = source_file
        self._canary        = canary
        self._in_class      = False
        self._current_class = None
        self.encrypted_count = 0
        self.skipped_count   = 0

    def _should_skip(self, node) -> bool:
        if node.name in self._SKIP_NAMES:
            return True
        def _is_trivial(stmt):
            if not isinstance(stmt, ast.Expr): return False
            v = stmt.value
            if isinstance(v, ast.Constant): return True
            if hasattr(ast, "Ellipsis") and isinstance(v, ast.Ellipsis): return True
            return False
        real = [s for s in node.body if not _is_trivial(s)]
        if not real:
            return True
        for dec in node.decorator_list:
            name = (dec.id if isinstance(dec, ast.Name)
                    else dec.attr if isinstance(dec, ast.Attribute) else "")
            if name in ("abstractmethod", "property"):
                return True
        return False

    def _transform_func(self, node):
        if self._should_skip(node):
            self.skipped_count += 1
            old_cls = self._current_class
            self.generic_visit(node)
            self._current_class = old_cls
            return node

        is_async   = isinstance(node, ast.AsyncFunctionDef)
        is_method  = self._in_class
        needs_cell = _needs_class_cell(node)

        try:
            code_obj = _extract_func_code(
                node, self._source_file,
                class_node=self._current_class if needs_cell else None,
            )
            encoded_payload, encoded_key = _encrypt_code(code_obj, self._canary)
        except Exception:
            self.skipped_count += 1
            old_cls = self._current_class
            self.generic_visit(node)
            self._current_class = old_cls
            return node

        stub = _build_stub(
            node.name, encoded_payload, encoded_key, node.args,
            is_async, is_method, needs_cell, self._canary,
        )
        node.body = stub
        self.encrypted_count += 1
        return node

    def visit_ClassDef(self, node):
        old_in_class    = self._in_class
        old_current_cls = self._current_class
        self._in_class      = True
        self._current_class = node
        self.generic_visit(node)
        self._in_class      = old_in_class
        self._current_class = old_current_cls
        return node

    def visit_FunctionDef(self, node):
        return self._transform_func(node)

    def visit_AsyncFunctionDef(self, node):
        return self._transform_func(node)

    def transform(self, tree: ast.AST, source_file: str = "<runtime>") -> ast.AST:
        self._source_file = source_file
        result = self.visit(tree)
        ast.fix_missing_locations(result)
        return result
