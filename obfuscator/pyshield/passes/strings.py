import ast
import os
import random
from ..entanglement import EntanglementSeed


class DocstringStripper(ast.NodeTransformer):

    def _strip(self, body: list) -> list:
        if (body
                and isinstance(body[0], ast.Expr)
                and isinstance(getattr(body[0], "value", None), ast.Constant)
                and isinstance(body[0].value.value, str)):
            return body[1:]
        return body

    def visit_Module(self, n):
        n.body = self._strip(n.body); self.generic_visit(n); return n

    def visit_FunctionDef(self, n):
        n.body = self._strip(n.body); self.generic_visit(n); return n

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, n):
        n.body = self._strip(n.body); self.generic_visit(n); return n


class DistributedStringEncryptor(ast.NodeTransformer):

    def __init__(self, seed: EntanglementSeed):
        self._seed  = seed
        self._count = 0

    # ── strategy A: chunked XOR 

    def _enc_chunked(self, raw: bytes) -> ast.expr:
        key = os.urandom(1)[0]
        enc = bytes(b ^ key for b in raw)
        n_chunks = random.randint(2, min(5, max(2, len(enc))))
        if n_chunks > 1 and len(enc) > 1:
            sizes = sorted(random.sample(range(1, len(enc)), n_chunks - 1))
        else:
            sizes = []
        boundaries = [0] + sizes + [len(enc)]
        chunks = [enc[boundaries[i]:boundaries[i + 1]] for i in range(len(boundaries) - 1)]

        parts = [
            ast.Call(
                func=ast.Name(id="bytes", ctx=ast.Load()),
                args=[ast.List(elts=[ast.Constant(b) for b in chunk], ctx=ast.Load())],
                keywords=[],
            )
            for chunk in chunks
        ]
        combined = parts[0]
        for p in parts[1:]:
            combined = ast.BinOp(combined, ast.Add(), p)

        bv  = ast.Name(id="__b", ctx=ast.Load())
        xor = ast.BinOp(bv, ast.BitXor(), ast.Constant(key))
        gen = ast.GeneratorExp(
            elt=xor,
            generators=[ast.comprehension(
                target=ast.Name(id="__b", ctx=ast.Store()),
                iter=combined, ifs=[], is_async=0,
            )],
        )
        result = ast.Call(func=ast.Name(id="bytes", ctx=ast.Load()), args=[gen], keywords=[])
        return ast.Call(
            func=ast.Attribute(value=result, attr="decode", ctx=ast.Load()),
            args=[], keywords=[],
        )

    # ── strategy B: index-scrambled bytes 

    def _enc_indexed(self, raw: bytes) -> ast.expr:
        n   = len(raw)
        idx = list(range(n))
        random.shuffle(idx)
        rev      = [0] * n
        shuffled = bytearray(n)
        for i, j in enumerate(idx):
            shuffled[i] = raw[j]
            rev[j] = i

        shuf_list = ast.List(elts=[ast.Constant(b) for b in shuffled], ctx=ast.Load())
        rev_list  = ast.List(elts=[ast.Constant(r) for r in rev],      ctx=ast.Load())
        iv        = ast.Name(id="__i", ctx=ast.Load())

        idx_expr = ast.Subscript(
            value=ast.Call(func=ast.Name(id="bytes", ctx=ast.Load()),
                           args=[shuf_list], keywords=[]),
            slice=ast.Subscript(value=rev_list, slice=iv, ctx=ast.Load()),
            ctx=ast.Load(),
        )
        gen = ast.GeneratorExp(
            elt=idx_expr,
            generators=[ast.comprehension(
                target=ast.Name(id="__i", ctx=ast.Store()),
                iter=ast.Call(func=ast.Name(id="range", ctx=ast.Load()),
                              args=[ast.Constant(n)], keywords=[]),
                ifs=[], is_async=0,
            )],
        )
        result = ast.Call(func=ast.Name(id="bytes", ctx=ast.Load()), args=[gen], keywords=[])
        return ast.Call(
            func=ast.Attribute(value=result, attr="decode", ctx=ast.Load()),
            args=[], keywords=[],
        )

    # ── strategy C: polynomial accumulator 

    def _enc_poly(self, raw: bytes) -> ast.expr:
        salt = random.randint(1, 127)
        enc  = [(b + salt * (i + 1)) % 256 for i, b in enumerate(raw)]
        n    = len(raw)

        enc_list = ast.List(elts=[ast.Constant(v) for v in enc], ctx=ast.Load())
        iv       = ast.Name(id="__i", ctx=ast.Load())

        enc_sub  = ast.Subscript(value=enc_list, slice=iv, ctx=ast.Load())
        mul      = ast.BinOp(ast.Constant(salt), ast.Mult(),
                             ast.BinOp(iv, ast.Add(), ast.Constant(1)))
        byte_val = ast.BinOp(ast.BinOp(enc_sub, ast.Sub(), mul), ast.Mod(), ast.Constant(256))

        gen = ast.GeneratorExp(
            elt=byte_val,
            generators=[ast.comprehension(
                target=ast.Name(id="__i", ctx=ast.Store()),
                iter=ast.Call(func=ast.Name(id="range", ctx=ast.Load()),
                              args=[ast.Constant(n)], keywords=[]),
                ifs=[], is_async=0,
            )],
        )
        result = ast.Call(func=ast.Name(id="bytes", ctx=ast.Load()), args=[gen], keywords=[])
        return ast.Call(
            func=ast.Attribute(value=result, attr="decode", ctx=ast.Load()),
            args=[], keywords=[],
        )

    # ── strategy D: entangled-key XOR 

    def _enc_entangled(self, raw: bytes) -> ast.expr:
        static_key  = list(os.urandom(16))
        iv_name     = self._seed.init_var
        expected_iv = self._seed.expected_iv("__main__")

        enc = bytes(
            b ^ ((expected_iv >> (i % 8)) & 0xFF) ^ static_key[i % len(static_key)]
            for i, b in enumerate(raw)
        )
        enc_list = ast.List(elts=[ast.Constant(b) for b in enc],         ctx=ast.Load())
        sk_list  = ast.List(elts=[ast.Constant(k) for k in static_key],  ctx=ast.Load())

        i_var = ast.Name(id="__i", ctx=ast.Load())
        b_var = ast.Name(id="__b", ctx=ast.Load())

        shift  = ast.BinOp(ast.Name(id=iv_name, ctx=ast.Load()),
                           ast.RShift(),
                           ast.BinOp(i_var, ast.Mod(), ast.Constant(8)))
        ent    = ast.BinOp(shift, ast.BitAnd(), ast.Constant(0xFF))
        sk_b   = ast.Subscript(value=sk_list,
                               slice=ast.BinOp(i_var, ast.Mod(),
                                               ast.Constant(len(static_key))),
                               ctx=ast.Load())
        decode = ast.BinOp(ast.BinOp(b_var, ast.BitXor(), ent), ast.BitXor(), sk_b)

        gen = ast.GeneratorExp(
            elt=decode,
            generators=[ast.comprehension(
                target=ast.Tuple(
                    elts=[ast.Name(id="__i", ctx=ast.Store()),
                          ast.Name(id="__b", ctx=ast.Store())],
                    ctx=ast.Store(),
                ),
                iter=ast.Call(
                    func=ast.Name(id="enumerate", ctx=ast.Load()),
                    args=[ast.Call(func=ast.Name(id="bytes", ctx=ast.Load()),
                                   args=[enc_list], keywords=[])],
                    keywords=[],
                ),
                ifs=[], is_async=0,
            )],
        )
        result = ast.Call(func=ast.Name(id="bytes", ctx=ast.Load()), args=[gen], keywords=[])
        return ast.Call(
            func=ast.Attribute(value=result, attr="decode", ctx=ast.Load()),
            args=[], keywords=[],
        )

    # ── dispatcher 

    def _encrypt(self, s: str) -> ast.expr:
        raw = s.encode("utf-8")
        fn  = random.choice([
            self._enc_chunked,
            self._enc_poly,
            self._enc_poly,        
            self._enc_entangled,
            self._enc_entangled,   
        ])
        return fn(raw)

    # ── AST visitors 

    def visit_JoinedStr(self, node):
        return node   

    def visit_Constant(self, node):
        if not isinstance(node.value, str) or len(node.value) < 2:
            return node
        self._count += 1
        expr = self._encrypt(node.value)
        return ast.copy_location(expr, node)

    # ── entry point 

    def transform(self, tree: ast.AST) -> ast.AST:
        DocstringStripper().visit(tree)
        result = self.visit(tree)
        ast.fix_missing_locations(result)
        return result
