import ast
import random


class ConstantTransformer(ast.NodeTransformer):

    def _make_int(self, v: int) -> ast.expr:
        if v == 0:
            k = random.randint(1, 0xFFFF)
            return ast.BinOp(ast.Constant(k), ast.BitXor(), ast.Constant(k))

        if abs(v) <= 0xFF:
            a = random.randint(1, 0x7F)
            b = random.randint(1, 0x7F)
            c = v - (a ^ b)
            xor = ast.BinOp(ast.Constant(a), ast.BitXor(), ast.Constant(b))
            return ast.BinOp(xor, ast.Add(), ast.Constant(c))

        if abs(v) <= 0xFFFF:
            a = random.randint(0, 0xFFFF)
            b = random.randint(0, 0xFFFF)
            c = v ^ a ^ b
            e1 = ast.BinOp(ast.Constant(a), ast.BitXor(), ast.Constant(b))
            return ast.BinOp(e1, ast.BitXor(), ast.Constant(c))

        lo = v & 0xFFFF
        hi = (v >> 16) & 0xFFFF
        k1 = random.randint(0, 0xFFFF)
        k2 = random.randint(0, 0xFFFF)
        lo_e = ast.BinOp(ast.Constant(lo ^ k1), ast.BitXor(), ast.Constant(k1))
        hi_e = ast.BinOp(ast.Constant(hi ^ k2), ast.BitXor(), ast.Constant(k2))
        return ast.BinOp(
            ast.BinOp(hi_e, ast.LShift(), ast.Constant(16)),
            ast.BitOr(), lo_e,
        )

    def _make_bool(self, v: bool) -> ast.expr:
        inner = ast.BinOp(ast.Constant(1), ast.BitOr(), ast.Constant(1))
        if v:
            return ast.UnaryOp(ast.Not(), ast.UnaryOp(ast.Not(), inner))
        return ast.UnaryOp(ast.Not(), inner)

    def _make_float(self, v: float) -> ast.expr:
        try:
            from fractions import Fraction
            frac = Fraction(v).limit_denominator(10000)
            n, d = frac.numerator, frac.denominator
            if d and abs(n) < 2 ** 24 and abs(d) < 2 ** 24:
                return ast.BinOp(self._make_int(n), ast.Div(), self._make_int(d))
        except Exception:
            pass
        return ast.Constant(v)

    def visit_Constant(self, node):
        v = node.value
        if isinstance(v, bool):
            return ast.copy_location(self._make_bool(v), node)
        if isinstance(v, int) and -2 ** 31 <= v <= 2 ** 31:
            if abs(v) < 8:  
                return node
            return ast.copy_location(self._make_int(v), node)
        if isinstance(v, float) and abs(v) < 1e9:
            return ast.copy_location(self._make_float(v), node)
        return node

    def transform(self, tree: ast.AST) -> ast.AST:
        result = self.visit(tree)
        ast.fix_missing_locations(result)
        return result
