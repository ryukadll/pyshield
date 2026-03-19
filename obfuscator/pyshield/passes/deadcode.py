import ast
import random
from ..utils import uid


class DeadCodeInjector(ast.NodeTransformer):

    # ── opaque predicates 

    def _opaque_true(self) -> ast.expr:
        ch = random.randint(0, 3)
        if ch == 0:
            n    = random.randint(2, 999)
            prod = ast.BinOp(ast.Constant(n), ast.Mult(), ast.Constant(n + 1))
            return ast.Compare(
                ast.BinOp(prod, ast.Mod(), ast.Constant(2)), [ast.Eq()], [ast.Constant(0)]
            )
        elif ch == 1:
            k    = random.randint(3, 50)
            call = ast.Call(
                ast.Name(id="len", ctx=ast.Load()),
                [ast.Call(ast.Name(id="range", ctx=ast.Load()), [ast.Constant(k)], [])],
                [],
            )
            return ast.Compare(call, [ast.Eq()], [ast.Constant(k)])
        elif ch == 2:
            k     = random.randint(1, 0xFFFF)
            bitor = ast.BinOp(
                ast.Constant(k), ast.BitOr(), ast.UnaryOp(ast.Invert(), ast.Constant(k))
            )
            return ast.Compare(bitor, [ast.Eq()], [ast.Constant(-1)])
        else:
            x  = random.randint(1, 100)
            sm = ast.BinOp(
                ast.BinOp(ast.Constant(x), ast.Pow(), ast.Constant(2)),
                ast.Add(), ast.Constant(x),
            )
            return ast.Compare(
                ast.BinOp(sm, ast.Mod(), ast.Constant(2)), [ast.Eq()], [ast.Constant(0)]
            )

    def _opaque_false(self) -> ast.expr:
        return ast.UnaryOp(ast.Not(), self._opaque_true())

    # ── dead block factory 

    def _make_dead(self) -> ast.stmt:
        ch = random.randint(0, 4)
        if ch == 0:
            msg = random.choice([
                "internal state corrupted", "invariant violation",
                "unreachable branch",       "unexpected condition",
            ])
            return ast.If(
                test=self._opaque_false(),
                body=[ast.Raise(exc=ast.Call(
                    ast.Name(id="AssertionError", ctx=ast.Load()),
                    [ast.Constant(msg)], [],
                ))],
                orelse=[],
            )
        elif ch == 1:
            var = uid(4)
            return ast.If(
                test=self._opaque_false(),
                body=[
                    ast.Assign(
                        targets=[ast.Name(id=var, ctx=ast.Store())],
                        value=ast.Constant(random.randint(0, 9999)),
                    ),
                    ast.Expr(ast.Call(
                        ast.Name(id="print", ctx=ast.Load()),
                        [ast.Constant(f"[debug] {var}")], [],
                    )),
                ],
                orelse=[],
            )
        elif ch == 2:
            return ast.While(test=self._opaque_false(), body=[ast.Pass()], orelse=[])
        elif ch == 3:
            return ast.Assert(
                test=self._opaque_true(),
                msg=ast.Constant(random.choice([
                    "precondition", "invariant", "type guard", "bounds check"
                ])),
            )
        else:
            var = uid(4)
            return ast.Try(
                body=[ast.Assign(
                    targets=[ast.Name(id=var, ctx=ast.Store())],
                    value=ast.Constant(0),
                )],
                handlers=[ast.ExceptHandler(
                    type=ast.Name(id="ZeroDivisionError", ctx=ast.Load()),
                    name=None,
                    body=[ast.Pass()],
                )],
                orelse=[],
                finalbody=[],
            )

    # ── injection 

    def _inject(self, body: list) -> list:
        if not body:
            return body
        out = []
        for stmt in body:
            out.append(stmt)
            if random.random() < 0.20:
                dead = self._make_dead()
                ast.copy_location(dead, stmt)
                ast.fix_missing_locations(dead)
                out.append(dead)
        return out

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Module(self, node):
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node

    # ── entry point 

    def transform(self, tree: ast.AST) -> ast.AST:
        result = self.visit(tree)
        ast.fix_missing_locations(result)
        return result
