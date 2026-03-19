import ast
import random
from ..utils import uid


class ControlFlowTransformer(ast.NodeTransformer):

    _SIMPLE = (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr, ast.Delete)

    def __init__(self, rename_map: dict[str, str], module_level_names: set[str]):
        self._rmap       = set(rename_map.values())
        self._module_obf = module_level_names

    # ── A: condition mutation 

    def _mutate_cond(self, test: ast.expr) -> ast.expr:
        ch = random.randint(0, 2)
        if ch == 0:
            return ast.UnaryOp(ast.Not(), ast.UnaryOp(ast.Not(), test))
        elif ch == 1:
            return ast.Compare(test, [ast.IsNot()], [ast.Constant(False)])
        return ast.UnaryOp(ast.Not(), ast.UnaryOp(ast.Not(), test))

    def visit_If(self, node):
        self.generic_visit(node)
        if random.random() < 0.55:
            node.test = self._mutate_cond(node.test)
            ast.fix_missing_locations(node)
        return node

    def visit_While(self, node):
        self.generic_visit(node)
        if not (isinstance(node.test, ast.Constant) and node.test.value is True):
            if random.random() < 0.4:
                node.test = self._mutate_cond(node.test)
                ast.fix_missing_locations(node)
        return node

    # ── C: call indirection 

    def visit_Call(self, node):
        self.generic_visit(node)
        if (isinstance(node.func, ast.Name)
                and node.func.id in self._module_obf
                and random.random() < 0.65):
            gbl    = ast.Call(ast.Name(id="globals", ctx=ast.Load()), [], [])
            lookup = ast.Subscript(value=gbl, slice=ast.Constant(node.func.id),
                                   ctx=ast.Load())
            node.func = lookup
        return node

    # ── B: dispatcher helpers 

    def _is_simple(self, stmt: ast.stmt) -> bool:
        if not isinstance(stmt, self._SIMPLE):
            return False
        for node in ast.walk(stmt):
            if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom,
                                  ast.Return, ast.Break, ast.Continue,
                                  ast.Raise, ast.Global, ast.Nonlocal)):
                return False
        return True

    def _names_assigned(self, stmts: list) -> set:
        names = set()
        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    names.add(node.id)
        return names

    def _names_used_in_loops(self, body: list) -> set:
        names = set()
        for stmt in body:
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                for node in ast.walk(stmt.target):
                    if isinstance(node, ast.Name):
                        names.add(node.id)
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                for node in ast.walk(stmt):
                    if isinstance(node, ast.AugAssign):
                        if isinstance(node.target, ast.Name):
                            names.add(node.target.id)
        return names

    def _safe_run(self, run: list, body: list) -> bool:
        return not (self._names_assigned(run) & self._names_used_in_loops(body))

    def _dispatch_while(self, stmts: list) -> list:
        sv   = uid(4)
        n    = len(stmts)
        mask = random.randint(1, 0x3FF)
        codes = [i ^ mask for i in range(n + 1)]

        def enc(i):
            return ast.BinOp(ast.Constant(codes[i]), ast.BitXor(), ast.Constant(mask))

        def branch(i):
            next_s = ast.Break() if i == n - 1 else ast.Assign(
                targets=[ast.Name(id=sv, ctx=ast.Store())], value=enc(i + 1)
            )
            return ast.If(
                test=ast.Compare(ast.Name(id=sv, ctx=ast.Load()), [ast.Eq()], [enc(i)]),
                body=[stmts[i], next_s],
                orelse=[],
            )

        branches = [branch(i) for i in range(n)]
        for i in range(n - 2, -1, -1):
            branches[i].orelse = [branches[i + 1]]

        return [
            ast.Assign(targets=[ast.Name(id=sv, ctx=ast.Store())], value=enc(0)),
            ast.While(test=ast.Constant(True), body=[branches[0]], orelse=[]),
        ]

    def _dispatch_dict(self, stmts: list) -> list:
        keys    = [random.randint(0x1000, 0xFFFF) for _ in stmts]
        key_var = uid(4)

        def branch(i):
            return ast.If(
                test=ast.Compare(
                    ast.Name(id=key_var, ctx=ast.Load()), [ast.Eq()], [ast.Constant(keys[i])]
                ),
                body=[stmts[i]],
                orelse=[],
            )

        chain = [branch(i) for i in range(len(stmts))]
        for i in range(len(chain) - 2, -1, -1):
            chain[i].orelse = [chain[i + 1]]

        return [ast.For(
            target=ast.Name(id=key_var, ctx=ast.Store()),
            iter=ast.List(elts=[ast.Constant(k) for k in keys], ctx=ast.Load()),
            body=[chain[0]],
            orelse=[],
        )]

    def _dispatch_choose(self, stmts: list) -> list:
        if len(stmts) < 2:
            return stmts
        return (self._dispatch_while if random.random() < 0.6 else self._dispatch_dict)(stmts)

    def _flatten_body(self, body: list) -> list:
        result, i = [], 0
        while i < len(body):
            run, j = [], i
            while j < len(body) and self._is_simple(body[j]):
                run.append(body[j]); j += 1
                if len(run) >= 6:
                    break
            if len(run) >= 3 and self._safe_run(run, body):
                result.extend(self._dispatch_choose(run))
                i = j
            else:
                result.append(body[i]); i += 1
        return result

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if len(node.body) >= 3:
            node.body = self._flatten_body(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── entry point 

    def transform(self, tree: ast.AST) -> ast.AST:
        result = self.visit(tree)
        ast.fix_missing_locations(result)
        return result
