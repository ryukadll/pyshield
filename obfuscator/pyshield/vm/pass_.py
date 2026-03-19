import ast
import random
from .isa import ISA
from .stub import compile_to_vm, build_vm_stub, _VM_RUNTIME_SOURCE
from ..utils import uid


class VMPass(ast.NodeTransformer):
    _SKIP_NAMES = frozenset({
        "__init_subclass__", "__class_getitem__", "__set_name__",
        "__get__", "__set__", "__delete__", "__missing__",
    })

    def __init__(self, source_file: str = "<vm>"):
        self._source_file   = source_file
        self._isa           = ISA()  
        self._in_class      = False
        self._current_class = None
        self.vm_count       = 0
        self.fallback_count = 0
        self._runtime_injected = False

    @property
    def isa(self) -> ISA:
        return self._isa

    def _should_skip(self, node) -> bool:
        if node.name in self._SKIP_NAMES:
            return True
        def _trivial(s):
            if not isinstance(s, ast.Expr): return False
            v = s.value
            return isinstance(v, ast.Constant) or (
                hasattr(ast, 'Ellipsis') and isinstance(v, ast.Ellipsis))
        return all(_trivial(s) for s in node.body)

    def _get_func_code(self, node):
        if self._current_class and self._needs_class_cell(node):
            mini = ast.Module(body=[self._current_class], type_ignores=[])
        else:
            mini = ast.Module(body=[node], type_ignores=[])
        ast.fix_missing_locations(mini)
        module_code = compile(mini, self._source_file, "exec")
        def find_code(co, name):
            if hasattr(co, 'co_name') and co.co_name == name:
                return co
            for c in co.co_consts:
                if hasattr(c, 'co_consts'):
                    result = find_code(c, name)
                    if result:
                        return result
            return None
        return find_code(module_code, node.name)

    def _needs_class_cell(self, node) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Name) and n.func.id == 'super':
                    return True
        return False

    def _transform_func(self, node):
        if self._should_skip(node):
            old = self._current_class
            self.generic_visit(node)
            self._current_class = old
            return node

        is_async = isinstance(node, ast.AsyncFunctionDef)

        try:
            code_obj = self._get_func_code(node)
            if code_obj is None:
                raise ValueError("Could not extract code object")

            result = compile_to_vm(code_obj, self._isa)
            if result is None:
                self.fallback_count += 1
                old = self._current_class
                self.generic_visit(node)
                self._current_class = old
                return node

            vm_bytes, tables = result
            stub_src = build_vm_stub(
                node.name, vm_bytes, tables, self._isa,
                node.args,
                is_method=self._in_class,
                needs_cell=self._needs_class_cell(node),
            )
            stub_stmts = ast.parse(stub_src, mode='exec').body
            node.body = stub_stmts
            self.vm_count += 1

        except Exception as e:
            import sys
            print(f"[vm] skipping {node.name}: {e}", file=sys.stderr)
            self.fallback_count += 1
            old = self._current_class
            self.generic_visit(node)
            self._current_class = old

        return node

    def visit_ClassDef(self, node):
        old_in   = self._in_class
        old_cls  = self._current_class
        self._in_class      = True
        self._current_class = node
        self.generic_visit(node)
        self._in_class      = old_in
        self._current_class = old_cls
        return node

    def visit_FunctionDef(self, node):
        return self._transform_func(node)

    def visit_AsyncFunctionDef(self, node):
        return self._transform_func(node)

    def transform(self, tree: ast.AST) -> ast.AST:
        result = self.visit(tree)
        ast.fix_missing_locations(result)

        runtime_stmts = ast.parse(_VM_RUNTIME_SOURCE.strip(), mode='exec').body
        if isinstance(result, ast.Module):
            result.body = runtime_stmts + result.body

        ast.fix_missing_locations(result)
        return result
