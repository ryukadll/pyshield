import ast
from ..utils import uid_seed


class IdentifierRenamer(ast.NodeTransformer):

    PRESERVE = frozenset({
        "ArithmeticError","AssertionError","AttributeError","BaseException",
        "BaseExceptionGroup","BlockingIOError","BrokenPipeError","BufferError",
        "BytesWarning","ChildProcessError","ConnectionAbortedError","ConnectionError",
        "ConnectionRefusedError","ConnectionResetError","DeprecationWarning","EOFError",
        "Ellipsis","EncodingWarning","EnvironmentError","Exception","ExceptionGroup",
        "False","FileExistsError","FileNotFoundError","FloatingPointError","FutureWarning",
        "GeneratorExit","IOError","ImportError","ImportWarning","IndentationError",
        "IndexError","InterruptedError","IsADirectoryError","KeyError","KeyboardInterrupt",
        "LookupError","MemoryError","ModuleNotFoundError","NameError","None",
        "NotADirectoryError","NotImplemented","NotImplementedError","OSError","OverflowError",
        "PendingDeprecationWarning","PermissionError","ProcessLookupError","RecursionError",
        "ReferenceError","ResourceWarning","RuntimeError","RuntimeWarning",
        "StopAsyncIteration","StopIteration","SyntaxError","SyntaxWarning","SystemError",
        "SystemExit","TabError","TimeoutError","True","TypeError","UnboundLocalError",
        "UnicodeDecodeError","UnicodeEncodeError","UnicodeError","UnicodeTranslateError",
        "UnicodeWarning","UserWarning","ValueError","Warning","ZeroDivisionError",
        "__build_class__","__debug__","__doc__","__import__","__loader__","__name__",
        "__package__","__spec__",
        "abs","aiter","all","anext","any","ascii","bin","bool","breakpoint","bytearray",
        "bytes","callable","chr","classmethod","compile","complex","copyright","credits",
        "delattr","dict","dir","divmod","enumerate","eval","exec","exit","filter","float",
        "format","frozenset","getattr","globals","hasattr","hash","help","hex","id","input",
        "int","isinstance","issubclass","iter","len","license","list","locals","map","max",
        "memoryview","min","next","object","oct","open","ord","pow","print","property",
        "quit","range","repr","reversed","round","set","setattr","slice","sorted",
        "staticmethod","str","sum","super","tuple","type","vars","zip",
        "self","cls",
        "__init__","__new__","__del__","__repr__","__str__","__len__","__iter__",
        "__next__","__enter__","__exit__","__call__","__getitem__","__setitem__",
        "__delitem__","__contains__","__add__","__sub__","__mul__","__truediv__",
        "__floordiv__","__mod__","__pow__","__lt__","__le__","__gt__","__ge__",
        "__eq__","__ne__","__and__","__or__","__not__","__neg__","__pos__","__abs__",
        "__hash__","__bool__","__class__","__dict__","__doc__","__name__","__module__",
        "__qualname__","__slots__","__all__","__file__","__spec__","__loader__",
        "__package__","__builtins__","__annotations__","__wrapped__","__cause__",
        "__context__","__traceback__","__suppress_context__","__aiter__","__anext__",
        "__aenter__","__aexit__","__await__","__get__","__set__","__delete__",
        "__set_name__","__init_subclass__","__class_getitem__","__format__",
        "__sizeof__","__reduce__","__reduce_ex__","__getnewargs__","__getnewargs_ex__",
        "__getstate__","__setstate__","__fspath__","__bytes__","__complex__","__int__",
        "__float__","__index__","__round__","__trunc__","__floor__","__ceil__",
        "__invert__","__lshift__","__rshift__","__xor__","__matmul__","__divmod__",
        "__iadd__","__isub__","__imul__","__itruediv__","__ifloordiv__","__imod__",
        "__ipow__","__ilshift__","__irshift__","__iand__","__ior__","__ixor__",
        "main","setup","teardown",
        "on_ready","on_message","on_error","setup_hook","close",
        "cog_load","cog_unload","interaction_check","on_app_command_error",
    })

    def __init__(self):
        self._map: dict[str, str] = {}
        self._imports: set[str] = set()

    # ── collection 

    def _collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self._imports.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    nm = a.asname or a.name
                    if nm != "*":
                        self._imports.add(nm)

    def _prebuild_map(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not self._should_preserve(node.name):
                    self._get_or_create(node.name)
                all_args = (
                    node.args.args + node.args.posonlyargs + node.args.kwonlyargs
                    + ([node.args.vararg] if node.args.vararg else [])
                    + ([node.args.kwarg]  if node.args.kwarg  else [])
                )
                for arg in all_args:
                    if arg.arg not in ("self", "cls"):
                        self._get_or_create(arg.arg)
            elif isinstance(node, ast.ClassDef):
                if not self._should_preserve(node.name):
                    self._get_or_create(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self._get_or_create(node.id)

    # ── name helpers

    def _should_preserve(self, name: str) -> bool:
        return (
            name in self.PRESERVE
            or name in self._imports
            or (name.startswith("__") and name.endswith("__"))
        )

    def _get_or_create(self, name: str) -> str:
        if self._should_preserve(name):
            return name
        if name not in self._map:
            self._map[name] = uid_seed(name)
        return self._map[name]

    # ── visitors 

    def visit_FunctionDef(self, node):
        if not self._should_preserve(node.name):
            node.name = self._get_or_create(node.name)
        if node.returns is not None:
            node.returns = self.visit(node.returns)
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        if not self._should_preserve(node.name):
            node.name = self._get_or_create(node.name)
        self.generic_visit(node)
        return node

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Load, ast.Del)):
            node.id = self._get_or_create(node.id)
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if not self._should_preserve(node.attr) and node.attr in self._map:
            node.attr = self._map[node.attr]
        return node

    def visit_arg(self, node):
        if node.arg not in ("self", "cls"):
            node.arg = self._get_or_create(node.arg)
        if node.annotation is not None:
            node.annotation = self.visit(node.annotation)
        return node

    def visit_keyword(self, node):
        if node.arg is not None and node.arg in self._map:
            node.arg = self._map[node.arg]
        self.generic_visit(node)
        return node

    def visit_Global(self, node):
        node.names = [self._get_or_create(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._get_or_create(n) for n in node.names]
        return node

    # ── entry point 

    def transform(self, tree: ast.AST) -> ast.AST:
        self._collect_imports(tree)
        self._prebuild_map(tree)
        return self.visit(tree)
