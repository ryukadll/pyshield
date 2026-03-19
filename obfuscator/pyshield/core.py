import ast
import os

from .entanglement import EntanglementSeed
from .passes import (
    IdentifierRenamer,
    ConstantTransformer,
    DistributedStringEncryptor,
    DeadCodeInjector,
    ControlFlowTransformer,
)
from .protection.runtime import RuntimeEncryptor
from .protection.anti_analysis import (
    make_guard_source, make_canary_key_mix_source,
)
from .wrapper import create_heterogeneous_wrapper
from .vm.pass_ import VMPass


class _AnnotationStripper(ast.NodeTransformer):
    def visit_arg(self, node):
        node.annotation = None
        return node

    def visit_FunctionDef(self, node):
        node.returns = None
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_AnnAssign(self, node):
        if node.value is not None:
            new = ast.Assign(
                targets=[node.target],
                value=node.value,
            )
            return ast.copy_location(new, node)
        return None


class PyShieldObfuscator:
    def __init__(
        self,
        rename_identifiers:  bool = True,
        encode_strings:      bool = True,
        transform_constants: bool = True,
        inject_dead_code:    bool = True,
        obfuscate_flow:      bool = True,
        wrap_exec:           bool = True,
        runtime_encrypt:     bool = True,
        c_guard_mode:        bool = False,
        vm_pass:             bool = False,   
    ):
        self.rename_identifiers  = rename_identifiers
        self.encode_strings      = encode_strings
        self.transform_constants = transform_constants
        self.inject_dead_code    = inject_dead_code
        self.obfuscate_flow      = obfuscate_flow
        self.wrap_exec           = wrap_exec
        self.runtime_encrypt     = runtime_encrypt
        self.c_guard_mode        = c_guard_mode
        self.vm_pass             = vm_pass

    def obfuscate(self, source: str, filename: str = "<protected>") -> str:
        tree = ast.parse(source)
        tree = _AnnotationStripper().visit(tree)
        ast.fix_missing_locations(tree)

        seed    = EntanglementSeed()
        renamer = IdentifierRenamer()
        canary  = os.urandom(4)

        if self.rename_identifiers:
            tree = renamer.transform(tree)

        if self.vm_pass:
            vm = VMPass(source_file=filename)
            tree = vm.transform(tree)
            ast.fix_missing_locations(tree)

        rt_enc = RuntimeEncryptor(source_file=filename, canary=canary)
        if self.runtime_encrypt:
            tree = rt_enc.transform(tree, source_file=filename)

        if self.transform_constants:
            tree = ConstantTransformer().transform(tree)

        str_enc = DistributedStringEncryptor(seed)
        if self.encode_strings:
            tree = str_enc.transform(tree)

        if self.inject_dead_code:
            tree = DeadCodeInjector().transform(tree)

        if self.obfuscate_flow:
            module_level_obf: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Module):
                    for stmt in node.body:
                        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                                             ast.ClassDef)):
                            module_level_obf.add(stmt.name)
                        elif isinstance(stmt, ast.Assign):
                            for t in stmt.targets:
                                if isinstance(t, ast.Name):
                                    module_level_obf.add(t.id)
                    break
            tree = ControlFlowTransformer(renamer._map, module_level_obf).transform(tree)

        ast.fix_missing_locations(tree)
        inner = ast.unparse(tree)

        if self.encode_strings:
            inner = seed.init_statements() + inner

        guard = make_guard_source(canary)
        inner = guard + "\n" + inner

        if self.wrap_exec:
            return create_heterogeneous_wrapper(inner)

        return inner

