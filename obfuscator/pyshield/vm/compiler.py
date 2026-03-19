import dis
import marshal
import base64
import struct
import zlib
import pickle

from .isa import ISA, ALL_OPS
from .isa import *   


def _parse_exc_table(code_obj) -> list:
    data = code_obj.co_exceptiontable
    entries = []
    i = 0
    def read_varint():
        nonlocal i
        val = 0; shift = 0
        while i < len(data):
            b = data[i]; i += 1
            val |= (b & 0x3F) << shift; shift += 6
            if not (b & 0x40): break
        return val
    while i < len(data):
        start  = read_varint() * 2
        length = read_varint() * 2
        target = read_varint() * 2
        dl     = read_varint()
        entries.append((start, start + length, target, dl >> 1))
    return entries


def _serialize_const(c) -> tuple:
    if hasattr(c, 'co_code'):
        return ('code', base64.b64encode(marshal.dumps(c)).decode())
    elif isinstance(c, tuple):
        return ('tuple', [_serialize_const(x) for x in c])
    elif isinstance(c, frozenset):
        return ('frozenset', [_serialize_const(x) for x in c])
    else:
        return ('obj', c)


def _deserialize_const(v: tuple):
    typ, val = v
    if typ == 'code':
        return marshal.loads(base64.b64decode(val))
    elif typ == 'tuple':
        return tuple(_deserialize_const(x) for x in val)
    elif typ == 'frozenset':
        return frozenset(_deserialize_const(x) for x in val)
    else:
        return val


class VMProgram:
    def __init__(self):
        self.instructions: list[tuple[str, int]] = []
        self.consts    = []
        self.names     = []
        self.varnames  = []
        self.cellvars  = []
        self.freevars  = []
        self.flags     = 0
        self.argcount  = 0
        self.is_generator = False
        self.is_async     = False
        self.exc_table: list[tuple[int,int,int,int]] = []

    def add_const(self, v) -> int:
        for i, c in enumerate(self.consts):
            if c is v or c == v:
                return i
        self.consts.append(v)
        return len(self.consts) - 1

    def add_name(self, n: str) -> int:
        if n not in self.names:
            self.names.append(n)
        return self.names.index(n)

    def emit(self, op: str, arg: int = 0):
        self.instructions.append((op, arg))

    def to_bytes(self, isa: ISA) -> bytes:
        out = bytearray()
        for op, arg in self.instructions:
            out += isa.emit(op, arg)
        return bytes(out)

    def serialize_tables(self) -> bytes:
        data = {
            'consts':    [_serialize_const(c) for c in self.consts],
            'names':     self.names,
            'varnames':  self.varnames,
            'cellvars':  self.cellvars,
            'freevars':  self.freevars,
            'flags':     self.flags,
            'argcount':  self.argcount,
            'is_gen':    self.is_generator,
            'is_async':  self.is_async,
            'exc_table': self.exc_table,
        }
        return zlib.compress(pickle.dumps(data, protocol=4), 9)

    @staticmethod
    def deserialize_tables(raw: bytes) -> dict:
        data = pickle.loads(zlib.decompress(raw))
        data['consts'] = [_deserialize_const(c) for c in data['consts']]
        return data


_SKIP_OPS = frozenset({
    'RESUME', 'NOP', 'EXTENDED_ARG',
    'NOT_TAKEN', 'PREDICTED', 'JUMP_FORWARD_NO_INTERRUPT',
})


class VMCompiler:
    def __init__(self, isa: ISA):
        self.isa = isa

    def compile(self, code_obj) -> VMProgram:
        prog = VMProgram()
        prog.argcount  = code_obj.co_argcount
        prog.flags     = code_obj.co_flags
        prog.varnames  = list(code_obj.co_varnames)
        prog.cellvars  = list(code_obj.co_cellvars)
        prog.freevars  = list(code_obj.co_freevars)
        prog.consts    = list(code_obj.co_consts)
        prog.names     = list(code_obj.co_names)
        prog.is_generator = bool(code_obj.co_flags & 0x20)
        prog.is_async     = bool(code_obj.co_flags & 0x100)

        instrs_list = list(dis.get_instructions(code_obj))

        offset_to_vi: dict[int, int] = {}
        vi = 0
        for instr in instrs_list:
            offset_to_vi[instr.offset] = vi
            if instr.opname not in _SKIP_OPS:
                vi += 1

        raw_exc = _parse_exc_table(code_obj)
        vm_instrs: list[list] = []
        patches: list[tuple[int,int]] = []

        def emit(op, arg=0):
            vm_instrs.append([op, arg])

        def vname(instr, raw_arg):
            av = instr.argval
            return av if isinstance(av, str) else (
                prog.varnames[raw_arg] if raw_arg < len(prog.varnames) else str(raw_arg)
            )

        def vidx(name):
            if name not in prog.varnames:
                prog.varnames.append(name)
            return prog.varnames.index(name)

        def nname(instr):
            av = instr.argval
            return av if isinstance(av, str) else str(av)

        i = 0
        while i < len(instrs_list):
            instr   = instrs_list[i]
            op      = instr.opname
            raw_arg = instr.arg or 0
            argval  = instr.argval

            if op in _SKIP_OPS:
                i += 1; continue

            # ── Data movement 
            if op == 'LOAD_CONST':
                emit(OP_LOAD_CONST, prog.add_const(argval))

            elif op in ('LOAD_FAST', 'LOAD_FAST_CHECK',
                        'LOAD_FAST_BORROW', 'LOAD_FAST_AND_CLEAR_BORROW'):
                emit(OP_LOAD_FAST, vidx(vname(instr, raw_arg)))

            elif op == 'LOAD_FAST_AND_CLEAR':
                emit(OP_LOAD_FAST_AND_CLEAR, vidx(vname(instr, raw_arg)))

            elif op == 'LOAD_FAST_LOAD_FAST':
                idx1 = (raw_arg >> 4) & 0xF
                idx2 = raw_arg & 0xF
                n1 = prog.varnames[idx1] if idx1 < len(prog.varnames) else str(idx1)
                n2 = prog.varnames[idx2] if idx2 < len(prog.varnames) else str(idx2)
                emit(OP_LOAD_FAST, vidx(n1))
                emit(OP_LOAD_FAST, vidx(n2))

            elif op == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
                idx1 = (raw_arg >> 4) & 0xF
                idx2 = raw_arg & 0xF
                n1 = prog.varnames[idx1] if idx1 < len(prog.varnames) else str(idx1)
                n2 = prog.varnames[idx2] if idx2 < len(prog.varnames) else str(idx2)
                emit(OP_LOAD_FAST, vidx(n1))
                emit(OP_LOAD_FAST, vidx(n2))

            elif op == 'LOAD_SMALL_INT':
                emit(OP_LOAD_SMALL_INT, raw_arg)

            elif op == 'STORE_FAST':
                emit(OP_STORE_FAST, vidx(vname(instr, raw_arg)))

            elif op == 'DELETE_FAST':
                emit(OP_DELETE_FAST, vidx(vname(instr, raw_arg)))

            elif op == 'LOAD_GLOBAL':
                name = nname(instr)
                push_null = bool(raw_arg & 1)
                emit(OP_LOAD_GLOBAL, prog.add_name(name) | (int(push_null) << 15))

            elif op == 'LOAD_NAME':
                emit(OP_LOAD_NAME, prog.add_name(nname(instr)))

            elif op == 'STORE_NAME':
                emit(OP_STORE_NAME, prog.add_name(nname(instr)))

            elif op == 'LOAD_ATTR':
                name = nname(instr)
                push_self = bool(raw_arg & 1)
                emit(OP_LOAD_ATTR, prog.add_name(name) | (int(push_self) << 15))

            elif op == 'STORE_ATTR':
                emit(OP_STORE_ATTR, prog.add_name(nname(instr)))

            elif op == 'LOAD_DEREF':
                emit(OP_LOAD_DEREF, raw_arg)

            elif op == 'STORE_DEREF':
                emit(OP_STORE_DEREF, raw_arg)

            elif op == 'LOAD_CLOSURE':
                emit(OP_LOAD_CLOSURE, raw_arg)

            elif op == 'LOAD_SUPER_ATTR':
                name = nname(instr)
                emit(OP_LOAD_SUPER_ATTR, prog.add_name(name) | ((raw_arg & 1) << 15))

            elif op == 'LOAD_BUILD_CLASS':
                emit(OP_LOAD_BUILD_CLASS)

            elif op == 'COPY_FREE_VARS':
                emit(OP_COPY_FREE_VARS, raw_arg)

            elif op == 'MAKE_CELL':
                emit(OP_MAKE_CELL, raw_arg)

            # ── Stack ops 
            elif op == 'POP_TOP':   emit(OP_POP_TOP)
            elif op == 'COPY':      emit(OP_COPY, raw_arg)
            elif op == 'SWAP':      emit(OP_SWAP, raw_arg)
            elif op == 'PUSH_NULL': emit(OP_PUSH_NULL)

            # ── Arithmetic / comparison 
            elif op == 'BINARY_OP':  emit(OP_BINARY_OP, raw_arg)
            elif op == 'COMPARE_OP': emit(OP_COMPARE_OP, raw_arg)
            elif op == 'TO_BOOL':    emit(OP_TO_BOOL)   # 3.14+: bool(TOS)

            # ── Subscript 
            elif op == 'BINARY_SUBSCR': emit(OP_BINARY_SUBSCR)
            elif op == 'STORE_SUBSCR':  emit(OP_STORE_SUBSCR)

            # ── Calls 
            elif op == 'CALL':              emit(OP_CALL, raw_arg)
            elif op == 'CALL_INTRINSIC_1':  emit(OP_CALL_INTRINSIC_1, raw_arg)
            elif op == 'KW_NAMES':          emit(OP_KW_NAMES, prog.add_const(argval))

            # ── Jumps 
            elif op in ('JUMP_FORWARD', 'JUMP_BACKWARD',
                        'JUMP_BACKWARD_NO_INTERRUPT'):
                patches.append((len(vm_instrs), argval)); emit(OP_JUMP)

            elif op == 'POP_JUMP_IF_FALSE':
                patches.append((len(vm_instrs), argval)); emit(OP_JUMP_IF_FALSE)

            elif op == 'POP_JUMP_IF_TRUE':
                patches.append((len(vm_instrs), argval)); emit(OP_JUMP_IF_TRUE)

            elif op == 'JUMP_IF_FALSE_OR_POP':
                patches.append((len(vm_instrs), argval)); emit(OP_JUMP_IF_FALSE_NK)

            elif op == 'JUMP_IF_TRUE_OR_POP':
                patches.append((len(vm_instrs), argval)); emit(OP_JUMP_IF_TRUE_NK)

            elif op == 'POP_JUMP_IF_NONE':
                patches.append((len(vm_instrs), argval)); emit(OP_JUMP_IF_NONE)

            elif op == 'POP_JUMP_IF_NOT_NONE':
                patches.append((len(vm_instrs), argval)); emit(OP_JUMP_IF_NOT_NONE)

            # ── Iterators 
            elif op == 'GET_ITER': emit(OP_GET_ITER)
            elif op == 'FOR_ITER':
                patches.append((len(vm_instrs), argval)); emit(OP_FOR_ITER)
            elif op == 'END_FOR':  emit(OP_END_FOR)
            elif op == 'SEND':
                patches.append((len(vm_instrs), argval)); emit(OP_SEND)
            elif op == 'END_SEND': emit(OP_END_SEND)

            # ── Build ops 
            elif op == 'BUILD_LIST':  emit(OP_BUILD_LIST, raw_arg)
            elif op == 'BUILD_TUPLE': emit(OP_BUILD_TUPLE, raw_arg)
            elif op == 'BUILD_MAP':   emit(OP_BUILD_MAP, raw_arg)
            elif op == 'BUILD_STRING':emit(OP_BUILD_STRING, raw_arg)
            elif op == 'BUILD_CONST_KEY_MAP': emit(OP_BUILD_CONST_KEY_MAP, raw_arg)
            elif op == 'LIST_APPEND': emit(OP_LIST_APPEND, raw_arg)
            elif op == 'MAP_ADD':     emit(OP_MAP_ADD, raw_arg)
            elif op == 'LIST_EXTEND': emit(OP_LIST_EXTEND, raw_arg)

            # ── Unpack 
            elif op == 'UNPACK_SEQUENCE': emit(OP_UNPACK_SEQ, raw_arg)
            elif op == 'UNPACK_EX':       emit(OP_UNPACK_EX, raw_arg)

            # ── Exceptions 
            elif op == 'PUSH_EXC_INFO':   emit(OP_PUSH_EXC_INFO)
            elif op == 'POP_EXCEPT':      emit(OP_POP_EXCEPT)
            elif op == 'RERAISE':         emit(OP_RERAISE, raw_arg)
            elif op == 'RAISE_VARARGS':   emit(OP_RAISE, raw_arg)
            elif op == 'CHECK_EXC_MATCH': emit(OP_CHECK_EXC_MATCH)
            elif op == 'WITH_EXCEPT_START': emit(OP_WITH_EXCEPT_START)
            elif op == 'CLEANUP_THROW':   emit(OP_CLEANUP_THROW)

            # ── Returns / yield 
            elif op == 'RETURN_VALUE':    emit(OP_RETURN_VALUE)
            elif op == 'RETURN_CONST':    emit(OP_RETURN_CONST, prog.add_const(argval))
            elif op == 'YIELD_VALUE':     emit(OP_YIELD_VALUE, raw_arg)
            elif op == 'GET_AWAITABLE':   emit(OP_GET_AWAITABLE, raw_arg)
            elif op == 'RETURN_GENERATOR':emit(OP_RETURN_GENERATOR)

            # ── Functions / classes 
            elif op == 'MAKE_FUNCTION':   emit(OP_MAKE_FUNCTION, raw_arg)
            elif op == 'IMPORT_NAME':
                emit(OP_IMPORT_NAME, prog.add_name(nname(instr)))
            elif op == 'IMPORT_FROM':
                emit(OP_IMPORT_FROM, prog.add_name(nname(instr)))
            elif op == 'FORMAT_VALUE':    emit(OP_FORMAT_VALUE, raw_arg)

            # ── Python 3.13/3.14 adaptive / new opcodes 
            elif op == 'TO_BOOL':
                emit(OP_TO_BOOL)
            elif op == 'LOAD_FAST_BORROW':
                vn = argval if isinstance(argval, str) else (prog.varnames[raw_arg] if raw_arg < len(prog.varnames) else '')
                emit(OP_LOAD_FAST_BORROW, prog.varnames.index(vn) if vn in prog.varnames else raw_arg)
            elif op == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
                emit(OP_LOAD_FAST_BORROW, raw_arg & 0xFF)
                emit(OP_LOAD_FAST_BORROW, (raw_arg >> 8) & 0xFF)
            elif op == 'LOAD_SMALL_INT':
                emit(OP_LOAD_CONST, prog.add_const(raw_arg))
            # ── Python 3.14 new opcodes 
            elif op == 'STORE_FAST_STORE_FAST':
                emit(OP_STORE_FAST_STORE_FAST, raw_arg)
            elif op == 'STORE_FAST_LOAD_FAST':
                emit(OP_STORE_FAST_LOAD_FAST, raw_arg)
            elif op == 'POP_ITER':
                emit(OP_POP_ITER)
            elif op == 'CALL_KW':
                emit(OP_CALL_KW, raw_arg)
            elif op == 'CALL_FUNCTION_EX':
                emit(OP_CALL_FUNCTION_EX, raw_arg)
            elif op == 'FORMAT_SIMPLE':
                emit(OP_FORMAT_SIMPLE)
            elif op == 'LOAD_SPECIAL':
                emit(OP_LOAD_SPECIAL, raw_arg)
            elif op == 'BINARY_SLICE':
                emit(OP_BINARY_SLICE)
            elif op == 'CONTAINS_OP':
                emit(OP_CONTAINS_OP, raw_arg)
            elif op == 'LOAD_COMMON_CONSTANT':
                emit(OP_LOAD_COMMON_CONSTANT, raw_arg)
            elif op == 'IS_OP':
                emit(OP_IS_OP, raw_arg)
            elif op == 'SET_FUNCTION_ATTRIBUTE':
                emit(OP_SET_FUNCTION_ATTRIBUTE, raw_arg)
            elif op in ('NOT_TAKEN', 'RESUME_CHECK', 'INSTRUMENTED_RESUME',
                        'COPY_FREE_VARS', 'PUSH_FRAME', 'DICT_MERGE',
                        'DICT_UPDATE', 'SET_UPDATE'):
                emit(OP_NOP)

            # ── Catch-all 
            else:
                import sys
                print(f"[vm] unhandled: {op}", file=sys.stderr)
                emit(OP_NOP)

            i += 1

        # Patch jumps
        for patch_vi, cpython_target in patches:
            vm_instrs[patch_vi][1] = offset_to_vi.get(cpython_target, 0)

        prog.instructions = [(op, arg) for op, arg in vm_instrs]

        # Convert exception table to VM indices
        for start_b, end_b, target_b, depth in raw_exc:
            sv = offset_to_vi.get(start_b, 0)
            ev = offset_to_vi.get(end_b, len(vm_instrs))
            tv = offset_to_vi.get(target_b, 0)
            prog.exc_table.append((sv, ev, tv, depth))

        return prog
