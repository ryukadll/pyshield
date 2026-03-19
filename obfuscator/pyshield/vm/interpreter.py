import sys
import operator
import dis as _dis

from .isa import ISA, ALL_OPS, OP_NOP
from .compiler import VMProgram


_BINARY_OPS = {
    0:  operator.add,
    1:  operator.and_,
    2:  operator.floordiv,
    3:  operator.lshift,
    4:  operator.matmul,
    5:  operator.mul,
    6:  operator.mod,
    7:  operator.or_,
    8:  operator.pow,
    9:  operator.rshift,
    10: operator.sub,
    11: operator.truediv,
    12: operator.xor,
    13: lambda a, b: a + b,   
    14: lambda a, b: a & b,
    15: lambda a, b: a // b,
    16: lambda a, b: a << b,
    17: lambda a, b: a @ b,
    18: lambda a, b: a * b,
    19: lambda a, b: a % b,
    20: lambda a, b: a | b,
    21: lambda a, b: a ** b,
    22: lambda a, b: a >> b,
    23: lambda a, b: a - b,
    24: lambda a, b: a / b,
    25: lambda a, b: a ^ b,
}

_COMPARE_OPS = ['<', '<=', '==', '!=', '>', '>=', 'in', 'not in', 'is', 'is not', 'exception match', 'BAD']


class VMFrame:
    def __init__(self, prog: VMProgram, globals_dict: dict,
                 locals_dict: dict, closure=None):
        self.prog         = prog
        self.globals      = globals_dict
        self.locals       = locals_dict
        self.closure      = closure or []
        self.stack        = []
        self.block_stack  = []   
        self.pc           = 0    
        self.return_value = None
        self.yielded      = False
        self.exc_info     = (None, None, None)

    def push(self, v):
        self.stack.append(v)

    def pop(self):
        return self.stack.pop()

    def peek(self, n=0):
        return self.stack[-(1 + n)]

    def tos(self):
        return self.stack[-1]


class VMInterpreter:
    def __init__(self, isa: ISA):
        self.isa = isa

    def run(self, prog: VMProgram, globals_dict: dict,
            args: tuple = (), kwargs: dict = None,
            closure=None) -> object:
        kwargs   = kwargs or {}
        locals_d = {}

        for i, val in enumerate(args):
            if i < len(prog.varnames):
                locals_d[prog.varnames[i]] = val

        for k, v in kwargs.items():
            locals_d[k] = v

        frame = VMFrame(prog, globals_dict, locals_d, closure)
        return self._exec(frame)

    def _exec(self, frame: VMFrame) -> object:
        prog   = frame.prog
        instrs = prog.instructions
        consts = prog.consts
        names  = prog.names

        def resolve_name(idx: int):
            name = names[idx]
            if name in frame.locals:
                return frame.locals[name]
            if name in frame.globals:
                return frame.globals[name]
            import builtins
            return getattr(builtins, name)

        while frame.pc < len(instrs):
            op, arg = instrs[frame.pc]
            frame.pc += 1

            try:
                # ── Data movement 
                if op == 'LOAD_CONST':
                    frame.push(consts[arg])

                elif op == 'LOAD_FAST':
                    frame.push(frame.locals.get(prog.varnames[arg]))

                elif op == 'LOAD_FAST_AND_CLEAR':
                    v = frame.locals.get(prog.varnames[arg])
                    frame.push(v)
                    frame.locals[prog.varnames[arg]] = None

                elif op == 'STORE_FAST':
                    frame.locals[prog.varnames[arg]] = frame.pop()

                elif op == 'DELETE_FAST':
                    frame.locals.pop(prog.varnames[arg], None)

                elif op == 'LOAD_GLOBAL':
                    push_null = bool(arg & (1 << 15))
                    nidx = arg & 0x7FFF
                    name = names[nidx]
                    if push_null:
                        frame.push(None)  
                    val = frame.globals.get(name)
                    if val is None:
                        import builtins
                        val = getattr(builtins, name, None)
                    frame.push(val)

                elif op == 'LOAD_NAME':
                    frame.push(resolve_name(arg))

                elif op == 'STORE_NAME':
                    frame.globals[names[arg]] = frame.pop()

                elif op == 'LOAD_ATTR':
                    push_self = bool(arg & (1 << 15))
                    nidx = arg & 0x7FFF
                    obj = frame.pop()
                    attr = getattr(obj, names[nidx])
                    if push_self:
                        frame.push(None)   
                        frame.push(attr)
                    else:
                        frame.push(attr)

                elif op == 'STORE_ATTR':
                    obj = frame.pop()
                    val = frame.pop()
                    setattr(obj, names[arg], val)

                elif op == 'LOAD_DEREF':
                    cell = frame.closure[arg] if arg < len(frame.closure) else None
                    frame.push(cell.cell_contents if cell else None)

                elif op == 'STORE_DEREF':
                    if arg < len(frame.closure):
                        frame.closure[arg].cell_contents = frame.pop()

                elif op == 'LOAD_CLOSURE':
                    frame.push(frame.closure[arg])

                elif op == 'LOAD_SUPER_ATTR':
                    self_obj = frame.locals.get('self') or frame.locals.get(prog.varnames[0] if prog.varnames else 'self')
                    tp = type(self_obj)
                    attr = names[arg & 0x7FFF]
                    frame.push(getattr(super(tp, self_obj), attr))

                elif op == 'LOAD_BUILD_CLASS':
                    import builtins
                    frame.push(builtins.__build_class__)

                elif op == 'COPY_FREE_VARS':
                    pass  

                elif op == 'MAKE_CELL':
                    pass  

                elif op == 'POP_TOP':
                    frame.pop()

                elif op == 'COPY':
                    frame.push(frame.peek(arg - 1))

                elif op == 'SWAP':
                    i = -(arg)
                    frame.stack[-1], frame.stack[i] = frame.stack[i], frame.stack[-1]

                elif op == 'PUSH_NULL':
                    frame.push(None)

                # ── Arithmetic 
                elif op == 'BINARY_OP':
                    rhs = frame.pop()
                    lhs = frame.pop()
                    fn  = _BINARY_OPS.get(arg)
                    frame.push(fn(lhs, rhs) if fn else NotImplemented)

                elif op == 'COMPARE_OP':
                    rhs = frame.pop()
                    lhs = frame.pop()
                    cmp = arg >> 4 if arg > 11 else arg 
                    cmp = cmp & 0xF
                    ops = ['<','<=','==','!=','>','>=']
                    if cmp < len(ops):
                        frame.push(eval(f'lhs {ops[cmp]} rhs'))
                    elif cmp == 6:
                        frame.push(lhs in rhs)
                    elif cmp == 7:
                        frame.push(lhs not in rhs)
                    elif cmp == 8:
                        frame.push(lhs is rhs)
                    elif cmp == 9:
                        frame.push(lhs is not rhs)
                    else:
                        frame.push(False)

                # ── Calls 
                elif op == 'CALL':
                    nargs = arg
                    pos_args = list(reversed([frame.pop() for _ in range(nargs)]))
                    func     = frame.pop()
                    _null    = frame.pop()  
                    if _null is not None:
                        result = func(*pos_args)
                    else:
                        result = func(*pos_args)
                    frame.push(result)

                elif op == 'CALL_INTRINSIC_1':
                    val = frame.pop()
                    if arg == 5:
                        frame.push(tuple(val))
                    else:
                        frame.push(val)

                # ── Jumps 
                elif op == 'JUMP':
                    frame.pc = arg

                elif op == 'JUMP_IF_FALSE':
                    cond = frame.pop()
                    if not cond:
                        frame.pc = arg

                elif op == 'JUMP_IF_TRUE':
                    cond = frame.pop()
                    if cond:
                        frame.pc = arg

                elif op == 'JUMP_IF_FALSE_NK':
                    if not frame.tos():
                        frame.pc = arg
                    else:
                        frame.pop()

                elif op == 'JUMP_IF_TRUE_NK':
                    if frame.tos():
                        frame.pc = arg
                    else:
                        frame.pop()

                # ── Iterators 
                elif op == 'GET_ITER':
                    frame.push(iter(frame.pop()))

                elif op == 'FOR_ITER':
                    it = frame.tos()
                    try:
                        frame.push(next(it))
                    except StopIteration:
                        frame.pop()  
                        frame.pc = arg

                elif op == 'END_FOR':
                    frame.pop()

                elif op == 'SEND':
                    val = frame.pop()
                    gen = frame.tos()
                    try:
                        result = gen.send(val)
                        frame.push(result)
                    except StopIteration as e:
                        frame.pop()
                        frame.push(e.value)
                        frame.pc = arg

                # ── Build ops 
                elif op == 'BUILD_LIST':
                    items = list(reversed([frame.pop() for _ in range(arg)]))
                    frame.push(items)

                elif op == 'BUILD_TUPLE':
                    items = list(reversed([frame.pop() for _ in range(arg)]))
                    frame.push(tuple(items))

                elif op == 'BUILD_MAP':
                    items = {}
                    pairs = [frame.pop() for _ in range(arg * 2)]
                    for j in range(0, len(pairs), 2):
                        items[pairs[j+1]] = pairs[j]
                    frame.push(items)

                elif op == 'BUILD_STRING':
                    parts = list(reversed([str(frame.pop()) for _ in range(arg)]))
                    frame.push(''.join(parts))

                elif op == 'BUILD_CONST_KEY_MAP':
                    keys  = frame.pop()
                    vals  = list(reversed([frame.pop() for _ in range(arg)]))
                    frame.push(dict(zip(keys, vals)))

                elif op == 'LIST_APPEND':
                    val  = frame.pop()
                    lst  = frame.peek(arg - 1)
                    lst.append(val)

                elif op == 'MAP_ADD':
                    val = frame.pop()
                    key = frame.pop()
                    frame.peek(arg - 1)[key] = val

                elif op == 'LIST_EXTEND':
                    val = frame.pop()
                    frame.peek(arg - 1).extend(val)

                # ── Unpack 
                elif op == 'UNPACK_SEQ':
                    seq = list(frame.pop())
                    for v in reversed(seq[:arg]):
                        frame.push(v)

                elif op == 'UNPACK_EX':
                    before = arg & 0xFF
                    after  = (arg >> 8) & 0xFF
                    seq    = list(frame.pop())
                    for v in reversed(seq[before + after:] if after else seq[before:]):
                        frame.push(v) if not after else None
                    frame.push(seq[before:len(seq)-after] if after else seq[before:])
                    for v in reversed(seq[:before]):
                        frame.push(v)

                # ── Exceptions 
                elif op == 'PUSH_EXC_INFO':
                    exc = frame.pop()
                    frame.block_stack.append(('except', frame.exc_info))
                    frame.exc_info = (type(exc), exc, exc.__traceback__)
                    frame.push(exc)

                elif op == 'POP_EXCEPT':
                    if frame.block_stack:
                        _, saved = frame.block_stack.pop()
                        frame.exc_info = saved

                elif op == 'RERAISE':
                    tp, val, tb = frame.exc_info
                    if val:
                        raise val.with_traceback(tb)

                elif op == 'RAISE':
                    if arg == 0:
                        raise
                    elif arg == 1:
                        exc = frame.pop()
                        raise exc
                    else:
                        cause = frame.pop()
                        exc   = frame.pop()
                        raise exc from cause

                elif op == 'CHECK_EXC_MATCH':
                    exc  = frame.tos()
                    typ  = frame.pop()
                    frame.push(isinstance(exc, typ))

                elif op == 'WITH_EXCEPT_START':
                    exc_info = frame.exc_info
                    exit_fn  = frame.peek(3)
                    result   = exit_fn(*exc_info)
                    frame.push(result)

                elif op == 'CLEANUP_THROW':
                    pass

                # ── Returns / yield 
                elif op == 'RETURN_VALUE':
                    return frame.pop()

                elif op == 'RETURN_CONST':
                    return consts[arg]

                elif op == 'YIELD_VALUE':
                    raise NotImplementedError("YIELD_VALUE: use CPython for generators")

                elif op == 'GET_AWAITABLE':
                    raise NotImplementedError("GET_AWAITABLE: use CPython for coroutines")

                elif op == 'RETURN_GENERATOR':
                    raise NotImplementedError("RETURN_GENERATOR: use CPython for generators")

                # ── Functions / imports
                elif op == 'MAKE_FUNCTION':
                    func_code = frame.pop()
                    qualname  = frame.pop()
                    defaults  = None
                    kwdefaults = None
                    annotations = None
                    closure_cells = None
                    if arg & 0x08:
                        closure_cells = frame.pop()
                    if arg & 0x04:
                        annotations = frame.pop()
                    if arg & 0x02:
                        kwdefaults = frame.pop()
                    if arg & 0x01:
                        defaults = frame.pop()
                    import types
                    fn = types.FunctionType(func_code, frame.globals,
                                           qualname,
                                           defaults,
                                           closure_cells)
                    frame.push(fn)

                elif op == 'IMPORT_NAME':
                    fromlist = frame.pop()
                    level    = frame.pop()
                    name     = names[arg]
                    mod = __import__(name, frame.globals, frame.locals,
                                     fromlist, level)
                    frame.push(mod)

                elif op == 'IMPORT_FROM':
                    mod = frame.tos()
                    frame.push(getattr(mod, names[arg]))

                elif op == 'FORMAT_VALUE':
                    val = frame.pop()
                    fmt = frame.pop() if (arg & 0x04) else ''
                    conv = arg & 0x03
                    if conv == 1: val = str(val)
                    elif conv == 2: val = repr(val)
                    elif conv == 3: val = ascii(val)
                    frame.push(format(val, fmt) if fmt else format(val))

                elif op == 'NOP':
                    pass  

                else:
                    raise NotImplementedError(f"Unhandled VM op: {op}")

            except NotImplementedError:
                raise
            except Exception as e:
                while frame.block_stack:
                    kind, data = frame.block_stack[-1]
                    if kind == 'except':
                        frame.block_stack.pop()
                        frame.exc_info = data
                        raise
                    frame.block_stack.pop()
                raise

        return None
