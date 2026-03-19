import base64
import os
import zlib
import pickle

from .isa import ISA
from .compiler import VMCompiler, VMProgram


def compile_to_vm(code_obj, isa: ISA) -> tuple[bytes, bytes] | None:
    import dis as _dis
    flags = code_obj.co_flags
    if flags & 0x20 or flags & 0x100 or flags & 0x200:
        return None
    instrs = list(_dis.get_instructions(code_obj))
    if any(i.opname == 'RETURN_GENERATOR' for i in instrs):
        return None
    try:
        compiler = VMCompiler(isa)
        prog     = compiler.compile(code_obj)
        vm_bytes = prog.to_bytes(isa)
        tables   = prog.serialize_tables()
        return vm_bytes, tables
    except Exception as e:
        import sys
        print(f"[vm] compile failed: {e}", file=sys.stderr)
        import traceback; traceback.print_exc(file=sys.stderr)
        return None


def build_vm_stub(func_name: str, vm_bytes: bytes, tables: bytes,
                  isa: ISA, args_node, is_method: bool, needs_cell: bool) -> str:
    from ..utils import uid

    vm_z       = zlib.compress(vm_bytes, 9)
    enc_tables = base64.b85encode(tables).decode()
    enc_vm     = base64.b85encode(vm_z).decode()

    isa_bytes = zlib.compress(pickle.dumps(isa._encode, protocol=4), 9)
    enc_isa   = base64.b85encode(isa_bytes).decode()

    vb = uid(4); vt = uid(4); vi = uid(4); vm = uid(4)
    vf = uid(4); vr = uid(4); vg = uid(4); vl = uid(4)

    arg_names = [a.arg for a in args_node.args]
    if args_node.vararg:
        arg_names.append(args_node.vararg.arg)
    for kw in args_node.kwonlyargs:
        arg_names.append(kw.arg)
    if args_node.kwarg:
        arg_names.append(args_node.kwarg.arg)

    args_dict_items = ', '.join(f"{repr(n)}: {n}" for n in arg_names)

    src = (
        f"import base64 as {vb}, zlib as {vi}, pickle as {vt}\n"
        f"{vm} = _PSVMInterp({vb}.b85decode({repr(enc_isa)}))\n"
        f"{vf} = {vm}.load({vb}.b85decode({repr(enc_vm)}),\n"
        f"               {vb}.b85decode({repr(enc_tables)}))\n"
        f"{vg} = globals()\n"
        f"{vl} = {{{args_dict_items}}}\n"
        f"{vr} = {vm}.run({vf}, {vg}, {vl})\n"
        f"del {vm}, {vf}, {vg}, {vl}\n"
        f"return {vr}\n"
    )
    return src


_VM_RUNTIME_SOURCE = r'''
import zlib as _zl, pickle as _pk, base64 as _b4, operator as _op, marshal as _ma

class _PSVMInterp:
    _BINOPS = [
        _op.add,_op.and_,_op.floordiv,_op.lshift,_op.matmul,_op.mul,_op.mod,
        _op.or_,_op.pow,_op.rshift,_op.sub,_op.truediv,_op.xor,
        lambda a,b:a+b,lambda a,b:a&b,lambda a,b:a//b,lambda a,b:a<<b,
        lambda a,b:a*b,lambda a,b:a%b,lambda a,b:a|b,lambda a,b:a**b,
        lambda a,b:a>>b,lambda a,b:a-b,lambda a,b:a/b,lambda a,b:a^b,
    ]

    def __init__(self,isa_enc):
        raw=_zl.decompress(isa_enc)
        self._isa=_pk.loads(raw)
        self._rev={v:k for k,v in self._isa.items()}

    def _dc(self,v):
        t,val=v
        if t=='code': return _ma.loads(_b4.b64decode(val))
        if t=='tuple': return tuple(self._dc(x) for x in val)
        if t=='frozenset': return frozenset(self._dc(x) for x in val)
        return val

    @staticmethod
    def _make_cell(val):
        """Create a real CPython cell object containing val."""
        return (lambda: val).__closure__[0]

    def load(self,vm_enc,tables_enc):
        vb=_zl.decompress(vm_enc)
        td=_pk.loads(_zl.decompress(tables_enc))
        td['consts']=[self._dc(c) for c in td['consts']]
        instrs=[]
        for i in range(0,len(vb),3):
            if i+2>=len(vb): break
            op=self._rev.get(vb[i],'NOP')
            arg=vb[i+1]|(vb[i+2]<<8)
            instrs.append((op,arg))
        td['instrs']=instrs
        return td

    def run(self,prog,gbl,lcl):
        instrs=prog['instrs']; consts=prog['consts']
        names=prog['names']; varnames=prog['varnames']
        cellvars=prog.get('cellvars',[]); freevars=prog.get('freevars',[])
        exc_table=prog.get('exc_table',[])
        stack=[]; blks=[]; pc=[0]; exc_ctx=[None]
        cells={}
        _kw_names=[()]

        def push(v): stack.append(v)
        def pop(): return stack.pop()
        def tos(): return stack[-1]
        def peek(n): return stack[-(1+n)]

        def rname(idx):
            n=names[idx]
            if n in lcl: return lcl[n]
            if n in gbl: return gbl[n]
            import builtins; return getattr(builtins,n)

        def find_handler(vi):
            for sv,ev,tv,dep in exc_table:
                if sv<=vi<ev: return tv,dep
            return None,0

        while pc[0]<len(instrs):
            cur_vi=pc[0]; op,arg=instrs[pc[0]]; pc[0]+=1
            try:
                if op=='LOAD_CONST': push(consts[arg])
                elif op=='LOAD_FAST':
                    vn=varnames[arg] if arg<len(varnames) else ''
                    if vn in cells:
                        try: push(cells[vn].cell_contents)
                        except ValueError: push(None)
                    else: push(lcl.get(vn))
                elif op=='LOAD_FAST_AND_CLEAR':
                    vn=varnames[arg] if arg<len(varnames) else ''
                    if vn in cells:
                        try: v=cells[vn].cell_contents
                        except ValueError: v=None
                        push(v)
                        cells.pop(vn,None)
                    else:
                        push(lcl.get(vn)); lcl[vn]=None
                elif op=='STORE_FAST':
                    vn=varnames[arg] if arg<len(varnames) else ''
                    v=pop()
                    if vn in cells: cells[vn]=self._make_cell(v)
                    else: lcl[vn]=v
                elif op=='DELETE_FAST':
                    vn=varnames[arg] if arg<len(varnames) else ''
                    cells.pop(vn,None); lcl.pop(vn,None)
                elif op=='LOAD_GLOBAL':
                    pn=bool(arg&(1<<15)); ni=arg&0x7FFF; nm=names[ni]
                    if pn: push(None)
                    v=gbl.get(nm)
                    if v is None:
                        import builtins; v=getattr(builtins,nm,None)
                    push(v)
                elif op=='LOAD_NAME': push(rname(arg))
                elif op=='STORE_NAME': gbl[names[arg]]=pop()
                elif op=='LOAD_ATTR':
                    ps=bool(arg&(1<<15)); ni=arg&0x7FFF; obj=pop()
                    a=getattr(obj,names[ni])
                    if ps: push(None); push(a)
                    else: push(a)
                elif op=='STORE_ATTR':
                    obj=pop(); val=pop(); setattr(obj,names[arg],val)
                elif op=='MAKE_CELL':
                    all_cv=cellvars+freevars
                    if arg<len(all_cv):
                        nm=all_cv[arg]
                        val=lcl.get(nm)
                        cells[nm]=self._make_cell(val)
                elif op=='LOAD_DEREF':
                    all_cv=cellvars+freevars
                    if arg<len(all_cv):
                        nm=all_cv[arg]
                        if nm in cells:
                            try: push(cells[nm].cell_contents)
                            except ValueError: push(None)
                        else: push(lcl.get(nm))
                    else: push(None)
                elif op=='STORE_DEREF':
                    all_cv=cellvars+freevars
                    if arg<len(all_cv):
                        nm=all_cv[arg]
                        cells[nm]=self._make_cell(pop())
                elif op=='LOAD_CLOSURE':
                    all_cv=cellvars+freevars
                    if arg<len(all_cv):
                        nm=all_cv[arg]
                        if nm not in cells:
                            cells[nm]=self._make_cell(lcl.get(nm))
                        push(cells[nm])
                    else: push(self._make_cell(None))
                elif op=='COPY_FREE_VARS': pass
                elif op=='LOAD_BUILD_CLASS':
                    import builtins; push(builtins.__build_class__)
                elif op=='LOAD_SUPER_ATTR':
                    ps=bool(arg&(1<<15)); ni=arg&0x7FFF
                    self_obj=lcl.get(varnames[0]) if varnames else None
                    tp=type(self_obj) if self_obj else object
                    a=getattr(super(tp,self_obj),names[ni])
                    if ps: push(None); push(a)
                    else: push(a)
                elif op=='POP_TOP': pop()
                elif op=='COPY':
                    if len(stack)>=arg: push(peek(arg-1))
                elif op=='SWAP':
                    if len(stack)>=arg: stack[-1],stack[-arg]=stack[-arg],stack[-1]
                elif op=='PUSH_NULL': push(None)
                elif op=='BINARY_OP':
                    r=pop(); l=pop()
                    fn=self._BINOPS[arg] if arg<len(self._BINOPS) else _op.add
                    push(fn(l,r))
                elif op=='COMPARE_OP':
                    r=pop(); l=pop(); c=arg>>4 if arg>11 else arg; c&=0xF
                    ops=['<','<=','==','!=','>','>=']
                    if c<len(ops): push(eval(f'l {ops[c]} r',{'l':l,'r':r}))
                    elif c==6: push(l in r)
                    elif c==7: push(l not in r)
                    elif c==8: push(l is r)
                    elif c==9: push(l is not r)
                    else: push(False)
                elif op=='BINARY_SUBSCR':
                    key=pop(); obj=pop(); push(obj[key])
                elif op=='STORE_SUBSCR':
                    key=pop(); obj=pop(); val=pop(); obj[key]=val
                elif op=='BINARY_SLICE':
                    stop=pop(); start=pop(); obj=pop(); push(obj[start:stop])
                elif op=='CONTAINS_OP':
                    seq=pop(); item=pop()
                    push((item not in seq) if arg else (item in seq))
                elif op=='IS_OP':
                    b=pop(); a=pop()
                    push((a is not b) if arg else (a is b))
                elif op=='KW_NAMES':
                    _kw_names[0]=consts[arg] if arg<len(consts) else ()
                elif op=='END_SEND':
                    pass  
                elif op=='FORMAT_SIMPLE':
                    push(format(pop()))
                elif op=='LOAD_COMMON_CONSTANT':
                    _cc=(None,True,False)
                    push(_cc[arg] if arg<len(_cc) else None)
                elif op=='LOAD_SPECIAL':
                    push(None)
                elif op=='CALL_KW':
                    kw_names=pop()  
                    pa=[pop() for _ in range(arg)]; pa.reverse()
                    ns=pop(); fn=pop()
                    if fn is None: fn,ns=ns,None
                    if ns is not None: pa=[ns]+pa
                    if kw_names:
                        n_kw=len(kw_names)
                        push(fn(*pa[:-n_kw],**dict(zip(kw_names,pa[-n_kw:]))))
                    else:
                        push(fn(*pa))
                elif op=='CALL_FUNCTION_EX':
                    kwargs=pop() if arg&1 else {}
                    args_t=pop()
                    fn=pop()
                    if not callable(fn): fn,args_t=args_t,fn  
                    push(fn(*args_t,**kwargs))
                elif op=='STORE_FAST_STORE_FAST':
                    lo=arg&0xFF; hi=(arg>>8)&0xFF
                    vn0=varnames[lo] if lo<len(varnames) else ''
                    vn1=varnames[hi] if hi<len(varnames) else ''
                    v0=pop(); v1=pop()
                    if vn0 in cells: cells[vn0]=self._make_cell(v0)
                    else: lcl[vn0]=v0
                    if vn1 in cells: cells[vn1]=self._make_cell(v1)
                    else: lcl[vn1]=v1
                elif op=='STORE_FAST_LOAD_FAST':
                    lo=arg&0xFF; hi=(arg>>8)&0xFF
                    vn0=varnames[lo] if lo<len(varnames) else ''
                    vn1=varnames[hi] if hi<len(varnames) else ''
                    v=pop()
                    if vn0 in cells: cells[vn0]=self._make_cell(v)
                    else: lcl[vn0]=v
                    if vn1 in cells:
                        try: push(cells[vn1].cell_contents)
                        except ValueError: push(None)
                    else: push(lcl.get(vn1))
                elif op=='POP_ITER':
                    pop()
                elif op=='SET_FUNCTION_ATTRIBUTE':
                    import types
                    attr=pop(); fn=pop()
                    if arg==1:
                        if hasattr(fn,'__defaults__'): fn.__defaults__=attr
                    elif arg==2:
                        if hasattr(fn,'__kwdefaults__'): fn.__kwdefaults__=attr
                    elif arg==4:
                        if hasattr(fn,'__annotations__'): fn.__annotations__=attr
                    elif arg==8:
                        fn=types.FunctionType(fn.__code__,fn.__globals__,
                                              fn.__name__,fn.__defaults__,attr)
                    push(fn)
                elif op=='LOAD_FAST_BORROW':
                    vn=varnames[arg] if arg<len(varnames) else ''
                    if vn in cells:
                        try: push(cells[vn].cell_contents)
                        except ValueError: push(None)
                    else: push(lcl.get(vn))
                elif op=='LOAD_FAST_BORROW_LOAD_FAST_BORROW':
                    idx1=arg&0xFF; idx2=(arg>>8)&0xFF
                    for idx in (idx1, idx2):
                        vn=varnames[idx] if idx<len(varnames) else ''
                        if vn in cells:
                            try: push(cells[vn].cell_contents)
                            except ValueError: push(None)
                        else: push(lcl.get(vn))
                elif op=='LOAD_SMALL_INT':
                    push(arg)
                elif op=='TO_BOOL':
                    push(bool(pop()))
                elif op=='CALL':
                    kw_names=_kw_names[0]; _kw_names[0]=()
                    pa=[pop() for _ in range(arg)]; pa.reverse()
                    ns=pop()  
                    fn=pop()  
                    if fn is None:
                        fn,ns=ns,None
                    if ns is not None:
                        pa=[ns]+pa
                    if kw_names:
                        n_kw=len(kw_names)
                        pos_args=pa[:-n_kw]
                        kw_args=dict(zip(kw_names,pa[-n_kw:]))
                        push(fn(*pos_args,**kw_args))
                    else:
                        push(fn(*pa))
                elif op=='CALL_INTRINSIC_1':
                    v=pop(); push(tuple(v) if arg==5 else v)
                elif op=='JUMP': pc[0]=arg
                elif op=='JUMP_IF_FALSE':
                    if not pop(): pc[0]=arg
                elif op=='JUMP_IF_TRUE':
                    if pop(): pc[0]=arg
                elif op=='JUMP_IF_FALSE_NK':
                    if not tos(): pc[0]=arg
                    else: pop()
                elif op=='JUMP_IF_TRUE_NK':
                    if tos(): pc[0]=arg
                    else: pop()
                elif op=='GET_ITER': push(iter(pop()))
                elif op=='FOR_ITER':
                    it=tos()
                    try: push(next(it))
                    except StopIteration: pc[0]=arg  
                elif op=='END_FOR': pop()  
                elif op=='BUILD_LIST':
                    i=[pop() for _ in range(arg)]; i.reverse(); push(i)
                elif op=='BUILD_TUPLE':
                    i=[pop() for _ in range(arg)]; i.reverse(); push(tuple(i))
                elif op=='BUILD_MAP':
                    d={}
                    for _ in range(arg): v=pop();k=pop();d[k]=v
                    push(d)
                elif op=='BUILD_STRING':
                    p=[pop() for _ in range(arg)]; p.reverse()
                    push(''.join(str(x) for x in p))
                elif op=='BUILD_CONST_KEY_MAP':
                    ks=pop(); vs=[pop() for _ in range(arg)]; vs.reverse()
                    push(dict(zip(ks,vs)))
                elif op=='LIST_APPEND':
                    lst=peek(arg); v=pop(); lst.append(v)
                elif op=='MAP_ADD':
                    mp=peek(arg); v=pop(); k=pop(); mp[k]=v
                elif op=='LIST_EXTEND': peek(arg).extend(pop())
                elif op=='UNPACK_SEQ':
                    s=list(pop())
                    for v in reversed(s[:arg]): push(v)
                elif op=='UNPACK_EX':
                    bf=arg&0xFF; af=(arg>>8)&0xFF; s=list(pop())
                    for v in reversed(s[:bf]): push(v)
                    push(s[bf:len(s)-af if af else len(s)])
                    if af:
                        for v in reversed(s[len(s)-af:]): push(v)
                elif op=='PUSH_EXC_INFO':
                    exc=pop(); old=exc_ctx[0]
                    blks.append(('exc',old,len(stack)))
                    exc_ctx[0]=exc
                    push(old)   
                    push(exc)   
                elif op=='POP_EXCEPT':
                    if blks: _,ec,_sd=blks.pop(); exc_ctx[0]=ec
                    if stack: pop() 
                elif op=='RERAISE':
                    ec=exc_ctx[0]
                    if ec: raise ec
                elif op=='RAISE':
                    if arg==0: raise
                    elif arg==1: raise pop()
                    else: c=pop();e=pop(); raise e from c
                elif op=='CHECK_EXC_MATCH':
                    tp=pop(); exc=tos(); push(isinstance(exc,tp))
                elif op=='WITH_EXCEPT_START':
                    ec=exc_ctx[0]; fn=peek(3)
                    push(fn(type(ec),ec,ec.__traceback__) if ec else fn(None,None,None))
                elif op=='RETURN_VALUE': return pop()
                elif op=='RETURN_CONST': return consts[arg]
                elif op in ('NOP','CLEANUP_THROW','COPY_FREE_VARS',
                            'SEND','GET_AWAITABLE',
                            'RETURN_GENERATOR','YIELD_VALUE',
                            'NOT_TAKEN','RESUME_CHECK',
                            'DICT_MERGE','DICT_UPDATE','SET_UPDATE'): pass
                elif op=='MAKE_FUNCTION':
                    import types
                    fc=pop()
                    qn=getattr(fc,'co_qualname',getattr(fc,'co_name',''))
                    df=kd=an=cl=None
                    if arg&8: cl=pop()   
                    if arg&4: an=pop()
                    if arg&2: kd=pop()
                    if arg&1: df=pop()
                    push(types.FunctionType(fc,gbl,qn,df,cl))
                elif op=='IMPORT_NAME':
                    fl=pop(); lv=pop()
                    push(__import__(names[arg],gbl,lcl,fl,lv))
                elif op=='IMPORT_FROM': push(getattr(tos(),names[arg]))
                elif op=='FORMAT_VALUE':
                    fmt=pop() if arg&4 else ''
                    v=pop(); c=arg&3
                    if c==1: v=str(v)
                    elif c==2: v=repr(v)
                    elif c==3: v=ascii(v)
                    push(format(v,fmt) if fmt else format(v))
            except (KeyboardInterrupt,SystemExit): raise
            except Exception as _e:
                hv,dep=find_handler(cur_vi)
                if hv is not None:
                    while len(stack)>dep: stack.pop()
                    push(_e)   
                    exc_ctx[0]=_e
                    pc[0]=hv
                else:
                    raise
        return None
'''
