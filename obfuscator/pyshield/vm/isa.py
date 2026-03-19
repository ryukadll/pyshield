import random
import struct

# ── Logical op names 

OP_LOAD_CONST       = 'LOAD_CONST'
OP_LOAD_FAST        = 'LOAD_FAST'
OP_LOAD_FAST2       = 'LOAD_FAST2'       
OP_LOAD_SMALL_INT   = 'LOAD_SMALL_INT'   
OP_STORE_FAST       = 'STORE_FAST'
OP_LOAD_GLOBAL      = 'LOAD_GLOBAL'
OP_LOAD_NAME        = 'LOAD_NAME'
OP_STORE_NAME       = 'STORE_NAME'
OP_LOAD_ATTR        = 'LOAD_ATTR'
OP_STORE_ATTR       = 'STORE_ATTR'
OP_LOAD_DEREF       = 'LOAD_DEREF'
OP_STORE_DEREF      = 'STORE_DEREF'
OP_LOAD_CLOSURE     = 'LOAD_CLOSURE'
OP_LOAD_SUPER_ATTR  = 'LOAD_SUPER_ATTR'
OP_BINARY_OP        = 'BINARY_OP'
OP_COMPARE_OP       = 'COMPARE_OP'
OP_TO_BOOL          = 'TO_BOOL'          
OP_CALL             = 'CALL'
OP_CALL_METHOD      = 'CALL_METHOD'
OP_POP_TOP          = 'POP_TOP'
OP_COPY             = 'COPY'
OP_SWAP             = 'SWAP'
OP_PUSH_NULL        = 'PUSH_NULL'
OP_JUMP             = 'JUMP'
OP_JUMP_IF_TRUE     = 'JUMP_IF_TRUE'
OP_JUMP_IF_FALSE    = 'JUMP_IF_FALSE'
OP_JUMP_IF_TRUE_NK  = 'JUMP_IF_TRUE_NK'
OP_JUMP_IF_FALSE_NK = 'JUMP_IF_FALSE_NK'
OP_JUMP_IF_NONE     = 'JUMP_IF_NONE'
OP_JUMP_IF_NOT_NONE = 'JUMP_IF_NOT_NONE'
OP_FOR_ITER         = 'FOR_ITER'
OP_GET_ITER         = 'GET_ITER'
OP_END_FOR          = 'END_FOR'
OP_BUILD_LIST       = 'BUILD_LIST'
OP_BUILD_TUPLE      = 'BUILD_TUPLE'
OP_BUILD_MAP        = 'BUILD_MAP'
OP_BUILD_STRING     = 'BUILD_STRING'
OP_BUILD_CONST_KEY_MAP = 'BUILD_CONST_KEY_MAP'
OP_LIST_APPEND      = 'LIST_APPEND'
OP_MAP_ADD          = 'MAP_ADD'
OP_LIST_EXTEND      = 'LIST_EXTEND'
OP_UNPACK_SEQ       = 'UNPACK_SEQ'
OP_UNPACK_EX        = 'UNPACK_EX'
OP_PUSH_EXC_INFO    = 'PUSH_EXC_INFO'
OP_POP_EXCEPT       = 'POP_EXCEPT'
OP_RERAISE          = 'RERAISE'
OP_RAISE            = 'RAISE'
OP_CHECK_EXC_MATCH  = 'CHECK_EXC_MATCH'
OP_WITH_EXCEPT_START= 'WITH_EXCEPT_START'
OP_RETURN_VALUE     = 'RETURN_VALUE'
OP_RETURN_CONST     = 'RETURN_CONST'
OP_YIELD_VALUE      = 'YIELD_VALUE'
OP_SEND             = 'SEND'
OP_GET_AWAITABLE    = 'GET_AWAITABLE'
OP_RETURN_GENERATOR = 'RETURN_GENERATOR'
OP_MAKE_FUNCTION    = 'MAKE_FUNCTION'
OP_MAKE_CELL        = 'MAKE_CELL'
OP_COPY_FREE_VARS   = 'COPY_FREE_VARS'
OP_IMPORT_NAME      = 'IMPORT_NAME'
OP_IMPORT_FROM      = 'IMPORT_FROM'
OP_LOAD_BUILD_CLASS = 'LOAD_BUILD_CLASS'
OP_FORMAT_VALUE     = 'FORMAT_VALUE'
OP_CALL_INTRINSIC_1 = 'CALL_INTRINSIC_1'
OP_DELETE_FAST      = 'DELETE_FAST'
OP_NOP              = 'NOP'
OP_EXTENDED_ARG     = 'EXTENDED_ARG'
OP_RESUME           = 'RESUME'
OP_CLEANUP_THROW    = 'CLEANUP_THROW'
OP_LOAD_FAST_AND_CLEAR = 'LOAD_FAST_AND_CLEAR'
OP_BINARY_SUBSCR    = 'BINARY_SUBSCR'
OP_STORE_SUBSCR     = 'STORE_SUBSCR'
OP_KW_NAMES         = 'KW_NAMES'
OP_END_SEND         = 'END_SEND'
OP_TO_BOOL               = 'TO_BOOL'
OP_LOAD_FAST_BORROW      = 'LOAD_FAST_BORROW'
OP_STORE_FAST_STORE_FAST  = 'STORE_FAST_STORE_FAST'
OP_STORE_FAST_LOAD_FAST   = 'STORE_FAST_LOAD_FAST'
OP_POP_ITER               = 'POP_ITER'
OP_CALL_KW                = 'CALL_KW'
OP_CALL_FUNCTION_EX       = 'CALL_FUNCTION_EX'
OP_FORMAT_SIMPLE          = 'FORMAT_SIMPLE'
OP_LOAD_SPECIAL           = 'LOAD_SPECIAL'
OP_BINARY_SLICE           = 'BINARY_SLICE'
OP_CONTAINS_OP            = 'CONTAINS_OP'
OP_LOAD_COMMON_CONSTANT   = 'LOAD_COMMON_CONSTANT'
OP_IS_OP                  = 'IS_OP'
OP_SET_FUNCTION_ATTRIBUTE = 'SET_FUNCTION_ATTRIBUTE'

ALL_OPS = [v for k, v in globals().items() if k.startswith('OP_')]


class ISA:

    def __init__(self, seed: int | None = None):
        rng = random.Random(seed)
        slots = list(range(255))
        rng.shuffle(slots)
        self._encode = {op: slots[i] for i, op in enumerate(ALL_OPS)}
        self._decode = {v: k for k, v in self._encode.items()}
        self.INSTR_SIZE = 3

    def encode_op(self, name: str) -> int:
        return self._encode[name]

    def decode_op(self, byte: int) -> str:
        return self._decode.get(byte, 'UNKNOWN')

    def emit(self, name: str, arg: int = 0) -> bytes:
        op = self._encode[name]
        return struct.pack('<BH', op, arg & 0xFFFF)

    @classmethod
    def from_seed(cls, seed: int) -> 'ISA':
        return cls(seed=seed)
