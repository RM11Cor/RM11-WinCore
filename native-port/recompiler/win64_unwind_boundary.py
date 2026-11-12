#!/usr/bin/env python3
"""Strict Win64 PE .xdata UNWIND_INFO decoding for genuine IL2CPP boundary work.

Parses metadata from an owner's original x64 PE build, NOT game binaries.
May reject malformed/newer encodings rather than misdeclare a standalone
function. Does not identify Unity gameplay methods or execute source code.

This decoder is designed for pairing with RUNTIME_FUNCTION records
(begin RVA, end RVA, unwind RVA) and file-backed read-only memory.
"""
from __future__ import annotations

import dataclasses
import struct
from typing import Any

OP_NAMES={
    0:"UWOP_PUSH_NONVOL",
    1:"UWOP_ALLOC_LARGE",
    2:"UWOP_ALLOC_SMALL",
    3:"UWOP_SET_FPREG",
    4:"UWOP_SAVE_NONVOL",
    5:"UWOP_SAVE_NONVOL_FAR",
    8:"UWOP_SAVE_XMM128",
    9:"UWOP_SAVE_XMM128_FAR",
    10:"UWOP_PUSH_MACHFRAME",
}
REG_NAMES=[
    "RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
    "R8","R9","R10","R11","R12","R13","R14","R15"
]
FLAG_EHANDLER=1
FLAG_UHANDLER=2
FLAG_CHAININFO=4
MAX_UNWIND_BYTES=16*1024

class UnsupportedWin64Unwind(ValueError):
    pass

def _check(valid:bool,reason:str)->None:
    if not valid:
        raise UnsupportedWin64Unwind(reason)

def _u16(buf:bytes,pos:int)->int:
    _check(pos>=0 and pos+2<=len(buf),"truncated unwind uint16")
    return struct.unpack_from("<H",buf,pos)[0]

def _u32(buf:bytes,pos:int)->int:
    _check(pos>=0 and pos+4<=len(buf),"truncated unwind uint32")
    return struct.unpack_from("<I",buf,pos)[0]

@dataclasses.dataclass(frozen=True)
class UnwindEntry:
    opcode:str
    code_offset:int
    op_info:int
    slots_consumed:int
    stack_delta_bytes:int
    save_offset_bytes:int|None

@dataclasses.dataclass(frozen=True)
class UnwindRecord:
    version:int
    flags:int
    prologue_bytes:int
    frame_register:str|None
    frame_offset_scaled16:int
    raw_code_slots:int
    unwind_operations:tuple[UnwindEntry,...]
    handler_rva:int|None
    chained_runtime_function:tuple[int,int,int]|None
    record_bytes_consumed:int
    stack_bytes_deallocated_by_unwind:int
    complete_local_method_proven:bool=False

    def safe_report(self)->dict[str,Any]:
        return {
            "schema":"rm11carx.win64-unwind-info-structural-v1",
            "version":self.version,
            "flags":self.flags,
            "prologue_bytes":self.prologue_bytes,
            "frame_register":self.frame_register,
            "frame_offset_scaled16":self.frame_offset_scaled16,
            "unwind_code_slots":self.raw_code_slots,
            "operations":[dataclasses.asdict(x) for x in self.unwind_operations],
            "handler_present":self.handler_rva is not None,
            "chained_runtime_function_present":
                self.chained_runtime_function is not None,
            "chained_runtime_function":self.chained_runtime_function,
            "record_bytes_consumed":self.record_bytes_consumed,
            "static_unwind_stack_bytes":self.stack_bytes_deallocated_by_unwind,
            "full_original_callable_game_method_proven":False,
            "x64_prologue_epilogue_semantics_executed":False,
        }

def decode_unwind_info(raw:bytes)->UnwindRecord:
    if not isinstance(raw,bytes):
        raise UnsupportedWin64Unwind("unwind byte source must be immutable bytes")
    _check(4<=len(raw)<=MAX_UNWIND_BYTES,
           "Win64 UNWIND_INFO buffer outside 4..16384 bytes")
    packed_version=raw[0]
    version=packed_version&0x7
    flags=packed_version>>3
    # Current Windows AMD64 uses version 1 (v2 adds epilogue op variants).
    # This decoder explicitly restricts to v1 until v2 has dedicated tests.
    _check(version==1,"unsupported Win64 UNWIND_INFO version")
    _check(flags&~7==0,"reserved Win64 unwind flags present")
    _check(not(flags&FLAG_CHAININFO and flags&(FLAG_EHANDLER|FLAG_UHANDLER)),
           "Win64 chained info must not coexist with custom EH/UH handlers")
    prolog=raw[1]
    slots=raw[2]
    frame=raw[3]&0xf
    frame_offset=raw[3]>>4
    _check(frame!=0 or frame_offset==0,
           "frame offset without a frame register")
    base_size=4+slots*2
    # DWORD alignment of optional trailing EH/UH or chain records.
    trailer=(base_size+3)&~3
    _check(trailer<=len(raw),"truncated UNWIND_CODE slot array")

    operations=[]
    n=0
    static_stack_bytes=0
    last_code_offset=256
    while n<slots:
        at=4+n*2
        code_offset=raw[at]
        packed=raw[at+1]
        opcode=packed&0xf
        opinfo=packed>>4
        _check(code_offset<=prolog,"unwind operation offset beyond prologue")
        _check(code_offset<=last_code_offset,
               "unwind codes not sorted in descending prologue order")
        last_code_offset=code_offset
        _check(opcode in OP_NAMES,
               "unrecognized or version-2 Win64 UWOP code")
        extra_slots=0
        save_offset=None
        stack_delta=0
        if opcode==0:
            _check(opinfo!=4,
                   "cannot restore RSP with UWOP_PUSH_NONVOL")
            stack_delta=8
        elif opcode==1:
            _check(opinfo in (0,1),"invalid UWOP_ALLOC_LARGE opinfo")
            extra_slots=1 if opinfo==0 else 2
            _check(n+extra_slots<slots,"truncated UWOP_ALLOC_LARGE extra operands")
            if opinfo==0:
                stack_delta=_u16(raw,at+2)*8
            else:
                stack_delta=_u32(raw,at+2)
            _check(stack_delta>0,"zero large stack allocation")
        elif opcode==2:
            stack_delta=opinfo*8+8
        elif opcode==3:
            _check(opinfo==0 and frame!=0,
                   "UWOP_SET_FPREG requires valid frame register")
        elif opcode==4:
            extra_slots=1
            _check(n+1<slots,"truncated UWOP_SAVE_NONVOL slot")
            save_offset=_u16(raw,at+2)*8
            _check(opinfo!=4,"cannot use RSP as SAVE_NONVOL register")
        elif opcode==5:
            extra_slots=2
            _check(n+2<slots,"truncated UWOP_SAVE_NONVOL_FAR slots")
            save_offset=_u32(raw,at+2)
            _check(opinfo!=4,"cannot use RSP as SAVE_NONVOL_FAR register")
        elif opcode==8:
            extra_slots=1
            _check(n+1<slots,"truncated UWOP_SAVE_XMM128 slot")
            save_offset=_u16(raw,at+2)*16
        elif opcode==9:
            extra_slots=2
            _check(n+2<slots,"truncated UWOP_SAVE_XMM128_FAR slots")
            save_offset=_u32(raw,at+2)
        elif opcode==10:
            _check(opinfo in (0,1),"invalid UWOP_PUSH_MACHFRAME opinfo")
            stack_delta=40 if opinfo==0 else 48
        static_stack_bytes+=stack_delta
        operations.append(UnwindEntry(
            OP_NAMES[opcode],code_offset,opinfo,1+extra_slots,
            stack_delta,save_offset))
        n+=1+extra_slots
    _check(n==slots,"Win64 UNWIND_CODE extra-slot overrun")

    handler=None
    chained=None
    end=trailer
    if flags&FLAG_CHAININFO:
        _check(trailer+12<=len(raw),"truncated chained Win64 RUNTIME_FUNCTION")
        chained=struct.unpack_from("<III",raw,trailer)
        _check(chained[0]>0 and chained[1]>chained[0] and chained[2]>0,
               "invalid chained unwind RUNTIME_FUNCTION RVA bounds")
        end+=12
    elif flags&(FLAG_EHANDLER|FLAG_UHANDLER):
        handler=_u32(raw,trailer)
        _check(handler>0,"zero Win64 unwind exception handler RVA")
        end+=4
    return UnwindRecord(
        version=version,flags=flags,prologue_bytes=prolog,
        frame_register=REG_NAMES[frame] if frame else None,
        frame_offset_scaled16=frame_offset*16,
        raw_code_slots=slots,
        unwind_operations=tuple(operations),handler_rva=handler,
        chained_runtime_function=chained,record_bytes_consumed=end,
        stack_bytes_deallocated_by_unwind=static_stack_bytes,
    )
