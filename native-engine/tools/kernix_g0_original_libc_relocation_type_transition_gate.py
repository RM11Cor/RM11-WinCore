#!/usr/bin/env python3
"""Classify all 147 SHA-pinned original GNU libc RELA/JMPREL source records.

Source-only ELF inspection: records #86-101 are JUMP_SLOT (16 total), #102-146
are original IRELATIVE (45 total), and one further IRELATIVE is in DT_RELA.
This NEVER proves an IFUNC resolver executed or that any Android game works.
"""
from collections import Counter
from pathlib import Path
import hashlib
import json
import struct
import sys

LIBC_SHA = "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
LDSO_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
OUTPUT = "original-libc-147-rela-jmprel-typed-source-next-stage-plan.json"


def decode_original_libc(data: bytes):
    assert len(data) == 2118168 and hashlib.sha256(data).hexdigest() == LIBC_SHA
    assert data[:6] == b"\x7fELF\x02\x01"
    assert struct.unpack_from("<H", data, 18)[0] == 62
    ph_off = struct.unpack_from("<Q", data, 32)[0]
    ph_size, ph_count = struct.unpack_from("<HH", data, 54)
    assert ph_size == 56 and 0 < ph_count <= 128
    assert ph_off + ph_size * ph_count <= len(data)
    ph = [struct.unpack_from("<IIQQQQQQ", data, ph_off + i * ph_size)
          for i in range(ph_count)]
    load = [p for p in ph if p[0] == 1]
    dynamic = [p for p in ph if p[0] == 2]
    assert len(dynamic) == 1 and load
    def source_file_offset(virtual, width, *, rw_nx=False):
        matches = [p for p in load if p[3] <= virtual and
                   virtual + width <= p[3] + p[5] and
                   (not rw_nx or ((p[1] & 6) == 6 and (p[1] & 1) == 0))]
        assert len(matches) == 1, (virtual,width,rw_nx)
        offset=matches[0][2]+virtual-matches[0][3]
        assert 0 <= offset and offset+width <= len(data)
        return offset
    dyn=dynamic[0]
    assert dyn[2]+dyn[5] <= len(data)
    assert dyn[5] % 16 == 0
    tags={}
    for at in range(dyn[2],dyn[2]+dyn[5],16):
        t,v=struct.unpack_from("<qQ",data,at)
        if t == 0:break
        if t in (7,8,9,23,2,20):
            assert t not in tags
            tags[t]=v
    assert set(tags)=={7,8,9,23,2,20}
    assert tags[8]==86*24 and tags[2]==61*24
    assert tags[9]==24 and tags[20]==7
    records=[]
    for table,va,n in (("DT_RELA",tags[7],86),("DT_JMPREL",tags[23],61)):
        p=source_file_offset(va,n*24)
        for i in range(n):
            off,info,addend=struct.unpack_from("<QQq",data,p+24*i)
            typ=info & 0xffffffff
            sym=info >> 32
            assert off % 8 == 0
            src=source_file_offset(off,8,rw_nx=True)
            initial=struct.unpack_from("<Q",data,src)[0]
            records.append({
                "index":len(records), "table":table, "table_index":i,
                "r_type":typ, "r_sym":sym,
                "r_offset":hex(off),
                "source_guest_target":hex(0x804000000+off),
                "original_source_qword":hex(initial),
                "r_addend":addend,
            })
    assert len(records)==147
    assert len({r["r_offset"] for r in records})==147
    return records


def classify(records):
    assert [r["index"] for r in records] == list(range(147))
    rela,plt=records[:86],records[86:]
    assert all(r["table"]=="DT_RELA" for r in rela)
    assert all(r["table"]=="DT_JMPREL" for r in plt)
    counts=Counter(r["r_type"] for r in rela)
    plt_counts=Counter(r["r_type"] for r in plt)
    assert counts=={1:8,18:16,6:61,37:1},counts
    assert plt_counts=={7:16,37:45},plt_counts
    assert all(r["original_source_qword"]=="0x0" for r in rela)
    assert all(int(r["original_source_qword"],16)!=0 for r in plt)
    assert all(r["r_type"]==7 and r["r_sym"]>0 for r in plt[:16])
    assert all(r["r_type"]==37 and r["r_sym"]==0 for r in plt[16:])
    last=records[101]
    assert (last["r_type"],last["r_sym"],last["r_offset"],
            last["source_guest_target"],last["original_source_qword"]) == (
             7,19,"0x202d70","0x804202d70","0x283c0")
    assert [r["index"] for r in records[102:] if r["r_type"]!=37]==[]
    # A source-only predicate must reject missing, misclassified, duplicated,
    # changed or re-ordered original records. These are NOT native runtime tests.
    def valid(a):
        return (len(a)==147 and [r["index"] for r in a]==list(range(147))
                and all(r["r_type"]==7 for r in a[86:102])
                and all(r["r_type"]==37 for r in a[102:])
                and len({r["r_offset"] for r in a})==147
                and a[101]["source_guest_target"]=="0x804202d70")
    assert valid(records)
    assert not valid(records[:-1])
    assert not valid(records[::-1])
    assert not valid(records[:102]+[{**records[102],"r_type":7}]+records[103:])
    assert not valid(records[:101]+[{**records[101],"source_guest_target":"0x0"}]+records[102:])
    assert not valid(records[:105]+[{**records[105],"r_offset":records[104]["r_offset"]}]+records[106:])
    return {
        "schema":"kernix.g0.original-libc-147-source-relocation-type-transition.v1",
        "original_libc_sha256":LIBC_SHA,
        "original_gnu_ldso_sha256":LDSO_SHA,
        "original_total_RELA_and_JMPREL":147,
        "original_DT_RELA_count":86,
        "original_DT_RELA_type_counts":{"R_X86_64_64":8,"R_X86_64_TPOFF64":16,
                                        "R_X86_64_GLOB_DAT":61,"R_X86_64_IRELATIVE":1},
        "original_DT_JMPREL_count":61,
        "original_DT_JMPREL_type_counts":{"R_X86_64_JUMP_SLOT":16,"R_X86_64_IRELATIVE":45},
        "genuine_source_JUMP_SLOT_indices":list(range(86,102)),
        "last_unproven_source_JUMP_SLOT":{
            "index":101,
            "symbol":19,
            "guest_target":"0x804202d70",
            "original_qword":"0x283c0"},
        "original_source_JMPREL_IFUNC_indices":list(range(102,147)),
        "original_source_IRELATIVE_count":46,
        "original_other_RELA_count":85,
        "individually_real_hardware_attested_JUMP_SLOT_before_last":15,
        "last_JUMP_SLOT_live_FEX_hardware_writer_proven":False,
        "remaining_45_JMPREL_IFUNC_resolvers_proven":False,
        "one_DT_RELA_IFUNC_resolver_proven":False,
        "other_85_RELA_writer_semantics_proven":False,
        "full_original_libc_relocations_closed":False,
        "one_guest_all_relocations_closed":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
        "five_source_type_mutations_rejected":True,
    }


def main(dist:Path):
    src=dist/"original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"
    ldso=dist/"original-source-pinned-root/lib64/ld-linux-x86-64.so.2"
    assert src.is_file() and not src.is_symlink()
    assert ldso.is_file() and not ldso.is_symlink()
    original=ldso.read_bytes()
    assert len(original)==235408 and hashlib.sha256(original).hexdigest()==LDSO_SHA
    result=classify(decode_original_libc(src.read_bytes()))
    (dist/OUTPUT).write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_LIBC_16_JUMP_SLOT_46_IFUNC_85_OTHER_RELA_TYPED_SOURCE_PASS_NO_NEW_WRITER")


if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
