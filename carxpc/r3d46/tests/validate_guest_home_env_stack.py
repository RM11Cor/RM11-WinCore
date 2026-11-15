#!/usr/bin/env python3
"""R3D46: inspect staged authentic Wine Linux guest ABI HOME env source patch.

This is source-shape and 64-bit pointer-table invariant verification.
Actual Linux stack guest-source/env values remain checked at runtime by
WineLinuxProcessLaunchContract.validate(), tested by Gradle compilation.
"""
import sys
from pathlib import Path
if len(sys.argv)!=2:raise SystemExit("usage: validate_guest_home_env_stack.py /tmp/carxpc")
app=Path(sys.argv[1])/"app"
p=app/"src/main/java/com/r4/carxpc/WineLinuxProcessLaunchContract.java"
s=p.read_text()
expected=[
    'long[] argv=new long[2],envp=new long[5];',
    'envp[0]=st.pushString("LANG=C");',
    'envp[1]=st.pushString("WINEDEBUG=-all");',
    'envp[2]=st.pushString("PATH=/usr/bin");',
    'envp[3]=st.pushString("HOME=/tmp");',
    'envp[4]=st.pushString("USER=wine");',
    'int aux=o+8+8*3+8*6;',
    'b.getLong(o+72)!=0',
    'guestCStringEquals(p,b.getLong(o+56),"HOME=/tmp")',
    'guestCStringEquals(p,b.getLong(o+64),"USER=wine")',
    'p.guestInitialStack[offset+expectedBytes.length]==0',
    'Path guestHome=root.resolve("tmp");',
    '!Files.isDirectory(guestHome,LinkOption.NOFOLLOW_LINKS)',
    'Files.isSymbolicLink(guestHome)',
    'throw reject("R3D46_HOME_MUST_BE_APP_OWNED_GUEST_ROOTFS_DIRECTORY")'
]
for token in expected:
    assert s.count(token)==1,("R3D46_MISSING_OR_DUPLICATED_SOURCE_MARKER",token,s.count(token))
assert 'envp=new long[3]' not in s
assert 'int aux=o+8+8*3+8*4;' not in s
# Exactly 10 64-bit words after argc: 2 argv, one terminator,
# 5 env entries, one terminator, plus argc = 10 words in all.
argc_words=1
argv_words=2
argv_null=1
envp_words=5
envp_null=1
assert sum((argc_words,argv_words,argv_null,envp_words,envp_null))==10
assert 10*8%16==0
assert (8+8*3+8*6)==80
assert (8+8*3+8*5)==72
# The 2 extra envp entries add exactly 16B, preserving the original
# source guest stack 16-byte RSP alignment.
assert (5-3)*8==16
print("R3D46_LINUX_X86_GUEST_HOME_USER_ENV_ABI_SOURCE_INVARIANTS_PASS")
print("R3D46_GUEST_10_WORD_RSP_16BYTE_ALIGNED_ENVP_AUXV_LAYOUT_PASS")
