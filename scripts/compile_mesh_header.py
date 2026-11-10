#!/usr/bin/env python3
from pathlib import Path
from struct import unpack
import sys
out=Path(sys.argv[1])
src=Path(sys.argv[2])
lines=['#pragma once','#include <cstdint>']
for ext in ('vert','frag'):
    buf=(src/f'fh5_mesh.{ext}.spv').read_bytes()
    assert len(buf)%4==0 and buf[:4]==b'\x03\x02\x23\x07', 'Bad SPIR-V'
    words=unpack('<'+'I'*(len(buf)//4),buf)
    lines += [f'static const uint32_t fh5_mesh_{ext}_spv[] = {{']
    lines += [', '.join(f'0x{w:08x}u' for w in words[i:i+8])+',' for i in range(0,len(words),8)]
    lines += ['};']
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text('\n'.join(lines)+'\n')
print('M22 generated shader header',out)
