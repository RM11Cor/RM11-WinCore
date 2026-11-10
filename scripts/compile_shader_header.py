#!/usr/bin/env python3
from pathlib import Path
from struct import unpack
import sys
target = Path(sys.argv[1])
base = Path(sys.argv[2])
words = {}
for stage in ['vert', 'frag']:
    content = (base / f'fh5_preview.{stage}.spv').read_bytes()
    assert len(content) % 4 == 0 and content[:4] == b'\x03\x02\x23\x07', f'invalid SPIR-V {stage}'
    words[stage] = unpack('<'+'I'*(len(content)//4), content)
code = ['#pragma once', '#include <cstdint>']
for stage, data in words.items():
    code += [f'static const uint32_t fh5_{stage}_spv[] = {{', ',\n'.join(', '.join(f'0x{w:08x}u' for w in data[i:i+8]) for i in range(0,len(data),8)), '};']
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text('\n'.join(code)+'\n')
print('Compiled header',target, 'words', {k:len(v) for k,v in words.items()})
