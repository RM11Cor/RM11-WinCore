#!/usr/bin/env python3
"""Build reproducible SPIR-V C arrays from three tracked GLSL sources.
The script runs on Linux GitHub Actions before Gradle/NDK builds.
"""
from pathlib import Path
import shutil
import subprocess

base = Path(__file__).resolve().parents[1]
compiler = shutil.which('glslangValidator')
if not compiler:
    raise SystemExit('Missing glslangValidator: install glslang-tools in CI')
outputs = []
for name, stage in [('triangle.vert','vert'), ('triangle.frag','frag'), ('check.comp','comp')]:
    source = base / 'shaders' / name
    result = base / 'shaders' / (name + '.spv')
    subprocess.run([compiler, '-V', '--target-env', 'vulkan1.0', '-S', stage,
                    '-o', str(result), str(source)], check=True)
    data = result.read_bytes()
    if len(data) < 32 or len(data)%4 != 0 or data[:4] != bytes([3,2,35,7]):
        raise SystemExit(f'Invalid compiled SPIR-V: {result}')
    symbol = {'triangle.vert':'rm11_vert_spv','triangle.frag':'rm11_frag_spv','check.comp':'rm11_comp_spv'}[name]
    words = [int.from_bytes(data[i:i+4], 'little') for i in range(0,len(data),4)]
    contents = ',\n'.join('    ' + ', '.join('0x%08xu'%w for w in words[j:j+8]) for j in range(0,len(words),8))
    outputs.append('static const uint32_t '+symbol+'[] = {\n'+contents+'\n};\n')
header = base / 'app/src/main/cpp/rm11_shaders_generated.h'
header.write_text('#pragma once\n#include <stdint.h>\n/* Auto-generated from tracked shaders via tools/compile_shaders.py */\n' + '\n'.join(outputs), encoding='utf-8')
print('RM11 SPIR-V generated: '+str(header)+' ('+str(header.stat().st_size)+' bytes)')
