#!/usr/bin/env python3
"""Pin-aware RM11 cursor geometry patch to upstream Termux:X11 Lorie.

Apply solely to the renderer drawing the sprite. Preserve X11 pointer
coordinates, events, input geometry and the underlying cursor image.
"""
from pathlib import Path
import sys

if len(sys.argv)!=2:
    raise SystemExit("usage: scale_cursor_lorie_v420.py <renderer.cpp>")
file=Path(sys.argv[1])
data=file.read_text()
old='''    x = 2.f * (cursorX - sourceLeft - (float) state->cursor.xhot) / displayWidth - 1.f;
    y = 2.f * (cursorY - sourceTop - (float) state->cursor.yhot) / displayHeight - 1.f;
    w = 2.f * (float) state->cursor.width / displayWidth;
    h = 2.f * (float) state->cursor.height / displayHeight;'''
new='''    // RM11 v420: REDMAGIC 2688x1216 cursor looked tiny.
    // Visual sprite only, 1.7x, preserving exact hotspot and input position.
    constexpr float RM11_CURSOR_SPRITE_SCALE = 1.7f;
    x = 2.f * (cursorX - sourceLeft - (float) state->cursor.xhot * RM11_CURSOR_SPRITE_SCALE) / displayWidth - 1.f;
    y = 2.f * (cursorY - sourceTop - (float) state->cursor.yhot * RM11_CURSOR_SPRITE_SCALE) / displayHeight - 1.f;
    w = 2.f * (float) state->cursor.width * RM11_CURSOR_SPRITE_SCALE / displayWidth;
    h = 2.f * (float) state->cursor.height * RM11_CURSOR_SPRITE_SCALE / displayHeight;'''
if data.count(old)!=1:
    raise SystemExit("Upstream pinned renderer sprite geometry changed; refusing unverified patch")
file.write_text(data.replace(old,new))
assert file.read_text().count('RM11_CURSOR_SPRITE_SCALE')==5
print('RM11_V420_NATIVE_LORIE_MOUSE_SPRITE_SCALE_170_PERCENT')
