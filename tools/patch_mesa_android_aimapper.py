#!/usr/bin/env python3
"""Fail-closed source-pinned IMapper5 prototype; no device or APK proof."""
import argparse
import hashlib
import json
from pathlib import Path

UPSTREAM_COMMIT = "c71f600a2977a141f21a922c9ed2e14fb09b13d3"
CHANGES = {
    "src/util/u_gralloc/meson.build": (
        "  'u_gralloc_qcom.c',\n)",
        "  'u_gralloc_qcom.c',\n  'u_gralloc_aimapper.c',\n)",
    ),
    "src/util/u_gralloc/u_gralloc.h": (
        "   U_GRALLOC_TYPE_GRALLOC4,\n   U_GRALLOC_TYPE_CROS,",
        "   U_GRALLOC_TYPE_GRALLOC4,\n   U_GRALLOC_TYPE_AIMAPPER,\n   U_GRALLOC_TYPE_CROS,",
    ),
    "src/util/u_gralloc/u_gralloc_internal.h": (
        "extern struct u_gralloc *u_gralloc_qcom_create(void);",
        "extern struct u_gralloc *u_gralloc_aimapper_create(void);\n"
        "extern struct u_gralloc *u_gralloc_qcom_create(void);",
    ),
    "src/util/u_gralloc/u_gralloc.c": (
        "   {.type = U_GRALLOC_TYPE_LIBDRM, .create = u_gralloc_libdrm_create},",
        "   {.type = U_GRALLOC_TYPE_AIMAPPER, .create = u_gralloc_aimapper_create},\n"
        "   {.type = U_GRALLOC_TYPE_LIBDRM, .create = u_gralloc_libdrm_create},",
    ),
}


def adapt_metadata_for_mesa_26_2(code):
    """Mesa 26.2.0 predates basic_info.layer_count and alloc_size.

    Remove only this verified downstream later-Mesa block. We do not
    simulate multilayer layout support or silently modify unrelated code.
    """
    start = b"   /* vk_gralloc_to_drm_explicit_layout()"
    end = b"   ret = 0;"
    have_layer = b"out->layer_count" in code
    have_size = b"out->alloc_size" in code
    if not have_layer and not have_size:
        return code, False
    if not (have_layer and have_size and code.count(start) == 1):
        raise ValueError("RM11_AIMAPPER_LATER_MESA_FIELDS_DRIFT")
    a = code.index(start)
    b = code.find(end, a)
    if b < a or b - a > 2000:
        raise ValueError("RM11_AIMAPPER_COMPAT_SECTION_MISSING")
    section = code[a:b]
    if (section.count(b"out->layer_count") != 1 or
            section.count(b"out->alloc_size") != 1 or
            b"SMT_LAYER_COUNT" not in section or
            b"SMT_ALLOCATION_SIZE" not in section):
        raise ValueError("RM11_AIMAPPER_UNEXPECTED_METADATA_LOGIC")
    note = (b"   /* RM11 Mesa 26.2.0 has no allocation size/layer-count fields. "
            b"Do not claim multi-layer metadata support. */\n")
    return code[:a] + note + code[b:], True


def patch_mesa(root, implementation):
    root = Path(root)
    impl = Path(implementation)
    if impl.is_symlink() or not impl.is_file():
        raise ValueError("RM11_AIMAPPER_SOURCE_MISSING_OR_SYMLINK")
    code = impl.read_bytes()
    if not 10000 <= len(code) <= 65536:
        raise ValueError("RM11_AIMAPPER_SOURCE_SIZE_UNEXPECTED")
    if b"SPDX-License-Identifier: MIT" not in code[:1024]:
        raise ValueError("RM11_AIMAPPER_SOURCE_LICENSE_NOT_VERIFIED")
    if b"u_gralloc_aimapper_create(void)" not in code:
        raise ValueError("RM11_AIMAPPER_CREATE_SYMBOL_MISSING")
    original_digest = hashlib.sha256(code).hexdigest()
    code, compat = adapt_metadata_for_mesa_26_2(code)
    changes = {}
    for name, (old, new) in CHANGES.items():
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("RM11_AIMAPPER_MESA_FILE_MISSING:" + name)
        original = path.read_text(encoding="utf-8")
        if original.count(new) == 1:
            updated = original
        elif original.count(old) == 1:
            updated = original.replace(old, new, 1)
        else:
            raise ValueError("RM11_AIMAPPER_MESA_SOURCE_DRIFT:" + name)
        if updated.count(new) != 1:
            raise ValueError("RM11_AIMAPPER_AMBIGUOUS_ANCHOR:" + name)
        changes[path] = updated
    dest = root / "src/util/u_gralloc/u_gralloc_aimapper.c"
    if dest.is_symlink() or (dest.exists() and dest.read_bytes() != code):
        raise ValueError("RM11_AIMAPPER_PREEXISTING_CONFLICT")
    # Atomic relative to source checking: all four changes are validated first.
    for path, contents in changes.items():
        if path.read_text(encoding="utf-8") != contents:
            path.write_text(contents, encoding="utf-8")
    if not dest.exists():
        dest.write_bytes(code)
    return {
        "upstream_commit": UPSTREAM_COMMIT,
        "source_sha256": hashlib.sha256(code).hexdigest(),
        "original_source_sha256": original_digest,
        "mesa_26_2_single_layer_compat_applied": compat,
        "source_spdx": "MIT",
        "mesa_sources_patched": len(changes),
        "static_integration_candidate": True,
        "android_app_mapper_load_verified": False,
        "actual_guest_android_frame_verified": False,
        "safe_to_publish_apk": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", required=True)
    p.add_argument("--implementation", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    info = patch_mesa(args.source, args.implementation)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(info, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("RM11_AIMAPPER_SOURCE_INTEGRATION_STATIC_ONLY_NOT_DEVICE_PROOF")


if __name__ == "__main__":
    main()
