#!/usr/bin/env python3
"""Apply a fail-closed, minimally scoped WineServer queue guard to pinned Proton.

This does not edit installed Android binaries. Build and verify the patched
source with the matching Proton toolchain before making any APK runtime switch.
"""
import argparse
from pathlib import Path

UPSTREAM_COMMIT="2c0670d0a6b5a3d4d19510f22b01d3a66de40f91"
MATCH="DECL_HANDLER(set_queue_fd)\n{\n    struct msg_queue *queue = get_current_queue();\n    struct file *file;\n    int unix_fd;\n\n    if (queue->fd)  /* fd can only be set once */"
REPLACE="DECL_HANDLER(set_queue_fd)\n{\n    struct msg_queue *queue = get_current_queue();\n    struct file *file;\n    int unix_fd;\n\n    /* KERNIX 49146: keep the original error from create_msg_queue().\n     * On Android 16 the GUI startup can arrive here with no desktop queue;\n     * dereferencing queue->fd then SIGSEGVs the entire private WineServer.\n     * A null queue is an error, not a successful Windows GUI launch. */\n    if (!queue)\n    {\n        fprintf(stderr, \"KERNIX_P11_QUEUE_CREATE_FAILED_BEFORE_FD\\n\");\n        return;\n    }\n\n    if (queue->fd)  /* fd can only be set once */"
MARKER="KERNIX_P11_QUEUE_CREATE_FAILED_BEFORE_FD"
DESKTOP_MATCH="""        if (!(input->desktop = get_thread_desktop( thread, 0 /* FIXME: access rights */ )))
        {
            release_object( input );
            return NULL;
        }"""
DESKTOP_REPLACE="""        if (!(input->desktop = get_thread_desktop( thread, 0 /* FIXME: access rights */ )))
        {
            /* KERNIX 49146: identify the root of a NULL message queue.
             * This is diagnostic only; preserve the original server error. */
            fprintf(stderr, "KERNIX_P11_QUEUE_NO_THREAD_DESKTOP\\n");
            release_object( input );
            return NULL;
        }"""
DESKTOP_MARKER="KERNIX_P11_QUEUE_NO_THREAD_DESKTOP"

def patch_queue(text):
    if MARKER in text or DESKTOP_MARKER in text:
        if text.count(MARKER)!=1 or REPLACE not in text or \
                text.count(DESKTOP_MARKER)!=1 or DESKTOP_REPLACE not in text:
            raise ValueError("KERNIX_QUEUE_PATCH_PARTIAL_OR_TAMPERED")
        return text
    if text.count(MATCH)!=1 or text.count(DESKTOP_MATCH)!=1:
        raise ValueError("KERNIX_QUEUE_SOURCE_NOT_PINNED_OR_UNEXPECTED")
    patched=text.replace(MATCH,REPLACE).replace(DESKTOP_MATCH,DESKTOP_REPLACE)
    assert patched.count(MARKER)==1 and patched.count(DESKTOP_MARKER)==1
    return patched

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True,type=Path)
    p.add_argument("--in-place",action="store_true")
    p.add_argument("--output",type=Path)
    p.add_argument("--checkout-revision",required=True)
    a=p.parse_args()
    if a.checkout_revision!=UPSTREAM_COMMIT:
        raise SystemExit("KERNIX_QUEUE_PATCH_REJECTED_SOURCE_COMMIT")
    if (a.output is None)==(not a.in_place):
        raise SystemExit("Set exactly one of --in-place or --output")
    if a.source.is_symlink() or not a.source.is_file():
        raise SystemExit("KERNIX_QUEUE_UNSAFE_SOURCE")
    data=a.source.read_bytes()
    if len(data)<100000 or len(data)>300000:
        raise SystemExit("KERNIX_QUEUE_SOURCE_SIZE_UNEXPECTED")
    try: patched=patch_queue(data.decode("utf-8"))
    except (UnicodeError,ValueError) as e:raise SystemExit(str(e))
    output=a.source if a.in_place else a.output
    if output.is_symlink():raise SystemExit("KERNIX_QUEUE_OUTPUT_SYMLINK")
    output.write_text(patched,encoding="utf-8")
    print("KERNIX_PINNED_WINESERVER_QUEUE_GUARD_APPLIED",UPSTREAM_COMMIT)

if __name__=="__main__":
    main()
