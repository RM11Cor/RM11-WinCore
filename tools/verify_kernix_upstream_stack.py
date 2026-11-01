#!/usr/bin/env python3
"""Fail-closed source/ABI inventory for KERNIX upstream Android engine baseline.

SOURCE_PRESENT is not an APK build or on-device runtime proof. No network,
subprocess, device probing or binary copying occurs here.
"""
import argparse
import hashlib
import json
from pathlib import Path

def audit(lock_path: Path, source: Path) -> dict:
    cfg=json.loads(lock_path.read_text(encoding="utf-8"))
    assert cfg.get("schema")=="kernix.backend-source-lock.v1"
    assert cfg.get("source_sha")=="146158413f25e28f9ad04d921d0b7b806f86cc53"
    assert cfg.get("source_license")=="GPL-3.0"
    assert cfg.get("packaged_in_kernix_apk") is False
    assert cfg.get("runtime_qualified_on_redmagic_11_pro") is False
    assert cfg.get("existing_kernix_x11_quarantine_must_remain") is True
    if not source.is_dir() or source.is_symlink():
        raise ValueError("UPSTREAM_SOURCE_MISSING_OR_SYMLINK")
    missing=[]
    paths=[]
    for group,entries in cfg["components"].items():
        if not isinstance(entries,list) or not entries:
            raise ValueError("EMPTY_COMPONENT_GROUP_"+group)
        for rel in entries:
            p=Path(rel)
            if p.is_absolute() or ".." in p.parts:
                raise ValueError("UNSAFE_SOURCE_PATH")
            target=source/p
            if target.is_symlink() or not target.is_file() or target.stat().st_size==0:
                missing.append(group+":"+rel)
            else:
                paths.append({"group":group,"path":rel,"sha256":hashlib.sha256(target.read_bytes()).hexdigest()})
    license_body=(source/"LICENSE").read_text(encoding="utf-8")
    if "GNU GENERAL PUBLIC LICENSE" not in license_body or "Version 3" not in license_body:
        raise ValueError("UPSTREAM_LICENSE_MISMATCH")
    if missing:
        raise ValueError("MISSING_SOURCE_COMPONENTS:"+",".join(missing))
    return {"schema":"kernix.backend-source-audit.v1",
            "commit":cfg["source_sha"],
            "source_present":True,
            "built_in_kernix_apk":False,
            "device_qualified":False,
            "component_groups":len(cfg["components"]),
            "audited_source_files":len(paths),
            "files":paths}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--lock",type=Path,default=Path("engines/backend-source-lock.json"))
    parser.add_argument("--source",type=Path,default=Path("engines/bannerlator_3_1_7"))
    parser.add_argument("--output",type=Path,default=Path("engine-source-audit.json"))
    args=parser.parse_args()
    report=audit(args.lock,args.source)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("KERNIX_UPSTREAM_SOURCE_COMPONENT_AUDIT_PASS",report["audited_source_files"])

if __name__=="__main__":
    main()
