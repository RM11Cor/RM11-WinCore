#!/usr/bin/env python3
"""Developer-only packaging tool; no binary downloaded or distributed by this source tree.

Example (AFTER acquiring suitable, legally distributable runtime builds):
  python3 tools/pack_engine_bundle.py --output rm11-engine.zip \
      --component box64=/absolute/path/to/box64-binary=MIT

The generated archive can be inspected (V0.4) or staged as inert data (V0.9).
It is NEVER executed by RM11 WinCore. License IDs are metadata, not a license check.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

MAX_SINGLE = 512 * 1024**2
MAX_TOTAL = 1536 * 1024**2


def hash_file(file: Path):
    digest = hashlib.sha256()
    count = 0
    with file.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
            count += len(block)
            if count > MAX_SINGLE:
                raise ValueError(f'Component exceeds 512 MiB: {file}')
    if not count:
        raise ValueError(f'Empty component: {file}')
    return digest.hexdigest(), count


def main():
    parser = argparse.ArgumentParser(description='Create an AUDIT-ONLY RM11 component ZIP')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--component', action='append', required=True,
                        help='id=/absolute/file/path=SPDX-license-id')
    args = parser.parse_args()
    entries = []
    paths = {}
    total = 0
    for descriptor in args.component:
        try:
            ident, path, license_id = descriptor.split('=', 2)
        except ValueError as error:
            raise SystemExit('Expected --component id=/path/file=SPDX-ID') from error
        if not ident.replace('-', '').replace('_', '').replace('.', '').isalnum() or not license_id.strip():
            raise ValueError('Invalid component id or license')
        if ident in paths or not Path(path).is_file():
            raise ValueError(f'Missing or duplicate component: {ident}')
        digest, size = hash_file(Path(path))
        total += size
        if total > MAX_TOTAL:
            raise ValueError('Bundle exceeds 1.5 GiB limit')
        entries.append(dict(id=ident, path=f'components/{ident}.blob',
                            sha256=digest, bytes=size, license=license_id))
        paths[ident] = Path(path)
    if len(entries) > 32:
        raise ValueError('Maximum 32 components')
    manifest = dict(schema=1, targetModel='NX809J', abi='arm64-v8a', minApi=36,
                    components=entries)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Manifest MUST be the first ZIP entry for the streaming Android verifier.
    with zipfile.ZipFile(args.output, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as out:
        out.writestr('rm11-engine.json', json.dumps(manifest, ensure_ascii=False,
                                                 separators=(',', ':')).encode('utf-8'))
        for item in entries:
            with paths[item['id']].open('rb') as source, out.open(item['path'], 'w') as dest:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    dest.write(block)
    print(f'Wrote {args.output} with {len(entries)} components for verification only')


if __name__ == '__main__':
    main()
