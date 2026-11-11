#!/usr/bin/env python3
"""FH5 M75: bounded, privacy-safe byte distribution triage on M74-verified windows.
No authenticated ForzaTech format, geometry decoding, or pointer claim.
"""
import collections
import json
import math
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

HOME=Path.home()
PRIOR=HOME/'fh5_auto'/'M74'
OUT=Path('/sdcard/Download/FH5_M75')
WIDTH=96

def features(data):
    if not data:
        return dict(entropy=0.0,zero=0.0,unique=0,repeat=0.0,header=False)
    counts=collections.Counter(data)
    n=len(data)
    entropy=-sum((v/n)*math.log2(v/n) for v in counts.values())
    words=[data[i:i+4] for i in range(0,n-3,4)]
    z=(len(data)>=2 and (data[0]&15)==8 and (data[0]>>4)<=7
       and ((data[0]<<8)|data[1])%31==0)
    signatures=(b'\x1f\x8b',b'\xfd7zXZ\x00',b'\x28\xb5\x2f\xfd',b'\x04\x22\x4d\x18')
    return dict(entropy=round(entropy,5),zero=round(counts[0]/n,5),
        unique=len(counts),repeat=round(1-len(set(words))/len(words),5) if words else 0,
        header=bool(z or any(data.startswith(s) for s in signatures)))

def aggregate(items):
    if not items:
        return dict(windows=0,entropy_mean=None,zero_mean=None,unique_mean=None,
                    repeat_mean=None,header_like=0,high_entropy=0,low_entropy=0)
    n=len(items)
    avg=lambda k:round(sum(x[k] for x in items)/n,5)
    return dict(windows=n,entropy_mean=avg('entropy'),zero_mean=avg('zero'),
        unique_mean=avg('unique'),repeat_mean=avg('repeat'),
        header_like=sum(x['header'] for x in items),
        high_entropy=sum(x['entropy']>=6 for x in items),
        low_entropy=sum(x['entropy']<=2 for x in items))

class Checks(unittest.TestCase):
    def test_empty(self):self.assertEqual(features(b'')['unique'],0)
    def test_zero_entropy(self):self.assertEqual(features(bytes(96))['entropy'],0)
    def test_binary_entropy(self):self.assertAlmostEqual(features(b'\x00\x01'*48)['entropy'],1)
    def test_repeated(self):self.assertGreater(features(b'ABCD'*24)['repeat'],0.9)
    def test_unrepeated(self):self.assertEqual(features(bytes(range(96)))['repeat'],0)
    def test_zlib_header(self):self.assertTrue(features(b'\x78\x9c'+bytes(94))['header'])
    def test_gzip_header(self):self.assertTrue(features(b'\x1f\x8b'+bytes(94))['header'])
    def test_xz_header(self):self.assertTrue(features(b'\xfd7zXZ\x00'+bytes(90))['header'])
    def test_zstd_header(self):self.assertTrue(features(b'\x28\xb5\x2f\xfd'+bytes(92))['header'])
    def test_lz4_header(self):self.assertTrue(features(b'\x04\x22\x4d\x18'+bytes(92))['header'])
    def test_normal_bytes(self):self.assertFalse(features(b'abcdef'*16)['header'])
    def test_no_windows(self):self.assertEqual(aggregate([])['windows'],0)
    def test_zero_rate(self):self.assertEqual(features(bytes(96))['zero'],1)
    def test_no_identity(self):self.assertNotIn('outer_path',json.dumps(aggregate([features(bytes(96))])))
    def test_no_pointer(self):self.assertNotIn('pointer',json.dumps(features(bytes(96))))

def regressions():
    results={}
    for stage in range(61,75):
        script=PRIOR/f'test_m{stage}.py'
        if not script.is_file():
            results[f'M{stage}']='MISSING'
            continue
        try:
            p=subprocess.run([sys.executable,script.name],cwd=PRIOR,
                             text=True,capture_output=True,timeout=120)
            (OUT/f'M75_M{stage}_REGRESSION.txt').write_text(
                 p.stdout+'\n'+p.stderr,encoding='utf8')
            results[f'M{stage}']='PASS' if p.returncode==0 else 'FAIL'
        except Exception:
            results[f'M{stage}']='ERROR'
    (OUT/'M75_REGRESSION_SUMMARY.json').write_text(
        json.dumps(results,indent=2)+'\n',encoding='utf8')
    return all(v=='PASS' for v in results.values()),results

def inputs():
    names={62:'PRIVATE_NESTED_ASSET_INDEX.json',
           67:'PRIVATE_CONTAINER_HEADERS_V0.json',
           68:'PRIVATE_BODY_BOUNDARIES_V0.json',
           69:'PRIVATE_BODY_HOLDOUT_V0.json',
           70:'PRIVATE_MODEL_TARGET_DIAGNOSTICS.json',
           71:'PRIVATE_MODEL_REGION_PROFILES.json',
           72:'PRIVATE_FRESH_MODELBIN_HOLDOUT.json',
           73:'PRIVATE_MODEL_TARGET_TOPOLOGY.json'}
    return [HOME/f'.fh5_m{k}'/v for k,v in names.items()]

def scan():
    if not (PRIOR/'m74_model_region_layout_triage.py').is_file():
        return dict(stage='M75',status='M75_REQUIRES_M74_LOCAL_PACKAGE')
    sys.path.insert(0,str(PRIOR))
    import m74_model_region_layout_triage as m74
    cand=[];ctrl=[];nfiles=0
    prior_probe=m74.probe
    def probe(data,slots):
        nonlocal nfiles
        item=prior_probe(data,slots)
        nfiles+=1
        for kind,sink in (('candidate',cand),('control',ctrl)):
            for offset,_ in item[kind]:
                if 0<=offset and offset+WIDTH<=len(data):
                    sink.append(features(data[offset:offset+WIDTH]))
        return item
    m74.probe=probe
    try:
        private=HOME/'.fh5_m75'/'VERIFIED_M74_RECOMPUTE_PRIVATE.json'
        m74_report=m74.run(*inputs(),private)
    finally:
        m74.probe=prior_probe
    c=aggregate(cand);k=aggregate(ctrl)
    verified=(m74_report.get('status')=='M74_REGION_LAYOUT_TRIAGE_COMPLETE_NO_MESH_CLAIM'
       and nfiles==8 and c['windows']==m74_report.get('distinct_candidate_windows')
       and k['windows']==m74_report.get('distinct_control_windows'))
    delta=(round(c['entropy_mean']-k['entropy_mean'],5)
            if c['windows']>=8 and k['windows']>=8 else None)
    return dict(stage='M75',
        status='M75_WINDOW_DISTRIBUTION_COMPLETE_NO_FORMAT_CLAIM' if verified else 'M75_PARTIAL_OR_UNVERIFIED',
        read_only=True,same_m72_m73_members_reverified=nfiles,
        independent_holdout=False,original_forza_asset_authenticated=False,
        numeric_target_is_pointer=False,compression_confirmed=False,
        forza_format_decoded=False,geometry_decoded=False,forza_playable=False,
        comparison=dict(candidate=c,control=k,entropy_delta=delta,
            descriptive_separation_gate=delta is not None and abs(delta)>=1.2),
        m74_full_revalidation_passed=m74_report.get('status')=='M74_REGION_LAYOUT_TRIAGE_COMPLETE_NO_MESH_CLAIM',
        interpretation='Byte distribution and possible header-like prefixes are descriptive only, never a mesh or compression decoder.',
        next_gate='Authenticate an original asset and a versioned container field or validated decompressed body before mesh parsing.',
        error_counts=m74_report.get('error_counts',{}))

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    import io
    stream=io.StringIO()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Checks)
    passed=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite).wasSuccessful()
    (OUT/'M75_LOCAL_TESTS.txt').write_text(stream.getvalue(),encoding='utf8')
    if not passed:
        report=dict(stage='M75',status='M75_TEST_FAILURE')
    else:
        try:
            good,_=regressions()
            report=scan() if good else dict(stage='M75',status='M75_REGRESSION_FAILURE')
        except Exception as ex:
            report=dict(stage='M75',status='M75_EXCEPTION',exception_type=type(ex).__name__)
    (OUT/'M75_WINDOW_REPORT.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    (OUT/'M75_SCAN_LOG.txt').write_text(report['status']+'\n',encoding='utf8')
    dest=OUT.parent/'FH5_M75_REPORTS.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED) as z:
        for path in sorted(OUT.glob('M75_*')):
            if path.is_file() and path.suffix in ('.txt','.json'):
                z.write(path,'FH5_M75/'+path.name)
    print('[M75]',report['status'])
    print('[M75] Report:',dest)
    return 0 if report['status']=='M75_WINDOW_DISTRIBUTION_COMPLETE_NO_FORMAT_CLAIM' else 17

if __name__=='__main__':
    raise SystemExit(main())
