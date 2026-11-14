#!/usr/bin/env python3
"""Promote CarX R3C21 signed v26 Android app to v27 with authentic hardlink
EACCES fallback and explicit audit counts. Rootfs source sha remains pinned.
"""
from pathlib import Path
import re,hashlib,sys
app=Path(sys.argv[1])
gradle=app/'app/build.gradle'
activity=app/'app/src/main/java/com/r4/carxpc/MainActivity.java'
installer=app/'app/src/main/java/com/r4/carxpc/GuestRootfsInstaller.java'
source=Path('carxpc/r3c18/android/GuestRootfsInstaller.java')
assert all(x.is_file() for x in [gradle,activity,installer,source])
assert hashlib.sha256(installer.read_bytes()).hexdigest()==hashlib.sha256(source.read_bytes()).hexdigest(), 'OLD_INSTALLER_BUNDLED'
assert 'catch(AccessDeniedException e)' in installer.read_text()
assert 'materializeVerifiedHardlinkCopy' in installer.read_text()
assert 'hardlinksMaterializedAsCopies' in installer.read_text()

s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+26\b','versionCode 27',s)
assert n==1,("R3C21_CODE26_NOT_PRESENT",n)
s,n=re.subn(r"versionName\s+'[^']+'",
  "versionName '0.27-r3c22-android-perl-hardlink-eacces-fallback'",s)
assert n==1
gradle.write_text(s)

s=activity.read_text()
old='.put("hardlinks",receipt.hardlinks)'
new=old+'\n             .put("hardlinks_materialized_as_copies",receipt.hardlinksMaterializedAsCopies)'
n=s.count(old)
assert n==2,("EXPECTED_SAF_AND_HTTPS_ORIGINAL_RECEIPT_CHAINS",n)
s=s.replace(old,new)
assert 'wine_guest_data_auto_provision' in s or 'provisioningResult' in s
activity.write_text(s)
assert s.count('hardlinks_materialized_as_copies')==2
assert 'CarXUnifiedBatch.run(getApplicationContext(),testSurface)' in s
assert 'beginUnifiedBatchWithOptionalProvision' in s
assert 'versionCode 27' in gradle.read_text()
print('CARX_R3C22_ORIGINAL_APK_V27_ANDROID_PERL_HARDLINK_EACCES_FALLBACK_APPLIED')
print('CARX_R3C22_SAF_AND_HTTPS_ROOTFS_RECEIPTS_BOTH_INCLUDE_REAL_COPY_COUNT')
