# CarX PC Runtime R3-C6 — خريطة libc الأصلية للقراءة فقط

## R3-C5 الموثق من جهاز المستخدم
- جهاز `NX809J`، Android 16، تقرير `CarX_PC_R3C_Diagnostics (5).json`.
- نجحت مراحل `read(832)` و`pread64(784, offset=64)` و`fstat(5)` في عملية FEX واحدة.
- كتب الضيف بنية `Linux x86_64 stat144` لملف `libc.so.6` المصدر بحجم `2118168`.
- نفّذ `pread64` آخر بعد `fstat`، ثم حاول `mmap(9)` بالمعاملات الأصلية:
  `addr=0`, `length=0x211d90`, `prot=1`, `flags=0x802`, `fd=100`, `offset=0`.
- توقف الاختبار السابق عند `exit_code=117` لأن `mmap` لم يكن مفعلاً في R3-C5.
- `success=true` يثبت **البوابة المحدودة السابقة فقط**؛ لا يثبت إطلاق `glibc`، Wine، DXVK أو CarX.

## تنفيذ R3-C6
- إعادة استخدام دالة KERNIX المثبتة `DispatchOriginalLdsoPinnedLibcLargeReadonlyMmap` مع الماكرو:
  `KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY`.
- التحقق من ترتيب المصدر: فتح `libc` مرة واحدة، قراءة `832`، قراءتان `pread64`، ونجاح `fstat`، وعدم أي `mmap` سابق للملف.
- تخطيط `libc` من نسخة المصدر ذات SHA المثبتة إلى صفحات ضيف مملوكة وخاصة، وصلاحيات القراءة فقط `r--p`، مع حماية `---p` لما بعد نهاية الملف.
- منع `W+X` والتعديل المباشر عبر `MAP_FIXED` على ذاكرة host، وعدم تمرير `fd=100` أو مسار ELF إلى host.
- العلامة المطلوبة للنجاح المحدود:
  `KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_MMAP9_LARGE_PRIVATE_RO_SOURCE_2118168_REQUEST_0x211d90_FD100_OFFSET0_WX_SAFE_EOF_GUARD_PASS`.
- **أمان المرحلة:** ماكرو R3-C6 يرفض خريطة الملف الثانية المتطلبة صلاحيات تنفيذ (RX) مع علامة `KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=1` و`exit_code=142` بشكل متعمد. هذا حاجز محدد لحماية الذاكرة، لا انهيار محرك FEX؛ المرور إليه بعد نجاح أول خريطة يعني اكتمال بوابة R3-C6 فقط. في المرحلة اللاحقة نفعل مسار RX المتحقق من `PT_LOAD`، لا نمنح التنفيذ لجميع صفحات libc.

## شروط الاعتماد
- GitHub Android/Bionic ARM64: نفس `libFEXCore.so`، وإصلاح SIGBUS المتحقق، ونسخة المصدر المصدرية بالـSHA، وتطابق مكتبات ELF مع APK النهائي وتوقيع ثابت.
- Android `com.r4.carxpc`, `versionCode=13`؛ تحديث فوق R3-C5 بدون حذف.
- على الهاتف: العلامة الأولى للربط `mmap` تظهر بعد `fstat`، وحاجز محاولة الربط الثانية يظهر بعدها، ورمز الخروج `142` مع `child_finished_within_45s=true`.
- التقرير يميّز `original_libc_mmap9_large_private_ro_verified` و`original_libc_next_mapping_intentionally_guarded`، ولا يدعي `full_dynamic_interpreter_complete=true`.

**الحالة:** المصدر جاهز للفحص والبناء؛ تشغيل R3-C6 على الهاتف لم يحدث بعد.
