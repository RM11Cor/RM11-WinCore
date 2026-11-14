# CarX PC Runtime R3-C9 — خريطة بيانات libc الرابعة RW بأمان

## الإثبات المعتمد من R3-C8
- المصدر: `CarX_PC_R3C_Diagnostics (8).json`، جهاز `NX809J`، Android 16/SDK36، arm64-v8a.
- `original_libc_third_data_ro_ptload_verified=true` و`original_libc_third_data_ro_wx_safe_verified=true`.
- الخرائط السابقة في العملية نفسها: `0x804000000` للقراءة فقط، `0x804028000` للتنفيذ والقراءة `RX`، `0x8041b0000` للقراءة فقط `RO`.
- `exit_code=142` و`after_first=3` يمثلان حاجزاً مقصوداً قبل التنفيذ الجديد، وليس انهياراً عتادياً.
- طلب الضيف الرابع الصحيح:
  `mmap(9): addr=0x8041ff000; len=0x6000; prot=3(RW); flags=0x812; fd=100(virtual libc); offset=0x1fe000`.
  **ملاحظة:** `fd=64` باللوج مكتوب سداسياً `0x64` ويساوي `100` عشرياً.

## المسار الجديد
- استخدمنا مصدر KERNIX الأصلي `DispatchOriginalLdsoPinnedLibcOwnedWritablePTLoad` بتفعيل `KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY`؛ لا كتابة لمعالج تعويض جديد.
- يجب أن يتحقق المصدر من `PT_LOAD`، ومن انزياح `source offset=0x1fe000` إلى `virtual guest offset=0x1ff000`، وحجم `0x6000`.
- حقوق الذاكرة الفعلية بعد التعديل:
  - base: `r--p`؛
  - base + `0x28000`: `r-xp` (التنفيذ القديم محمي)؛
  - base + `0x1b0000`: `r--p`؛
  - base + `0x1ff000`: `rw-p`؛
  - ما بعد نهاية ELF: `---p`.
- ممنوع `W+X`، وممنوع استخدام `MAP_FIXED` الأصلي على عناوين Android أو تمرير `fd=100` الافتراضي إلى host.
- العلامة الإلزامية:
  `KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_FOURTH_FIXED_RW_MMAP_PTLOAD_OFFSET_SHIFT_SOURCE_0x1fe000_TO_VADDR_0x1ff000_LENGTH_0x6000_NO_NATIVE_FIXED_NO_WX_PASS base=8041ff000`.

## بوابة الإثبات الجديدة
- يثبت GitHub بناء ARM64/Bionic من نفس FEXCore المحدد بالبصمة، وحفظ جميع المكتبات بعد تغليف APK، وتوقيع نفس الحزمة `com.r4.carxpc` بإصدار `versionCode=16`.
- على الهاتف يجب أن يظهر نجاح الخريطة الرابعة بعد نجاح الخرائط الثلاث، ثم علامة `KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL` ويخرج الاختبار **117**، بحسب مسار KERNIX `OWNED_DATA_RW_ONLY`.
- **ليس المطلوب 142 بعد هذه المرحلة**: 142 كان منع الخريطة الرابعة، أما الآن فتجاوزها وانتقل إلى استدعاء جديد.
- لا يعني نجاح هذه البوابة اكتمال GNU ldso أو glibc. الهدف اللاحق هو `BSS` الصفري المملوك، ثم ما يتلوه من استدعاءات المصدر الأصلي عند ثبوت النجاح العتادي.

الحالة عند إنشاء الوثيقة: **R3-C8 نجح على الهاتف، R3-C9 قيد البناء/الاختبار؛ لا يوجد دليل على تشغيل Wine أو DXVK أو اللعبة**.
