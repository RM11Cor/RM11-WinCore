# CarX PC Runtime R3-C7 — مصدر libc التنفيذي RX الأصلي

## نتيجة R3-C6 المثبتة على جهاز Android
- `CarX_PC_R3C_Diagnostics (6).json`: `success=true` لبوابة الربط RO المحدودة، `exit_code=142`.
- تم ربط `libc.so.6` الأصلي إلى `guest_base=0x804000000`، بخريطة `r--p` مع حماية نهاية الملف.
- طلب الضيف الثاني `mmap(9)` فعلياً: `addr=0x804028000`, `len=0x188000`, `prot=5 (RX)`, `flags=0x812`, `fd=100`, `offset=0x28000`.
- طلب الخريطة الثانية رُفض متعمداً في R3-C6، بعلامة `PRECONDITION_REJECT after_first=1`؛ لا يدل ذلك على فشل FEX.

## الجديد في R3-C7
- نستخدم معالج KERNIX `DispatchOriginalLdsoPinnedLibcOwnedTextRX` عبر `KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY`، بدلاً من إعادة كتابة طبقة `mmap`.
- يُتحقق من قيمة عنوان الخريطة، وأصل مقاطع `PT_LOAD` التنفيذية الموقّعة، وصحة المحتوى، وصفحة نهاية الملف المحمية، وصلاحيات الصفحات الفعلية `r-xp` عند `base+0x28000`.
- يمنع `native MAP_FIXED` وتوجيه FD الأصلي أو مسار الضيف إلى Android؛ ولا يسمح `W+X`.
- نجاح الخريطة الثانية يجب أن يُسجّل من عملية FEX نفسها بالعلامة
  `KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_SECOND_FIXED_TEXT_MMAP_PTLOAD_VERIFIED_RX_NO_NATIVE_FIXED_NO_WX_PASS`،
  وبعدها يُرفض طلب الخريطة الثالثة بشكل آمن عند
  `KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=2`.
- المتوقع للبوابة المحدودة `exit_code=142`. المهم **ترتيب العلامتين وبصمات الملفات ونجاح الخريطة RX**، وليس الرقم وحده.
- `versionCode=14`، حزمة `com.r4.carxpc` والشهادة الأصلية الثابتة؛ تثبيت فوق R3-C6.

## الحد الهندسي
هذا نجاح جزئي محتمل لربط النص التنفيذي، لا إثبات تشغيل تنفيذ `libc`، أو `glibc` كاملة، أو Wine أو DXVK أو اللعبة. اختبار R3-C7 العتادي لم يُجرَ بعد. المرحلة اللاحقة تعتمد أول طلب أصلي بعد نجاح RX، وهو على الأغلب خريطة مقطع RO ثالث؛ لا نفترض دخوله في هذه المرحلة.
