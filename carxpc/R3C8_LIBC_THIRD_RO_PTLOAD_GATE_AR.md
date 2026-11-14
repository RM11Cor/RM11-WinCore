# CarX PC Runtime R3-C8 — المصدر الأصلي لخريطة libc الثالثة RO

## نتيجة R3-C7 الموثقة من جهاز الهاتف
تقرير `CarX_PC_R3C_Diagnostics (7).json` لجهاز REDMAGIC NX809J (Android SDK 36) قدّم:
- `original_libc_second_text_rx_ptload_verified=true`، `original_libc_second_text_rx_wx_safe_verified=true`، و`success=true` **للاختبار المحدود**.
- الخريطة الأولى من `libc.so.6`: `guest_base=0x804000000` بحقوق `r--p`؛ الثانية: `base=0x804028000, length=0x188000, offset=0x28000` بحقوق `r-xp`، بدون صفحات W+X.
- `exit_code=142` هو الحاجز المتعمّد قبل استكمال الطلب الثالث، وليس تعطل FEX.
- الطلب الثالث الحقيقي:
  `mmap(addr=0x8041b0000, len=0x4f000, prot=1 [RO], flags=0x812, fd=100, offset=0x1b0000)`.
  مُلاحظة: `fd=64` في اللوج مكتوبة hex؛ تعادل `100` عشرياً، وهو الملف الافتراضي الموثق `libc`.
- `guest_glibc_initialized=false`, `full_dynamic_interpreter_complete=false`, `wine_executed=false`, `carx_game_boot_proven=false`.

## تنفيذ R3-C8
بدون إعادة كتابة المحرك، نفعل دالة KERNIX الأصلية:
`DispatchOriginalLdsoPinnedLibcOwnedReadOnlyPTLoad` باستخدام علم التجميع
`KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY`.
تُراجع هذه الدالة مصدر `PT_LOAD` الأصلي، وتحتفظ بمحتوى الخرائط السابقة، وتمنع التنفيذ أو الكتابة خارج المدى المسموح.

علامة النجاح المطلوبة بعد نجاح الخريطتين السابقتين:
`KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_THIRD_FIXED_RO_MMAP_PTLOAD_VERIFIED_SOURCE_NO_NATIVE_FIXED_NO_WX_PASS base=8041b0000 length=0x4f000 offset=0x1b0000`.

يتوقف مسار R3-C8 عمداً قبل الخريطة الرابعة `RW` عند
`KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=3` و `exit_code=142`.
**هذه بوابة سلامة مقصودة**؛ النجاح مشروط بظهور علامتي RO الثالثة وحاجز الرابعة بالترتيب، والتحقق من الملفات الأصلية وتوقيع APK.

## حدود الإثبات
- R3-C8 لا يثبت اكتمال `glibc` أو جلب Wine أو تشغيل CarX أو رسومات DXVK.
- حُفظ FEXCore بمصدره pinned وتوقيع `com.r4.carxpc`، `versionCode=15`، ويثبت التحديث فوق R3-C7 بدون حذف.
- عند نجاح اختبار الهاتف، الانتقال التالي إلى الخريطة الرابعة `RW` بعد مراجعة offset/vaddr والتحقق من W^X، ثم BSS. لا نسمح بتحويل الخريطة التنفيذية إلى writable.

**CI build success ليس نتيجة هاتف.** تقرير الهاتف الجديد هو الذي يقرر R3-C8 PASS أو فشل تفصيلي.
