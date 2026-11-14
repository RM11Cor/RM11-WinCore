# CarX PC Runtime R3-C5 — GNU libc fstat(5) على ARM64

## الإثبات المعتمد من تقرير الجهاز R3-C4
- الجهاز REDMAGIC NX809J، Android 16، `arm64-v8a`.
- `R3-C4` اجتاز `read(fd=100, 832)` ثم `pread64(fd=100, 784, offset=64)`، وبصمات FEX وELF سليمة.
- بلغ محمّل GNU الأصلي استدعاء `syscall 5 (fstat)` من تعليمات x86-64:
  `rip=0x8010258f9`، `rdi=100`، `rsi=0x80300ef60`.
- خرج التجريب المحدود برمز `117` لأنه رفض الطلب غير المدعوم في R3-C4؛ لم يثبت إطلاق `glibc`.
- `success=true` بالتقرير تعني **بوابة pread64 المحدودة**، وليس بدء ويندوز/CarX.

## R3-C5 — إعادة استعمال الشفرة السابقة بدون التراجع للاختبارات الناجحة
نستخدم كود KERNIX المصادق عليه، `DispatchOriginalLdsoPinnedLibcFstatToStack`، عن طريق:
`-DKERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY`.

المعالج يتحقق من أن:
1. `fd=100` مرتبط حصراً بملف `libc.so.6` الموثّق ببصمته، ولا يوجد فتحات إضافية.
2. `fstat` وقع بعد `read(832)` ثم `pread64(784)` في العملية نفسها.
3. عنوان الضيف للنتيجة موجود داخل ذاكرة `RW`، ضمن حدود محمية؛ لا ينفّذ host `fstat` نيابة عن ضيف غير موثوق.
4. البنية المكتوبة هي Linux x86-64 `stat` بحجم `144` بايت، وتحتوي حجم الملف المصدر `2118168` بايت وبقية الحقول المدقّقة.
5. تُسجّل العلامة التي طبعها التنفيذ الضيف-المصدر:
`KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_FSTAT5_VIRTUAL_X86_64_STAT144_SOURCE_SIZE_2118168_OWNED_GUEST_STACK_PASS_NO_HOST_FSTAT`.

## بوابات CI والجهاز
- Build native ARM64/Bionic ولقطة KERNIX الأصلية، نفس FEXCore SHA256 `f71397bf1bbedd03305c7127e442d674227fa54d15217cc7effb22dbaa9f4b1d`، نفس إصلاح SIGBUS.
- بايتات `.so` داخل Debug وRelease مطابقة لبصماتها المثبتة، مكتبة `libc++_shared.so` مرفقة.
- الحزمة `com.r4.carxpc`، `versionCode=12`، شهادة تحديث ثابتة مطابقة R3-C4؛ لا نحذف التطبيق عند التحديث.
- اختبار الهاتف **06** فقط: `original_libc_fstat5_virtual_stat144_verified=true` ثم رصد الاستدعاء التالي مع `exit_code=117` في حال التوقف المتعمّد. غير ذلك نحتفظ بالنجاحات الجزئية ونشخص أول اختلاف.
- لا يُدّعى إطلاق `glibc` أو Wine أو DXVK أو CarX قبل ظهور أدلة تشغيلها الفعلي.

المرحلة الجديدة بعد R3-C5 تُختار من الاستدعاء الأصلي التالي (غالباً تخصيص مقاطع الملف عبر mmap، لكن لا نثبت اسمه أو معاييره إلا من التقرير).
