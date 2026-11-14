# CarX PC Runtime R3-C2 — إصلاح عائق SIGBUS 183 دون إعادة تجارب FEX

**مصدر التشخيص:** تقرير الهاتف `CarX_PC_R3C_Diagnostics (1)(1).json`، REDMAGIC NX809J، Android 16. هذا ملف المستخدم، ولم يُنشر لأنه يحتوي آثار تشغيل الجهاز.

## الأدلة قبل الإصلاح
- **R3-C1** حل مشكلة Android Bionic `libc++_shared.so not found`: المكتبة أضيفت وثبت تشغيل المشغّل.
- الحقل `original_ldso_continuation.exit_code=183` وليس `0`.
- تم رصد `brk(12)`، و`access(21)` الاختياري، و`openat(257)` الخاص بـ`/etc/ld.so.cache` كـ`ENOENT` افتراضي آمن.
- لم يسجل `libc` virtual open ولا glibc startup؛ لا نرفع حالة المرحلة إلى PASS كاملة.
- قيمة 183 تظهر في ملف `native-engine/android-host/kernix_g0_original_fex_sigbus_backpatch_android_bionic_diagnostic.h` فقط عند **رفض القيمة العائدة من الدالة الأصلية** أو انحرافها، بعدما اجتاز الفحص الأولي لشروط SIGBUS/JIT.

## السبب المحدد من كود FEX الحقيقي pinned source
استدعاء `FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess` يرجع `std::optional<int32_t>`:
- **nullopt**: غير معالج ويجب رفضه.
- **0**: نجاح تصحيح `LDAR/LDAPR` إلى `LDR` مع حفظ `DMB_LD`؛ يجب إعادة محاولة نفس PC.
- **-4**: تصحيح `STLR` إلى `STR` وإعادة التنفيذ من حاجز `DMB` السابق؛ يجب إنقاص PC بمقدار 4.
- **4**: نجاح محاكاة التعليمة مع تجاوز 4 بايت.

في R3-C1 كان الشرط `!*recovered` يرفض القيمة **0** على أنها فشل؛ وكان حساب `max - *recovered` بدون التعامل مع الإشارة يرفض **-4** بسبب التحويل الضمني غير الموقّع. لذلك رمز `183` بعد `ld.so.cache` يتفق مع عيب في عقد PC الخاص بمعالج Bionic، وليس فشلاً لمكتبة GNU أو ملفات اللعبة.

**الدليل المرجعي الدقيق:** FEX-Emu/FEX commit `02e24ca5c01ed0c864466ed573db347336f70170`, `FEXCore/Source/Utils/ArchHelpers/Arm64.cpp`, function `HandleUnalignedAccess`.

## إصلاح R3-C2
الملف `carxpc/r3c2/apply_signal_fix.py` يطبّق باتش محدود على **نسخة البناء المعزولة** من Header الخاص بـKERNIX، ولا يغيّر مستودع KERNIX التاريخي.
1. التمييز بين `nullopt` وبين نجاح `optional(0)`.
2. احترام دلتا signed بالمدى `[-4,128]` ومحاذاة ARM64 الطبيعية؛ منع overflow/underflow.
3. الاحتفاظ بفحوص مصدر JIT `IsAddressInCodeBuffer` و`BUS_ADRALN` وإيقاف إعادة الدخول وحد 4096 معالجة.
4. عدم تعطيل x86 TSO إطلاقاً، وعدم تغيير source ELF أو `libc.so.6`.
5. تسجيل علامة واضحة عند أول backpatch بقيمة `0` أو `-4`، مع إبقاء الإبلاغ عن `nullopt` فشلاً صريحاً.

## بوابات النجاح
- CI: نجاح تطبيق الباتش وتجميع مكتبة Android/Bionic الأصلية، تطابق FEX/ELF الثلاثة، وجود `libc++_shared.so`، بصمات APK والتوقيع الأصلي مع `versionCode=9`.
- **الجهاز:** تشغيل الاختبار السادس فقط؛ إثبات ظهور علامة تصحيح SIGBUS ثم استمرار المحمّل بعد `ld.so.cache` إلى طلب `libc` الحقيقي.
- لا نعتبر الوصول إلى `libc` أو إنشاء FD نجاح glibc؛ تشغيل `main` و`exit_group(0)` يبقى هدف R3-C اللاحق.

**النتيجة حتى الآن:** إصلاح المصدر معروف؛ اختبار الهاتف على R3-C2 لا يزال مطلوباً بعد إصدار APK موقّع.
