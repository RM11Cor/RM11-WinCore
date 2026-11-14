# CarX R3-C15 AutoBatch — اختبار GNU ld.so الأصلي دفعة واحدة

## لماذا غيّرنا طريقة الاختبار؟
بعد نجاح تقرير R3-C14 على REDMAGIC NX809J، الخطوة الأصلية التالية x86 `set_robust_list(273)`. بدلاً من عمل APK جديد لكل syscall، يجمع R3-C15 سلسلة المصدر الموجودة في KERNIX داخل **تشغيل واحد** لتجربة الاختبارات المعتمدة تباعاً. كل مرحلة تحتفظ بشرطها الأصلي للتحقق من عنوان x86، وملكية ذاكرة الضيف، وحقوق الحماية، وعدم تمرير مؤشرات الضيف إلى نواة أندرويد.

## سلسلة 12 نقطة متابعة بعد R3-C14
1. `set_robust_list(273)` داخل TLS
2. تطبيق GLOB_DAT واحد من مصدر ELF المُوثق — **ليس** اكتمال كل relocations
3. `rseq(334)` مع fallback `-ENOSYS`
4. تأكيد قيمة CPU ID `-2` على مسار glibc الاحتياطي
5. إغلاق صلاحيات GNU RELRO الأربع لصفحات libc
6. إغلاق صفحة GNU RELRO لعينة ELF الرئيسية
7. إغلاق صفحتي GNU RELRO لمحمّل ld-linux
8. `prlimit64` لحدود stack عبر مخزن محلي ثم guest stack
9. `fstat(1)` وتحويل نتيجة x86 stat144 الآمنة
10. `getrandom(8)` إلى مخزن محلي ثم BSS المُوثق
11. `write(1)` بطول 45 بايت من heap مُوثق
12. طلب `exit_group(0)` الأصلي من عينة ELF x86 (يُعالج داخل child فقط)

## تقرير تلقائي واحد
- `auto_batch_step_results`: لكل خطوة PASS أو STOPPED_OR_FAILED أو NOT_REACHED
- `auto_batch_steps_passed` و`auto_batch_steps_total=12`
- `auto_batch_first_failed_or_unreached_step`
- `auto_batch_stop_reason`
- `auto_batch_last_unsupported_x86_syscall` عند توقف على syscall مجهول
- `success=true` فقط إذا اجتازت جميع النقاط مرتبة وفي child exit code 0 مع علامة المصدر الصحيحة والاختبارات السابقة

## حدود الإثبات
هذا اختبار تشغيل `ELF` ضيف صغير ذو مصدر مُثبت، **ليس CarX Street**. حتى لو نجحت نقاط الدفعة كلها لا تثبت اكتمال GNU dynamic relocations أو Wine أو Vulkan أو DXVK أو تشغيل CarX. رسومات اللعبة والخيوط العامة وWine Windows APIs تحتاج سلسلة اختبارات وبناء منفصلة. إذا توقفت إحدى النقاط، تحدد العلامة الفاشلة وتُرجع تقريراً بدلاً من تجاوزها. 

لا تفعيل عام لـ syscalls غير المُوثقة، ولا تعديل للملفات الثنائية الأصلية. بورت Android المُباشر دون Wine/FEX هو مشروع آخر مستقل.
