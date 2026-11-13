# CarX PC Runtime R3-C — بوابة تشغيل المحمّل الديناميكي كاملة دون تكرار الاختبارات

## قرار الإغلاق
- **R3-B ناجح على جهاز Android** بناءً على تقرير المستخدم: `ldso_progress.success=true`, `exit_code=0`, صحة ملفات المصدر، تسلسل العلامات، تنفيذ حالة ذاكرة RW ومكدس محمّل GNU الأصلي، استعادة الأذونات.
- خطأ تاريخي في R3-A المتعلق ببصمة المكتبة انتهى؛ R3-B اشتغل دون `LIBRARY_HASH_REJECTED`.
- **محدودية صارمة:** `full_dynamic_interpreter_complete=false`, `guest_glibc_started=false`, `wine_executed=false`, `carx_game_executed=false`. **هذا ليس بدء تشغيل ld-linux كاملاً**.
- `components.fexcore.runtime_test_passed=false` هو مؤشر منفصل لاختبار R3-A الذي لم يُنفذ في التقرير الحالي؛ دليل R3-B موجود في `ldso_progress` وليس نتيجة فشل FEX.

## المراجع التي يجب إعادة استخدامها لا إعادة اختبارها
- FEXCore ARM64 Android بنفس SHA `f71397bf1bbedd03305c7127e442d674227fa54d15217cc7effb22dbaa9f4b1d`.
- مشغّل R3-B SHA `eb521dd35ca1afafbc31126f8670ac792a73fd06db9e34e87c98aed68f28454c`.
- مكتبات GNU ضيف x86 المصدرية الثلاثة المثبتة بالبصمات في سلسلة R3-A/B.
- من KERNIX: تحقق **147/147** من **كتّاب relocations على حدة**؛ وStages A/B نفّذت **40/40 في كل عملية Linux FEX منفصلة**، بينما C نفّذت ستة على الأقل في عملية Linux منفصلة حسب وثائق تاريخ 2026-11-12. لا يُجمع ذلك إلى ادعاء تشغيل كل 147 في عملية واحدة، ولا إلى نجاح Android runtime كامل.
- نتائج Android Vulkan، Surface، Swapchain وFEX البسيط محفوظة ولا يُعاد إرسال APKات لها.

## هدف R3-C العملي — وليس نسخة عرض أو شاشة لون
**إثبات تشغيل البرنامج x86-64 GNU المصدر الأصلي بواسطة محمّله الديناميكي وlibc حتى نقطة دخول البرنامج/كتابة stdout والخروج السليم** داخل تطبيق CarX على Android.

### التنفيذ الهندسي المطلوب
1. إعادة استخدام مشغّل R3-B المثبت وواجهات الـFEX والـELF المؤمنة، ثم دمج مسار استمرار `_dl_start` الأصلي بعد استدعاء callee المحدود، **من دون** HLT مصطنع يُعلن نجاح العملية.
2. جسر syscalls لينكس الخاص بالضيف داخل عملية معزولة: `brk, mmap, mprotect, openat, pread64, close, arch_prctl, fstat, write, exit_group` فقط عند ظهورها فعلياً في الأثر؛ Virtual FS خاص بملفات ضيف ELF الموقّعة، ولا تُمرر المسارات أو المؤشرات الأصلية إلى Android host.
3. المحافظة على guest address space وW^X و4K/16K pages وJIT signal handling وخاصة إصلاح SIGBUS unaligned LDAR السابق؛ لا نعدّل ELF اللعبة أو ملفات المستخدم.
4. سِجل واحد لنفس عملية FEX يثبت مراحل loader الفعلية: relocations (RELA, RELR, JMPREL), TLS/FS, IFUNC، حماية RELRO بالترتيب الصحيح، ثم انتقال التحكم إلى `main` من GNU executable الأصلي.
5. دليل نجاح من العملية الضيف نفسها: `guest main RIP` مثبت، stdout الأصلي، `exit_group(0)`، نظافة تحرير الموارد وSHA صحيح. ممنوع تزوير stdout بعلامة يطبعها host من خارج تعليمات الضيف.
6. بناء Android ARM64 Bionic وإجراء اختبار على الهاتف، بنفس الحزمة `com.r4.carxpc` وشهادة توقيع R3-A1/R3-B، و`versionCode>=7`، ونشر فقط بعد فحوص البصمات والتوقيع.

## شروط الانتقال إلى Wine
- **لا** ندمج Wine/Proton أو DXVK لادعاء تشغيل ألعاب قبل تحقق R3-C الكامل. يمكن تحضير تكامل Wine كمصدر بالتوازي دون فحص ألعاب/رسومات غير مفيد.
- بعد نجاح ELF+ldso+glibc على Android، الهدف التالي: Win64 PE صغير شرعي تحت Wine وFEX مع دورة رسالة GUI ونظام ملفات وتحكم، ثم CarX Street x64 Unity IL2CPP/D3D11، وأخيراً DXVK/Vulkan وFPS المدينة.

## بوابات صدق ملزمة
- نجاح GitHub CI لتجميع المكتبة لا يعادل PASS على الهاتف.
- استمرار `ldso` لعدة syscalls أو مئات relocation writes بلا دخول برنامج الضيف **PARTIAL** وليس FULL.
- `147/147` أدلة فردية لا تعني اكتمال relocation process.
- إن احتاج التنفيذ إصلاحاً جديداً، يُوثَّق الفشل الأول بموضعه ويُصلح ذلك الموضع فقط. لا نعود إلى تجارب R1–R3-B.

**الحالة الآن:** R3-C خطة/تكامل محدد، لم يُبنَ APK R3-C ولم ينطلق GNU dynamic guest process كاملاً في تطبيق CarX. لا رابط تحميل جديد إلى أن توجد قدرة تشغيل إضافية مثبتة.
