# CarX PC Runtime R3-C20 — حزمة اختبار موحدة واحدة

الإصدار Android ARM64 `com.r4.carxpc`, `versionCode 25`. لا يحذف بيانات R3C18/R3C19 عند التحديث، وموقّع بنفس الشهادة الأصلية إذا نجح GitHub Actions.

## شيء واحد على الهاتف
- ثبّت APK واحداً فوق التطبيق السابق. افتحه واضغط الزر **09 — بدء الاختبار الموحد الكامل — تقرير JSON واحد**، ثم صدّر `CarX_PC_R3C_Diagnostics.json` من نفس التطبيق. لا حاجة لتكرار الضغط على 04/05/06/08؛ الزر 09 يستدعي وظائفها الفعلية التي يحتاجها.
- اختبار GNU الأصلي 12 checkpoint داخل ضيف FEX و`exit_group(0)` يُنفذ مرة واحدة في الدفعة؛ لا يعاد تلقائياً على الجهاز لعدة دورات.
- إذا كان Wine RootFS مُثبّتاً سابقاً عبر الزر 07، يُفحص من دون إعادة استخراج الملف الكبير. وإذا لم يكن مثبتاً تظهر `ROOTFS_NOT_IMPORTED_USE_BUTTON_07_WITH_ORIGINAL_ARCHIVE` كعائق واضح؛ يمكن إرسال التقرير على الرغم من ذلك.
- العرض البرمجي يستخدم سطح Vulkan عند توافر SurfaceView؛ `Vulkan clear` حقيقي لا يُحسب مثلث DXVK.

## المراحل التسع/العشر المنفصلة في التقرير
1. `01_FEXCORE_ORIGINAL` — تشغيل عينة x86 بوساطة مكتبة FEXCore ARM64 الأصلية داخل Android.
2. `02_GNU_LDSO_LIBC_12_OF_12` — تشغيل 12 خطوة أصلية `GNU ld-linux/glibc`, `exit_group(0)` الحقيقي. النجاح يتطلب جميع الإثباتات.
3. `03_WINE_GUEST_ROOTFS` — فحص وجود أرشيف Wine المثبت في مساحة التطبيق وبصمته المتوقعة؛ علامة PASS هنا تعني التواجد فقط، وليس نجاح المحتوى أو تشغيل Wine.
4. `04_WINE_ELF_AND_KERNEL32_AUTHENTIC` — فحص SHA-256 الأصلي لـWine64 وld-linux وkernel32.dll وDT_NEEDED ضد RootFS كامل؛ قراءة فقط.
5. `05_ANDROID_VULKAN_ICD` — استدعاء Vulkan الحقيقي للمكتبة الأصلية.
6. `06_ANDROID_VULKAN_SWAPCHAIN_CLEAR_PRESENT` — تقديم إطار clear باستخدام SurfaceView إن كان جاهزاً؛ ليس DXVK.
7. `07_ANDROID_BIONIC_WINE_PROCESS_ADAPTER` — `BLOCKED` صريح لأن المحرك الحالي يفتقد مترجم عملية Linux x64 العام لـWine/Wineserver تحت Android/Bionic. لا تقدم له نجاحاً مصطنعاً.
8. `08_ANDROID_WINE_NTDLL_KERNEL32_WIN64_PE` — `NOT_REACHED` حتى يثبت Android Wine PE marker + exit0.
9. `09_DXVK_D3D11_VULKAN_TRIANGLE` — `NOT_REACHED` حتى تكتمل المرحلة السابقة.
10. `10_CARX_STREET_PC_BOOT` — `NOT_REACHED` حتى ينجح Windows/DXVK ويجري اختبار اللعبة الأصلي.

كل `stages[]` تتضمن `id,status,reason,evidence` ونتائج FEX الأصلية، و`first_stop` أول توقف حقيقي، و`first_failure` أول فشل، مع تمييز `BLOCKED` عن `FAIL`. النتائج تخص جهاز المستخدم عندما يرسل تقريراً، وليس مجرد نجاح CI.

## حدّ الاختبار المقبول
- نجح Wine+FEX Windows x64 على **Linux ARM64** في R3C16، وليس على Android/Bionic.
- Android 10+ يمنع `execve` من الملفات القابلة للتعديل داخل مجلد التطبيق على التطبيقات المستهدِفة للإصدارات الحديثة، ولا يمكن تجاوز هذا بإعادة تسمية ELF x86 كـ`.so`. الحل الصحيح مترجم ضيف FEXCore + syscalls/خدمات عمليات وWine داخل Android، مع احترام W^X.
- FEX الرسمي نفسه لا يستهدف Android كـLinux emulator، إنما FEXCore يمكن بناؤه لمضيف Android دون أن يحل طبقة syscalls والعمليات. المصادر: https://wiki.fex-emu.com/index.php/FAQ و https://developer.android.com/about/versions/10/behavior-changes-10

## بوابة التنفيذ التالية
مطلوب نموذج Android Bionic حقيقي لعملية `wine64` (FEX translated x86 instruction stream, linux x86 process startup/TLS/FS, guest fork/exec and wineserver virtual syscalls), ثم stdout `wine --version` من جهاز المستخدم، ثم Win64 PE `VirtualAlloc/TLS/WriteFile` خروج0 ثم DXVK D3D11 Vulkan مثلث، وأخيراً CarX. لا يُعلن عن تشغيل Windows أو اللعبة بدون دليل تنفيذ الجهاز.
