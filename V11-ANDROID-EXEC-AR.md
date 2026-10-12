# RM11 WinCore V1.1 — أول تشغيل لملف Android ARM64 تنفيذي مستقل

## ما الجديد؟

* المشروع يبني ملف **ELF PIE تنفيذي** جديد من `PackagedExecProbe.c` بواسطة **Android NDK r27** ويخزنه باسم `librm11execprobe.so` داخل مجلد `lib/arm64-v8a/` في APK؛ هذه التسمية لأغراض التغليف والاستخراج فقط، وليس الملف مكتبة JNI.
* Android >= 10 يقيّد تشغيل الملفات من مجلدات التطبيق القابلة للكتابة؛ لذلك يتم تشغيل **هذا الملف المضمّن والثابت فقط** من `ApplicationInfo.nativeLibraryDir` بعد استخراج مكتبات APK، باستخدام `ProcessBuilder` **دون shell** ولا أي أسماء أو معاملات تأتي من المستخدم.
* الزر الجديد في القسم 11 يبدأ عملية ARM64 مستقلة، ينتظر حتى 7 ثوان، ويعرض رمز الخروج وstdout. مخرجات النجاح المتوقعة: `[PASS] Separate ARM64 Android executable launched from APK` مع `RM11_ANDROID_ELF_EXEC_OK` و`ARCH=aarch64`.
* يتم فحص بنية ELF الناتجة (ELF64 AArch64 ET_DYN + PT_INTERP + Android linker64) في مرحلة بناء GitHub وفي خطوة مراجعة APK، قبل عرض نجاح البناء.

## كيف يُبنى دون تغيير workflow كل مرة؟

في المستودع يوجد بالفعل خطوة `python3 scripts-check.py` قبل `gradle assembleDebug` في ملف workflow. تقوم V1.1 باستدعاء `tools/build_native_exec.py --required` تلقائياً **على GitHub Actions**، فتولّد ملف `app/src/main/jniLibs/arm64-v8a/librm11execprobe.so` قبل بناء APK. على بيئة التطوير تحتاج NDK r27، ويمكن تشغيل سكربت البناء يدوياً قبل Gradle. إذا لم يتوفر NDK محلياً، تنجح اختبارات المصدر وتعرض `SKIP`؛ ولا يعني هذا أنه تم اختبار بناء APK. على GitHub يجب أن يتوقف البناء **بخطأ** إذا لم يوجد NDK.

لا يحتاج الأمر روت، ولا يسمح بتنفيذ محتوى حزم ZIP المخزونة في V0.9. تستمر تلك الحزم كبيانات فقط.

## ماذا **لا** يثبت اختبار V1.1؟

* لا يوجد **Box64** فعلي أو **Wine** أو **glibc rootfs** أو **DXVK/VKD3D** داخل هذا الإصدار؛ لذلك لا يشغل `.exe` أو ألعاب Windows.
* نجاح تشغيل ملف Android ARM64 بسيط لا يضمن نجاح تشغيل Box64 المبني لبيئة Linux/glibc. هذه خطوة أولى لاختبار مسار التنفيذ من APK فقط.
* الخطوة الهندسية التالية: بناء Box64 من المصدر الرسمي بتراخيصه، واعتماد استراتيجية Windows/Wine64 + glibc rootfs، مع مراعاة قيود أندرويد وW^X، ثم تجربة أمر `box64 -v` بشكل معزول، قبل التفكير في EXE بسيط ثم الأداء الرسومي.
* المرجع الرسمي لـ Box64 ومعلومات Android/Termux: https://github.com/ptitSeb/box64/blob/main/docs/COMPILE.md

## الاختبار الذي نريده منك

بعد تشغيل GitHub Actions وفتح APK، انزل إلى **القسم 11** واضغط **«تشغيل الملف التنفيذي ARM64»**، وأرسل لنا صورة النتيجة. لا تحتاج رفع حزمة الـ79 بايت لهذه الخطوة.
