# RM11 WinCore V0.2 — فحص جاهزية المحرك فقط

هذه النسخة مخصصة لـ REDMAGIC 11 Pro NX809J / SM8850 / Adreno 840 / Android 16، رام 16GB.
لا تحتوي على Wine أو Box64، ولا تنفذ EXE أو تثبت Steam. هذه خطوة تمهيدية تقنية، وليست محاكي ألعاب مكتمل.

## ما أضفناه

- شاشة جديدة «فحص جاهزية المحرك» تتحقق **وقت الفحص** من الموديل، المعالج، ABI، نسخة Android، الذاكرة والمساحة وحالة الحرارة.
- استعلام Vulkan أصلي عن قيم ميزات حقيقية، لا مجرد وجود أسماء الامتدادات: descriptorIndexing / runtimeDescriptorArray / timelineSemaphore / bufferDeviceAddress / synchronization2 / dynamicRendering / robustBufferAccess2 وغيرها.
- تقرير فحص الجهاز من الإصدار 0.2.0 مع المحافظة على قسم المشغّلات والتصدير من النسخة الأولى.
- توضيح صريح لحالة Wine وBox64 وDXVK وVKD3D: **غير مدمج**.

## كيف تجرب النسخة الجديدة من الهاتف

1. ارفع ملف `RM11-WinCore-v0.2.0-source.zip` كما هو إلى جذر مستودع GitHub الخاص بالمشروع، بجوار ملف ZIP القديم.
2. افتح `.github/workflows/build-apk.yml` في Github واختر Edit file (In place).
3. غيّر `RM11-WinCore-v0.1.0-source.zip` إلى `RM11-WinCore-v0.2.0-source.zip` **في سطر فك الضغط فقط**. لا تحتاج تغيّر مسار `working-directory: RM11-WinCore` لأن مجلد المشروع داخل الأرشيف لا يزال بنفس الاسم.
4. تأكد أن خطوة `setup-android` لا تزال `android-actions/setup-android@v4` كما نجحت عندك سابقاً.
5. اضغط Commit changes وانتظر نجاح GitHub Actions، ثم نزّل Artifacts وداخلها `app-debug.apk`.
6. حدّث التطبيق على الهاتف (قد يتطلب تفعيل صلاحية تثبيت تطبيقات من هذا المصدر). إذا كان توقيع Debug مختلفاً ورفض النظام التحديث، احتفظ بالتقرير الأصلي ثم احذف النسخة القديمة وثبّت الجديدة؛ حذف القديمة يمسح الروابط المحفوظة داخلها.
7. افتح التطبيق > «فحص جاهزية المحرك» ثم صوّر **قسم Feature support** وقسم **Actual engine status**.

### ما بعد التحقق

بعد فحص ميزات Vulkan الفعلية، تأتي مرحلة منفصلة لتجهيز بيئة التشغيل: اختيار Wine/Box64 متوافقين، تحديد الترخيص وحزم الاعتماديات، بناء ملفات runtime ARM64، ثم اختبار برنامج EXE صغير غير محمي قبل أي لعبة أو launcher. دعم Anti-Cheat قد يبقى غير ممكن عند متطلبات برامج تشغيل kernel-level أو Secure Boot على ويندوز.

## الخصوصية

لا ترفع تقرير Build Fingerprint أو بيانات الجهاز إلى مستودع عام. لم تُضمّن بيانات تقرير هاتفك الشخصي داخل المشروع.
