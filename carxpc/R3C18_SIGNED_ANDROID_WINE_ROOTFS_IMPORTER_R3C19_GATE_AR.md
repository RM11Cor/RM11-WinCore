# R3-C18 / RootFS المملوك للتطبيق — نتيجة موثقة وانتقال إلى R3-C19

التاريخ: 14 نوفمبر 2026

## 1. ما اكتمل فعلاً
- تم بناء مُثبّت Java قابل للتشغيل على Android API 26+، يدعم إدخال stream من SAF إلى مساحة التطبيق، ويتحقق من SHA-256 الثابت `86fafa2f5072aa2c47b7025ca591d945007584ecda37ae92eee208a95283f4b0`.
- لا يحتاج root، ولا ينفذ Wine ولا ملفات Linux، ولا يرفع ملفات مستخدم إلى الإنترنت.
- تحميه قواعد رفض path traversal، الكتابة خارج rootfs، تجاوز حجم الأرشيف، الروابط الرمزية المطلقة التي تُوجّه للمضيف، روابط hardlink الخطرة، محتوى TAR المعدل، وفشل digest. يتم إنشاء نسخة مؤقتة ثم استبدال آمن والرجوع للسابق عند الخطأ.
- اختبارات الاصطناع: `14` حالة قُبلت/رُفضت حسب المتوقع، GitHub Actions https://github.com/RM11Cor/RM11-WinCore/actions/runs/43603485049
- استخراج أرشيف Wine الأصلي نجح على Linux بنفس كود Java:
  - compressed archive: 517,361,543 bytes
  - regular extracted bytes: 1,255,718,615
  - entries: 10,278
  - symbolic links: 1,393
  - hardlinks: 2
  - هذا **ليس** اختبار تشغيل Wine على Android.
- APK جديد signed stable applicationId `com.r4.carxpc`, `versionCode 23`; UI button07 imports external `.tar.gz` through ACTION_OPEN_DOCUMENT, checks free app-internal space 1.4 GB new / 2.7 GB replacement, exports `wine_guest_rootfs` JSON with false fields `wine_android_executed`, `win64_pe_android_executed`, `carx_game_boot_proven`.
- Release: https://github.com/RM11Cor/RM11-WinCore/releases/tag/carx-pc-v0023-r3c18-wine-rootfs
- Signed release GitHub Actions: https://github.com/RM11Cor/RM11-WinCore/actions/runs/43604494531 ; certificate continuity verified and original FEXCore/ldso library fingerprints retained.
- Signed APK SHA256: `c39d0673d2947c6247a40d4ef6215c8e2605457defa3bd7e48dbcb2d37c97051`.

## 2. حدود مهمة
- APK لا يضم الأرشيف 517 MB. الملف الأصلي محفوظ في GitHub Actions artifact لبيئة Linux control: https://github.com/RM11Cor/RM11-WinCore/actions/runs/43598239873/artifacts/14115405834
- تجربة المستورد على REDMAGIC 11 Pro Android16 لم تتم بعد؛ لا نعلن نجاحاً فعلياً على الجهاز حتى يأتي تقرير.
- ملف RootFS هدفه تهيئة **بيانات Linux x86_64**، وليس تشغيل `wine64` بواسطة `execve` من Android app private writable storage. Android/Bionic يفرض قيوداً منفصلة على العمليات والتنفيذ وصفحات الذاكرة، وتحتاج FEXCore guest process adapter.
- نتيجة R3-C16 أثبتت Wine + FEX على **Linux ARM64** فقط وليس Android. كذلك R3-C15 أثبتت عينة GNU x86 ELF المحدودة فقط، 12/12.

## 3. R3-C19 — المطلوب قبل Window PE على هاتف المستخدم
- Android ARM64/Bionic process adapter يدعم قراءة ملفات ELF x86-64 من app-owned rootfs كبيانات، ويتحقق من `PT_INTERP`, `PT_LOAD`, `DT_NEEDED`, symlinks/FD ownership, guest VMA and safe mapped memory.
- Guest process/subprocess semantics لبيئة Wine (fork/clone/exec guest virtual), ELF loader, guest TLS/FS and syscalls; عدم تمرير untrusted guest pointers مباشرة إلى kernel Android host، وعدم الكتابة على TLS الأصلي للمضيف.
- يختبر Linux guest `wine --version` داخل التطبيق على الجهاز أولاً، ثم Windows ntdll/kernel32، ثم exact Win64 API smoke PE مع العلامة + exit code 0.
- عند إثبات اختبار Win64 على Android، اختبار DXVK D3D11 → Vulkan WSI Surface swapchain acquire/submit/present ورسمة مثلث ثم تشغيل CarX Street PC واختبار يد التحكم.
- استراتيجية الدفعات مُعتمدة: تقرير واحد يذكر أول فشل لكل مرحلة، ولا يعيد اختبارات R3-C15 إلا كـ regression.
