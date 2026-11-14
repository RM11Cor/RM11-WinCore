# CarX PC Runtime R3-C10 — الأصلية libc BSS الصفري

## نتيجة الهاتف المعتمدة من R3-C9
- تقرير `CarX_PC_R3C_Diagnostics (9).json` من جهاز `NX809J`، Android 16 arm64-v8a.
- ظهر `original_libc_fourth_data_rw_ptload_verified=true` و`original_libc_fourth_data_rw_wx_safe_verified=true` و`success=true` **لبوابة R3-C9 المحدودة فقط**.
- أتم FEX في العملية نفسها أربعة خرائط مصدرية `libc.so.6`: `RO` عند `0x804000000`، `RX` عند `0x804028000`، `RO` عند `0x8041b0000`، `RW` عند `0x8041ff000`.
- `exit_code=117` بعد استدعاء الضيف الجديد `mmap(9)`:
  - `addr=0x804205000`;
  - `length=0xcd90` (52624 بايت);
  - `prot=3` (`RW`);
  - `flags=0x32` (`MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS` لعنوان الضيف فقط);
  - `fd=-1`, `offset=0`.
- لم يثبت هذا التقرير تشغيل `glibc` كاملاً أو `Wine` أو اللعبة.

## R3-C10 — تنفيذ BSS بدون إعادة اختبارات الخرائط القديمة
نفعّل معالج KERNIX المثبت بالشفرة:
`-DKERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY`
والدالة `DispatchOriginalLdsoPinnedLibcOwnedAnonymousBSS`.

يجب أن تتحقق نفس العملية من:
1. مصدر `PT_LOAD` المكتوب سابقاً، و`mem_end=0x211d90`، وحجم مساحة BSS الأصلية `0xcd90`، بدءاً من `0x804205000`.
2. صفحات BSS المملوكة مملوءة بالأصفار فعلياً عند أربعة مواضع عينة: `0`, `0x1000`, `0xc000`, `0xcfff`.
3. حقوق خرائط `libc`: `r--p` و`r-xp` و`r--p` و`rw-p` و`rw-p`، ولا توجد أية صفحة `W+X`.
4. عدم تمرير `MAP_FIXED` الخاص بالضيف إلى Android host؛ لا استغلال لواصفات الملفات الافتراضية عبر host.
5. `BytesHeld=0x212000` بعد ضم الصفحات، ومراجعة أي تجاوز حدود أو صلاحيات.

العلامة المطلوبة لنجاح BSS من عملية الضيف هي:
`KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_FIFTH_ANONYMOUS_BSS_MMAP_ORIGINAL_RW_PTLOAD_SOURCE_MEM_END_0x211d90_ZERO_0xcd90_OWNED_NO_NATIVE_FIXED_NO_WX_PASS base=804205000`.

## بوابات الاختبار
- CI: نجاح بناء ARM64/Bionic من نفس FEXCore وصورة GNU المثبتة SHA؛ نفس إصلاح SIGBUS؛ حزمة `com.r4.carxpc` مع `versionCode=17`، فحص SHA ومكتبة C++ وتوقيع ثابت.
- الهاتف: ظهور علامة BSS بعد علامات الخرائط الأربع، ثم `KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL` مع `exit_code=117`، وإكمال العملية في 45 ثانية.
- `success=true` هنا يعني **R3-C10 bounded progress فقط**؛ لا يعني تهيئة glibc أو تنفيذ Wine أو اللعبة.
- المرحلة التالية تحددها معاملات استدعاء النظام الحقيقي الذي يظهر *بعد BSS*، ولا نفترض رقم الاستدعاء قبل التقرير الجديد.

**حالة هذه الوثيقة:** دليل R3-C9 على الهاتف PASS؛ R3-C10 يخضع للبناء والتجربة الهاتفية ولا يعد PASS بعد.
