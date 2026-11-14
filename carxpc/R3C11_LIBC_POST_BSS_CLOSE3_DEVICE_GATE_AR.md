# CarX PC Runtime R3-C11 — إغلاق واصف libc الافتراضي بعد اكتمال BSS

## دليل الهاتف السابق: R3-C10
- مصدر الإثبات: تقرير `CarX_PC_R3C_Diagnostics (10).json`، REDMAGIC NX809J، Android SDK36، `arm64-v8a`.
- `original_libc_fifth_anonymous_bss_zero_mmap_verified=true`، `original_libc_fifth_bss_zero_sample_and_wx_safe_verified=true`، و`success=true` **لبوابة R3-C10 المحدودة**.
- خرائط `libc` الموثقة على الهاتف: `RO` الأولى، `RX` الثانية، `RO` الثالثة، `RW` الرابعة، ثم `BSS` مجهولة وصفرية داخل صفحات ضيف مملوكة.
- توقفت العملية عمداً برمز `117` عند استدعاء x86-64 أصلي:
  `syscall=3 (close)`، `rdi=0x64=100`، `rip=0x801025a29`.
  هذا **واصف افتراضي لملف `libc.so.6`**، وليس واصف ملف تابع لعملية Android host.

## هندسة R3-C11
- نعتمد كود KERNIX المثبت `DispatchOriginalLdsoPinnedLibcCloseAfterBSS` عبر ماكرو التجميع:
  `KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY`.
- قبل إرجاع `RAX=0` إلى الضيف، نتحقق من أن الملف فُتح مرة واحدة فقط، وأن `read`، `pread64`، `fstat`، وخمس خرائط `mmap` الأصلية تحققت بالترتيب.
- يتحقق كود المصدر من اختفاء الملف من جدول الواصلات الافتراضي، **مع الاحتفاظ بخرائط `libc` القائمة** (`BytesHeld=0x212000`) وبحقوقها `r--p/r-xp/r--p/rw-p/rw-p`، ومنع `W+X`.
- لا نمرر `close(100)` إلى host ولا نغلق أي واصف Android فعلي.
- العلامة الإلزامية:
  `KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_CLOSE3_AFTER_FIFTH_BSS_SYNTHETIC_FD100_ONLY_MAPPED_RO_RX_RW_PTLOADS_REMAIN_PASS base=804000000 NO_HOST_CLOSE`.
- عندما يظهر الاستدعاء الأصلي التالي بعد علامة الإغلاق، تتوقف بوابة R3-C11 المحدودة عند `exit_code=117`، مع الاحتفاظ برقمه ومعاملاته من تقرير الجهاز؛ لا نفترض نوعه مسبقاً.

## شروط اعتماد R3-C11
1. CI: نفس المصدر الكامل `FEXCore` وملفات ELF الثلاثة وبصماتها الأصلية؛ تصحيح `SIGBUS` السابق؛ تنفيذ Android ARM64/Bionic؛ توقيع APK ثابت `com.r4.carxpc`، `versionCode=18`.
2. على الهاتف: علامتا `BSS` و`close3` الحقيقيتان بالترتيب، ثم علامة `NEXT_UNSUPPORTED_X86_SYSCALL` والخروج `117` خلال 45 ثانية.
3. `success=true` لا يعني سوى **مرحلة close3** المحدودة. `full_dynamic_interpreter_complete` و`guest_glibc_initialized` و`wine_executed` و`carx_game_boot_proven` تبقى `false`.

إصلاحات FEX/Vulkan السابقة لا تُعاد أو تُستبدل. أي مرحلة تالية تحددها المعاملات الفعلية لأول استدعاء أصلي بعد `close`.
