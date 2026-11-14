# CarX PC Runtime R3-C16 — انتقال من GNU ELF إلى اختبار Win64/Wine ثم الرسوميات

## مدخلات مؤكدة من تقرير R3-C15 على الهاتف
- 12/12 لنقاط المتابعة المعتمدة بعد `set_tid_address` نجحت في عملية واحدة.
- `exit_code=0`, `auto_batch_terminal_original_guest_exit_group0_proven=true`, `success=true` للبوابة المحدودة.
- شوهد تنفيذ دالة `puts` من glibc و`write(1)` للبيانات ذات 45 بايت وانتهاء العينة بـ `exit_group(0)`.
- تشير نفس العينة إلى `full_dynamic_interpreter_complete=false` و`guest_glibc_initialized=false` لكون غلق جميع dynamic relocations، IFUNC resolver traces وGNU ld.so return لا تزال غير مكتملة الإثبات. هذه القيمة لا تحوّل نجاح العينة المحدود إلى فشل.
- لا نعيد R3C15 على جهاز المستخدم إلا عند regression ناتج عن دمج فعلي.

## لماذا لا ننتقل إلى CarX مباشرة؟
نجاح ELF ضيف واحد لا يثبت تنفيذ برنامج Windows PE ولا احتياجات Wine المتعددة. نموذج syscalls السابق مقيد بثلاثة ELF فقط، ومكتبة Wine11 الموجودة محفوظة كـ Linux x86_64 guest مع glibc، وليست مكتبة Android ARM64 تفتحها Bionic مباشرة.

## مرحلة R3-C16 المطبّقة الآن
أُنشئ مصدر برنامج Win64 PE مستقل شرعي:
`carxpc/r3c16/win64_vmem_tls_stdout_smoke.c`.
يغطي `GetCurrentProcessId/GetCurrentThreadId`, `VirtualAlloc/VirtualProtect/VirtualFree`, `TlsAlloc/TlsSetValue/TlsGetValue/TlsFree`, `GetStdHandle/WriteFile` مع نجاح stdout وخروج status0 **عند تشغيله الحقيقي**. حتى الآن يجري *بناء PE64 وفحص imports فقط*، ولا ننسب إليه أداء تنفيذ على أندرويد.

Workflow يقوم بفحص:
- MZ/PE32+/AMD64 وImports من Windows KERNEL32.
- بصمة Android ARM64 FEXCore والـrunner المأخوذ من R3-C15.
- بصمة Wine 11 x86_64 Linux guest archive من بناء KERNIX الناجح مع توثيق commit والترخيص.
- تصدر نتيجة JSON صريحة `wine_x64_ntdll_kernel32_loaded_on_android=false` و`win64_pe_executed_under_fex_wine_android=false` ما دامت مرحلة الجسر غير موجودة.

## سلسلة تنفيذ واحدة مستقبلية على الهاتف
1. Host Android/FEXCore original-ELF regression witness (R3C15 accepted cached).
2. Mount guest Linux x86-64 rootfs properly, protected path/FD ownership and full guest process syscall service, with no accidental Android-native ptr forwarding.
3. Load guest glibc and Wine x64 runtime into FEX, test `wine --version` and real `ntdll.dll/kernel32.dll` initialization.
4. Execute this Win64 PE, test VM/TLS/write and exit 0; report first failure by subsystem.
5. Attach Android Surface and DXVK D3D11 to Vulkan; measure actual triangle **submitted/presented**, not merely clear color.
6. Only then select source-owned CarX Street PC folder and test main EXE/game graphics and input.

**Important:** no claims that R3-C16 makes CarX playable yet; no updated APK in this stage until Android Wine guest execution bridge actually exists. Keep original game files unchanged. Direct ARM64 native recompilation is a separate project.
