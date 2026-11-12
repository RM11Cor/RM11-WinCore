# CarX Street PC → Android: مراجعة طريقة صناعة البورتات الحقيقية

تاريخ الدراسة: 12 نوفمبر 2026. الفرع: carx-street-pc-port-v1.
هذه وثيقة بحث وخطة هندسية، مو إثبات تشغيل CarX ولا APK لعبة.

## قرار البحث: نلغي افتراض أن السورس الرسمي هو الطريق الوحيد

البورتات المجتمعية الفعلية تنبني بأكثر من أسلوب:
1. Static Recompilation / AOT recomp: تحليل كود اللعبة الثنائي الأصلي وإصدار C/C++/LLVM IR ثم بناء ARM64 مسبقاً. ما يحتاج سورس رسمي، لكنه يحتاج محلل تعليمات ومكتبة خدمات ومحرك رسم متوافقين مع اللعبة والمنصة المستهدفة.
2. Reverse-engineered source port: إعادة كتابة/استنتاج كود اللعبة والمحرك ثم ترجمة مباشرة لأندرويد. مثال re3/reVC.
3. Same-engine reconstruction: استخراج مشاهد وموارد Unity من نسخة PC، واستعادة مشروع متوافق وتوفير كود اللعبة. الألعاب التي تستخدم Mono يسهل تحليل كودها المُدار مقارنة بـ IL2CPP.
4. Game-specific compatibility runtime: يبقى كود x86 أصلي ويترجم وقت التشغيل بواسطة FEX مع واجهات خدمات اللعبة / Vulkan. قد يكون APK مستقل ومخصص للعبة، لكنه ليس بورت ARM64 أصلياً خالصاً.
5. Existing native ARM64 executable: يستخدم المطورون مكتبة لعبة ARM64 مبنية مسبقاً ويركزون على Launcher/UI/DXVK/Turnip. وجود libgtav.so في مشروع آخر لا يشرح كيف أُنتجت المكتبة.

## مصادر أولية: GTA V

### A. andrewnakas/gtav-recomp: إثبات Static Recomp حقيقي
https://github.com/andrewnakas/gtav-recomp

هذا المشروع مبني على Xbox 360 GTA V Title Update 27، وليس GTA5.exe للكمبيوتر. يقرأ نسختين من الأقراص والتحديث ويطابق SHA256؛ ReXGlue يحوّل PowerPC game executable إلى 811 مصدر C++ بحسب README المطور؛ LLVM/clang يبني مكتبة Native، ويوفر Runtime متوافقاً مع خدمات Xbox 360 ورسومات Vulkan وShader translation إلى SPIR-V.

في Android، بحسب وثائق المطور، الحاسوب ينتج APK فارغاً من كود اللعبة + حزمة شخصية فيها كود ARM64 وشيدرات مترجمة من ملفات المالك. يجرى استيراد حزمة الكود والموارد على الهاتف. المطور يبلّغ عن اختبار اللعب على Galaxy S23 FE، ولا نتعامل مع هذا على أنه تحقق ميداني مستقل منا.

ReXGlue SDK:
https://github.com/rexglue/rexglue-sdk
https://github.com/rexglue/rexglue-sdk/wiki

إطار ReXGlue محدد لبنية PowerPC/Xbox 360. ليس مترجماً عاماً لمكتبات Windows PE/x86-64 ولا يمكن تمرير GameAssembly.dll إليه وتوقع Android libil2cpp.so.

### B. Rush5 / native Chinese GTA V Legacy port
https://github.com/rushilvishwakarma/Rush5
https://github.com/XHYN-PH/XHYN-V-reborn

Rush5 يذكر أنه Launcher + touch controls فوق محرك GTA V ARM64 من مجتمع آخر، مع مكتبة libgtav.so جاهزة تقريباً 153MB وDXVK/DXVK Native + Turnip. ينقل ملفات بيانات RPF وx64 وupdate من نسخة PC Legacy ولا يستخدم GTA5.exe أو Rockstar Launcher. هذه طريقة توزيع/دمج محرك native جاهز وليست تعليمات موثقة لإعادة إنشاء محرك CarX أو إثبات منشأ مصدر محرك GTA.

هناك مشروع ARM64 آخر مرتبط بحسب التغطيات بتسريب سورس GTA V. تقرير Android Authority بتاريخ 29 سبتمبر 2026 يذكر خطاب cease-and-desist وإغلاقه. لا نستخدم مسارات سورس متسربة، ولا نعتبر التشابه بين مشاريع المجتمع دليلاً أن جميعها استخدمت التسريب.
https://www.androidauthority.com/gta-v-android-port-shut-down-3716766/

### C. GTA III / Vice City re3 / reVC
https://github.com/codepdbh/re3-android-port-evolved
https://github.com/codepdbh/revc-android-port-evolved

مشاريع تستنتج محرك اللعبة ووظائفه ثم تعيد بناءه سورس C/C++ يعمل على عدة أنظمة. عناصر Android تشمل Gradle+CMake+SDL2 وlibrw/OpenGL ES وOpenAL ومدخلات لمس وملفات مستخدم. المشروع الأصلي استغرق جهداً مجتمعياً كبيراً وراجع وظائف الألعاب الأصلية واحدة بواحدة. نموذج مثبت للمحركات الأقدم، مو تحويل تلقائي لأي Unity IL2CPP حديث.

## مصادر أولية: The Last of Us

### The Last of Us Remastered (PS4) Android / Daedalus
https://github.com/erickmendes22/tlou-remastered-android
https://github.com/erickmendes22/tlou-remastered-android/releases

الاسم المحدد: Remastered المبنية على PS4 CUSA00552، **مو The Last of Us Part I على Steam**. مكوّنات هذا البورت: إعداد ملفات PS4 PKG/extracted، PS4 system runtime من عمل ravencaio وأعمال shadPS4، ARM64 Bionic host، **FEX runtime CPU x86-64→ARM64 أثناء اللعب**، وVulkan/Turnip للرسم، مع تصحيحات resolution/fps/physics وواجهة أندرويد وتحكم. المطور يذكر gameplay أولياً لكنه ما أثبت full playthrough على Android.

https://github.com/ravencaio/tlou-remastered-pc

المشروع الأساسي في Windows كان ينفذ x86-64 للـPS4 مباشرة على x86-64 PC، ويستبدل واجهات خدمات PS4 ويترجم GPU. عند Android ظهرت حاجة مترجم FEX للـCPU. هذا الطريق له قيمة كمثال على **Runtime خاص بلعبة**، لكنه لا يطابق شرط Native ARM64 الخالي من CPU translation.

## مصادر أولية: إعادة بناء نفس المحرك دون مشروع رسمي

### Hollow Knight Dual Souls
https://github.com/igawa6/dualsouls
https://github.com/PatnosDD/Hollow-Knight-PsVita

مشروع Unity Android يبني نسخة متوافقة من أصول اللعبة المملوكة للمستخدم، بتصحيحات على نسخة محددة، وأدوات AssetRipper وxdelta3 وUnity. هذا النموذج مهم لـ CarX لأن اللعبة Unity، لكنه ليس دليلاً على أن Unity IL2CPP AOT الحديثة يمكن تحويلها بمجرد استخراج المشاهد: إعادة إنشاء سكربتات اللعبة وAPI التابع لها لا تزال مطلوبة.

### CelesteAndroid
https://github.com/BelmanteGu/CelesteAndroid

مطور اللعبة مستقل؛ يعتمد على كود Celeste المُدار داخل نسخة FNA PC مع .NET ARM64 وSDL3 وFNA/Vulkan وMonoMod لتعديل managed assembly. يعمل بدون x86 translation لأن CLR/CIL قابل للترجمة للمعمارية الجديدة. هذا مسار مناسب للألعاب التي تشحن Managed IL، لكنه لا ينتقل مباشرة إلى CarX IL2CPP بعد ترجمة C# إلى x86-64 native.

## أدوات ممكن ندرسها، ودورها المحدود

- AssetRipper وAssetStudio: استكشاف/إعادة تكوين موارد Unity مثل Assets, scenes, prefabs, textures, materials. لا يضمنان استعادة GameAssembly gameplay implementation.
https://github.com/AssetRipper/AssetRipper
https://github.com/Perfare/AssetStudio

- Cpp2IL: استعادة نوع وأساليب وتحليل IL2CPP، مع IR وCIL جزئي/غير مكتمل؛ قد يتعامل مع method bodies بحدود وليس build كامل جاهز.
https://github.com/SamboyCoding/Cpp2IL

- Il2CppDumper: يستعيد تعريفات وdummy assemblies، لا يعيد أجسام الدوال الأصلية.
https://github.com/Perfare/Il2CppDumper

- rev.ng: Binary lifting / LLVM IR والتحليل العام لكود x86-64. شبيه نظرياً بفكرة AOT لكن ليس هنالك دليل أنه يعيد بناء Unity6 Windows PE GameAssembly مع WinAPI وUnity runtime وAndroid assets بعملية واحدة.
https://github.com/revng/revng

- ReXGlue: تخصصه Xbox 360 PowerPC، ليس Windows Unity.
https://github.com/rexglue/rexglue-sdk

إياك اعتبار نجاح أداة استخراج أو وجود توقيع ARM64 داخل APK نجاح تشغيل لعبة.

## واقع CarX الخاص بنا — أدلة من تقارير جهاز المالك v0.6–v0.9

- REDMAGIC NX809J Android 16 ARM64، Adreno 840.
- GameAssembly.dll (~142 MB) وUnityPlayer.dll (~35.7 MB) هما Windows PE x86-64.
- Unity source header candidate 6000.3.8f1، وحددته صورتان من source SerializedFile.
- Metadata global-metadata.dat غير قياسية في أول 4096 بايت: لا نستنتج تشفيراً تلقائياً، لكن أدوات IL2CPP قد تحتاج معالجة تنسيق أو إثبات ارتباط قبل استخراج تعريفات حقيقية.
- 808 Windows64 bundles؛ 807 catalog references؛ 806 accepted filename matches، اسم player_layout.bundle زائد ضمن matched subset. توجد أسماء رفضها normalized matching، لكن لا دليل أن ملفات اللعبة ناقصة.
- Native Vulkan offscreen framebuffer test نجح 1024/1024، ولم يثبت CarX gameplay code أو أول فريم.
- لا مشروع Unity الأصلي أو مستند حقوق كود متوفر في مستودعنا، ولا نسخة Android من GameAssembly/Unity gameplay.
- التحدي الحقيقي: ثنائي IL2CPP x86-64 + Unity player / WinAPI + Addressables targeted Windows + shader dependencies.

## القرار الجديد (بدلاً من انتظار السورس الرسمي)

**افتح مسار بحث هندسي Source-free CarX Port**. لا نفترض الحصول على كود من الناشر، لكن لا نزعم أن الانتقال إلى Native أصبح مضموناً.

المسار 1 / Unity-aware reconstruction (الأقرب لطبيعة اللعبة):
1. عمل فهرس classes/methods وأجزاء gameplay من تحليل GameAssembly.dll + metadata بطريقة تحترم حدود الحقوق. تحديد أسباب فشل metadata parser إذا فشل.
2. إعادة تكوين مشروع Unity 6000.3 من أصول قابلة للاستخدام وتوثيق نسب السكربتات الأساسية. لا نستخدم dummy C# methods على أنها لعبة حقيقية.
3. اختبار تنفيذ **دالة أو سلوك أصلي ملموس من اللعبة** ثم scene functionality على Android (ليس مجرد تلوين Vulkan).
4. ترميم أنظمة المركبات/الفيزياء/الحفظ/الصوت/الإدخال مع تصحيح الرسومات والموارد حتى الوصول لمشهد CarX الحقيقي، إذا اتضح أن الكود قابل للاستعادة.
5. الاختبارات gated by actual source game behavior and scene/frame, not generic APK compilation.

المسار 2 / experimental PE x86-64 AOT (خيار مخاطرة عالية):
1. اختبار احتمالية binary lifting لـ Unity game-specific native methods إلى LLVM IR/ARM64.
2. تحديد كل WinAPI imports, code registration, indirect branches, TLS, SEH, SIMD, pointers, Unity Native engine hooks.
3. لا نستخدم ReXGlue مباشرة لأنه PPC؛ نحتاج مترجماً مناسباً x86-64 PE ثم واجهة Unity/Android حقيقية.
4. إذا لم نتمكن من تنفيذ دالة Unity IL2CPP من اللعبة نفسها بمدخل ومخرج قابليْن للمقارنة، نوقف التوسع قبل تحويل 142MB من التعليمات.

المسار 3 / dedicated FEX runtime (فقط لو خُفف شرط لا ترجمة CPU):
يجوز تصميم APK خاص بـCarX مع FEX وWindows API / DXVK وملفات يختارها المستخدم؛ يقدم أسرع فرصة تشغيل عملي، لكن بصراحة هو ترجمة ديناميكية للـCPU على الهاتف وليس بورتاً ARM64 خالصاً. يتداخل تقنياً مع KERNIX المؤجل، فلا نخلط المشاريع بدون قرار واضح.

## بوابات اتخاذ القرار وإيقاف تضييع الجهد

G0: Recovery أو AOT code extraction validated على **كود CarX الحقيقي**، لا sample dummy. إذا no، نوقف المسار native.
G1: Basic native-game-logic function actually executed under Android ARM64 with same result as allowed desktop reference, no emulation.
G2: Compatible Unity original scene assets and one user-owned real original scene loaded on Android.
G3: Actual game-specific rendered first frame, input, stable scene transition and vehicle simulation.
G4: Licence/provenance check and no publishing copyrighted game-derived binary or leaked code.

**لا APK فحص إضافي ولا ادّعاء نجاح إلا عند انتقال فعلي بين G0–G3.**

ملف هذه الدراسة نفسه فقط يثبت البحث والقرار الجديد، ولا يحمل ملفات ألعاب أو ناتج إعادة ترجمة.
