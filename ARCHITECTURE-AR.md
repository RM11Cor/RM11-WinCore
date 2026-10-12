# هندسة المنتج المخصصة لـ REDMAGIC 11 Pro (16GB/512GB)

## حدود الاستهداف

- تطبيق Android ARM64، للهاتف المستهدف فقط؛ الكود لا يقيّد الفحص قسريًا بناءً على اسم الجهاز حتى لا يمنع كشف موديل الجهاز الحقيقي إذا اختلف نص Build.MODEL.
- التشغيل المحلي هو الشرط الرئيسي. لا يوجد بث سحابي للألعاب أو اعتماد على كمبيوتر بعيد.
- النسخة الحالية: Device Probe + Official Launcher Installer Registry.
- النسخة اللاحقة: Wine + WoW64 + Box64 + DXVK/VKD3D عند توفر متطلبات Vulkan. هذه مكونات مخطط دمجها وليست مدمجة الآن.

## سلسلة التشغيل المتوقعة مستقبلاً

```text
UI / Game Library (Android)
          |
Game Profile & Installer Registry
          |
Wine Prefix/Container Manager
          |
Windows API translation: Wine / WoW64
x86_64 -> ARM64 execution: Box64
DirectX -> Vulkan: DXVK / VKD3D-Proton (if supported)
          |
Android input, sound, Vulkan loader, filesystem, network
          |
REDMAGIC 11 Pro (Snapdragon, Adreno, unified RAM)
```

## اتفاقية واجهة المحرك

`RuntimeGateway` في V1 يعيد `false` لحالة المحرك. لن تتحول أي عملية ربط ملف إلى «مثبت» إلا بعد أن يصبح لدينا محرك يعمل بالفعل ويتم التحقق من نتيجة عملية التثبيت.

## سياسة المشغّلات الرسمية

| المشغّل | مصدر ملف التثبيت الرسمي | العمل في النسخة الحالية |
|---|---|---|
| Steam | store.steampowered.com/about | فتح المصدر + ربط ملف |
| Ubisoft Connect | ubisoft.com/en-us/ubisoft-connect | فتح المصدر + ربط ملف |
| EA app | ea.com/ea-app | فتح المصدر + ربط ملف |
| Rockstar Games Launcher | rockstargames.com/downloads | فتح المصدر + ربط ملف |

بعد إضافة Wine، لكل مشغّل حاوية/بادئة Wine أو حاوية مشتركة عند الضرورة، مع دعم المصادقة والتحديث عبر التطبيق الرسمي نفسه وبدون اعتراض كلمات السر أو حقنها.

## تصنيفات حالة التوافق المستقبلي

1. **لم يُختبر**: ليس هناك بيانات فعلية للجهاز.
2. **يبدأ المشغّل**: نافذة المشغّل تظهر، لكن هذا لا يثبت أن الحساب أو اللعبة يعملان.
3. **تسجيل الدخول يعمل**: تحقق الدخول بدون تدخل بالمصادقة.
4. **اللعبة تبدأ**: الواجهة والرسوميات تعملان، لكن الاتصال قد يفشل.
5. **الأونلاين مقبول**: خادم اللعبة والحماية يسمحان، دون تعديل نظام مكافحة الغش.
6. **أداء مقاس**: قياس متوسط FPS، تقلبات frame-time، الرام وحالة الحرارة بعد جلسة تجريبية.

لا نزعم أن PUBG PC أو Battlefield 6 أو GTA Online أو The Crew Motorfest تعمل محليًا على هذا الهاتف إلا بعد اختبار وتشخيص موثوقين وموافقة الناشر حيث يلزم.

## ملاحظة مضادات الغش

- حماية بمستوى kernel / Secure Boot قد تتطلب نظام Windows فعليًا ومكونات غير متاحة في Android/Wine.
- توافق Steam / Proton على Linux **لا يساوي** توافقًا على Android تلقائيًا.
- لا نضمن دعم ألعاب تتطلب TPM / Secure Boot أو anti-cheat يعمل بنواة ويندوز.
