# RM11 WinCore V2.2.3 — إصلاح CODESET وتشخيص انهيار الذاكرة

- أثبتت تجربة V2.2.2 على الهاتف أن Wine NLS وWindows modules تُنسخ وتُفحص، لكن اختبار Win32 انتهى بـ Exit 134 وmarker=NO.
- تحذير `unrecognized charset 'Saturday'` سببه مرجّح ومحدّد في كود Box64 0.4.4: قيمة glibc `CODESET=14` تمرّ إلى Bionic، حيث 14 تعني `DAY_7`.
- تغيّر هذه النسخة الاستدعاء `nl_langinfo(14)` إلى `nl_langinfo(CODESET)` في مضيف Android، دون الادعاء بتوافق كامل لبقية قيم `nl_item`.
- خطأ `Pointer tag was truncated` عند `box64(free+0)` **لم يُحلّ بعد**. إصلاح اللغة مستقل ولا يضمن زوال انهيار الذاكرة. أزلنا تعطيل الحماية `allowNativeHeapPointerTagging=false` الموروث من V2.2.1، لأن تجربة الهاتف أثبتت أنه لا يعالج السبب؛ حماية Android الافتراضية مفعلة مجدداً.
- يرجى تجربة القسم 22 وإرسال صورة من نهاية التقرير؛ النجاح فقط إذا `Exit code: 0` و`Win32 marker verified: YES`.
- اختبارات الكود المحلية لا تُثبت نجاح Wine على Android. البناء الحقيقي يتم على GitHub.
