# دليل أدوات الهندسة العكسية (Reverse Engineering Guide)
**المجال**: الهندسة العكسية وفك الشيفرات الثنائية (Reverse Engineering) | **الملف**: `solve.py` | **اللغة**: بايثون 3

---

## 1. ما هو هذا المجلد والملف وما الغرض منه؟

مجلد `Reverse/` مخصص لتحليل البرمجيات الثنائية والتطبيقات (ELF, PE, APK) لاكتشاف الشروط المنطقية التي تقود لطباعة الفلاج أو فحص الكلمات السرية (Crackmes / Keygens).

الملف `solve.py` يجمع قوة أقوى أدوات التحليل الرمزي والرياضي في بايثون:
- **محلل القيود الرياضية (Z3 SMT Solver)**: لحل المعادلات الرياضية المعقدة التي يطلبها البرنامج للتحقق من المدخلات.
- **محرك التنفيذ الرمزي (Angr Engine)**: لاستكشاف كل المسارات المحتملة للبرنامج تلقائياً حتى الوصول إلى حالة النجاح وتجنب حالة الفشل دون الحاجة لعكس الكود يدوياً!

---

## 2. كيف تم بناؤه وكيف يعمل برمجياً (Under The Hood)؟

1. **إدارة المكتبات المتخصصة**:
   - `z3`: لحل المتغيرات الرياضية ومطابقة بايتات الفلاج.
   - `angr` و `claripy`: لمحاكاة تشغيل البرنامج في الذاكرة مع إدخال رمزي (Symbolic Input).
   - `capstone`: لتفكيك الأكواد التنفيذية وفحص تعليمات الأسمبلي المباشرة.
2. **استراتيجيات الحل الذكي**:
   - إمكانية قراءة الباينري وتحديد عناوين دوال الفحص (`check_password`).
   - استخراج النصوص المطبوعة وعلامات الفلاج (`find_flag`).

---

## 3. كيف تستخدمه خطوة بخطوة أثناء المسابقة؟

### الاستخدام الأول: التنفيذ الرمزي التلقائي باستخدام `Angr`

إذا كان لديك برنامج يأخذ فلاج ويطبع "Correct!" أو "Wrong!":
1. افتح البرنامج في **Ghidra** أو **IDA** أو استخدم `objdump`.
2. حدد عنوان الطباعة الناجحة (مثلاً: `0x401234`) وعنوان الفشل (مثلاً: `0x401260`).
3. اكتب في دالة `solve()` في السكريبت:

```python
import angr
import claripy

proj = angr.Project("./crackme", auto_load_libs=False)

# تعريف فلاج رمزي بطول 32 حرف مثلاً
flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(32)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])

state = proj.factory.full_init_state(
    args=["./crackme"],
    stdin=flag
)

# تقييد الحروف لتكون حروفاً مقروءة ASCII فقط
for c in flag_chars:
    state.solver.add(c >= 0x20, c <= 0x7E)

simgr = proj.factory.simulation_manager(state)

# حدد عناوين النجاح والفشل
FIND_ADDR  = 0x401234  # عنوان رسالة النجاح
AVOID_ADDR = 0x401260  # عنوان رسالة الخطأ

simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    solution_state = simgr.found[0]
    print("[+] Flag Found:", solution_state.solver.eval(flag, cast_to=bytes))
```

### الاستخدام الثاني: حل معادلات التحقق باستخدام `Z3 Solver`

عندما يقوم البرنامج بعمليات مثل `flag[0] ^ 0x5a == 0x33` و `flag[1] + flag[2] == 180`:
```python
from z3 import *

s = Solver()
flag = [BitVec(f"f_{i}", 8) for i in range(20)]

# أضف قيود البرنامج هنا:
s.add(flag[0] ^ 0x5A == 0x33)
s.add(flag[1] + flag[2] == 180)
# صيغة الفلاج المعروفة: FDC{
s.add(flag[0] == ord('F'))
s.add(flag[1] == ord('D'))
s.add(flag[2] == ord('C'))
s.add(flag[3] == ord('{'))
s.add(flag[19] == ord('}'))

if s.check() == sat:
    m = s.model()
    result = bytes([m[flag[i]].as_long() for i in range(20)])
    print("[+] Flag:", result.decode())
```

### تشغيل السكريبت:
```powershell
cd Reverse
python solve.py -f ./crackme
```
