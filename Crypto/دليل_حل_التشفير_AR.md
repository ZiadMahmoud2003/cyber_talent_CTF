# دليل حل تحديات التشفير (Cryptography Solver Guide)
**المجال**: التشفير وحماية البيانات | **الملف البرمجي**: `solve.py` | **اللغة**: بايثون 3

---

## 1. ما هو هذا المجلد والملف وما الغرض منه؟

مجلد `Crypto/` مخصص بالكامل لحل تحديات التشفير في مسابقات CTF.
الملف `solve.py` هو قالب عمل تفاعلي ذكي وسريع مجهز بأهم خوارزميات التشفير الرياضية والحديثة، صُمم ليوفر عليك كتابة أكواد الاتصال والتحويل الرياضي من الصفر أثناء وقت المسابقة الضيق.

---

## 2. كيف تم بناؤه وكيف يعمل برمجياً (Under The Hood)؟

تم بناء الكود ليعتمد على بنية معيارية تضم:
1. **استيراد المكتبات الأساسية (Imports Architecture)**:
   - استيراد `hashlib` و `base64` و `binascii` و `struct`.
   - استيراد آمن مع معالجة الأخطاء (`try/except`) لمكتبات:
     - `pycryptodome`: لتشفير وفك تشفير AES، DES، و RSA وحساب الدوال الرياضية الكبرى.
     - `sympy`: للتحليل إلى العوامل الأولية السريعة (`factorint`, `isprime`).
     - `requests` و `pwntools`: للتعامل مع التحديات التي تتطلب اتصالات عبر Socket أو HTTP.
2. **دوال المساعدة الرياضية الجاهزة (Helper Functions)**:
   - `read_file(path)`: قراءة الملفات الثنائية (Binary) بدقة دون تلف البايتات.
   - `xor(data, key)`: تنفيذ تشفير وفك تشفير الـ XOR بمفتاح متغير الطول (Repeating-key XOR).
   - `rot13(text)` و `brute_caesar(ciphertext)`: تجربة جميع إزاحات قيصر وتوليد الـ 26 ناتجاً دفعة واحدة.
   - `rsa_decrypt(c, d, n)`: تنفيذ فك تشفير RSA القياسي $m = c^d \pmod n$ ثم تحويل الناتج من رقم كبير إلى بايتات قابلة للقراءة بواسطة `long_to_bytes`.
   - `find_flag(text)`: البحث التلقائي عن الفلاج بالصيغة المحددة (مثل `FDC{...}`).

---

## 3. ماذا يفعل بالتفصيل (Features & Capabilities)؟

- **التعامل مع مختلف مصادر الدخل**: قراءة المعطيات من ملف محلي، أو من سطر الأوامر مباشرة، أو الاتصال بسيرفر المسابقة.
- **جاهزية قوالب الهجمات الشهيرة**:
  - كسر RSA عند وجود $e$ صغير ($e = 3$) بهجوم الجذر التكعيبي.
  - كسر RSA بهجوم فاكتور دي بي (FactorDB API) لتحليل $n$ إلى $p$ و $q$.
  - كسر RSA بهجوم وينر (Wiener's Attack) عند استخدام مفتاح فك تشفير خاص صغير $d < \frac{1}{3} n^{1/4}$.
  - فك تشفير أنماط AES المختلفة (ECB, CBC, CTR).

---

## 4. كيف تستعمله خطوة بخطوة أثناء المسابقة؟

### الخطوة 1: ضبط الإعدادات السريعة في رأس الملف
افتح `Crypto/solve.py` وحدث المتغيرات في البداية:
```python
TARGET_URL   = "http://challenge.ctf.com:1337"
FLAG_FORMAT  = r"FDC\{.*?\}"
```

### الخطوة 2: تشغيل السكريبت من سطر الأوامر (Terminal)

- **لقراءة ملف معطى في التحدي (مثل ciphertext.txt)**:
  ```powershell
  python solve.py -f challenge.txt
  ```

- **لتمرير النص المشفر مباشرة في الأمر**:
  ```powershell
  python solve.py -d "7f654b3a21..."
  ```

- **للاتصال بسيرفر تحدي مباشر**:
  ```powershell
  python solve.py -t "http://challenge.ctf.com:8080"
  ```

### نماذج جاهزة يمكن تفعيلها بداخل دالة `solve(args)`:

#### أ. فك تشفير RSA إذا أعطاك $n$ و $e$ و $c$ ووجدت $p$ و $q$:
```python
p = ...
q = ...
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m).decode(errors="replace"))
```

#### ب. فك تشفير AES-ECB إذا كان معك المفتاح:
```python
key = b"my_secret_key_16"
cipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(data), AES.block_size)
print(plaintext.decode(errors="replace"))
```
