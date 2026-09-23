# CTF General Tools (أدوات المسابقة العامة)

مجلد مخصص للأدوات البرمجية المستقلة المشتركة لجميع مجالات المسابقة.

---

## 🛠️ أداة فك التشفيرات الشاملة (`decoder.py`)

أداة سريعة ومحلية 100% مبنية بالكامل بلغة Python (بدون استخدام الذكاء الاصطناعي وبدون اتصال بالإنترنت)، مصممة لفك التشفيرات والترميزات الشهيرة تلقائياً واستخراج الأعلام (Flags) فوراً.

### المميزات:
- **Base Encodings**: Base16, Base32, Base58, Base64, Base85, Ascii85.
- **Numeric & Text Encodings**: Hex, Binary (8-bit), Octal, Decimal ASCII, URL encoding, Unicode escapes, Morse code.
- **Substitution Ciphers**: Caesar (all 26 shifts), ROT13, ROT47, Atbash, Rail Fence (2-6 rails).
- **XOR Analysis**: Single-byte XOR brute-force (255 keys) مع التحليل الإحصائي للإنجليزية.
- **Multi-Layer Chains**: فك تشفير السلاسل المتداخلة (مثل Base64 -> Hex).
- **Flag Extraction**: البحث الآلي عن نمط الفلاج الافتراضي `FDC{...}` أو أي بادئة مخصصة.

### أمثلة الاستخدام:

```powershell
# 1. القراءة التلقائية من ملف tools/cipher.txt
python tools/decoder.py

# 2. تمرير نص مشفر مباشرة من سطر الأوامر
python tools/decoder.py -i "RkRDe3Rlc3RfZmw0Z30="

# 3. قراءة ملف محدد
python tools/decoder.py -f path/to/challenge.txt

# 4. تحديد بادئة فلاج مخصصة (مثلاً فلاج مسابقة CyberTalents)
python tools/decoder.py -i "..." --flag FLAG
```
