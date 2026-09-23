# دليل التشغيل الشامل لمساحة العمل (HOW TO RUN GUIDE)

**المشروع**: CyberTalents & Global CTFs Workspace  
**البيئة**: Python 3.10+ / Virtual Environment (`.venv`)  
**أنظمة التشغيل**: Windows (PowerShell / CMD) & Linux / WSL2  

---

## 📌 الفهرس
1. [طرق التشغيل السريعة (3 طرق مرنة)](#1-طرق-التشغيل-السريعة)
2. [سكريبتات التشغيل بنقرة واحدة (`run.ps1` و `run.bat`)](#2-أسهل-طريقة-سكريبتات-التشغيل-runps1-و-runbat)
3. [دليل أوامر التشغيل لكل أداة وقسم](#3-دليل-أوامر-التشغيل-لكل-أداة-وقسم)
   - [أ. أداة فك التشفيرات الشاملة (`tools/decoder.py`)](#أ-أداة-فك-التشفيرات-الشاملة-toolsdecoderpy)
   - [ب. قسم الويب (`Web/fuzzer.py` و `Web/solve.py`)](#ب-قسم-الويب-web)
   - [ج. قسم الهندسة العكسية (`Reverse/solve.py`)](#ج-قسم-الهندسة-العكسية-reverse)
   - [د. قسم التشفير (`Crypto/solve.py`)](#د-قسم-التشفير-crypto)
   - [هـ. قسم التحقيق الرقمي الجنائي (`Forensics/solve.py`)](#هـ-قسم-التحقيق-الرقمي-الجنائي-forensics)
   - [و. قسم استغلال الثغرات الثنائية (`Pwn/exploit.py`)](#و-قسم-استغلال-الثغرات-الثنائية-pwn)
4. [تهيئة المحرر تلقائياً (VS Code / Antigravity IDE)](#4-تهيئة-المحرر-تلقائياً)
5. [حلول المشاكل الشائعة (Troubleshooting)](#5-حلول-المشاكل-الشائعة-troubleshooting)

---

## 1. طرق التشغيل السريعة

تم تثبيت كافة المكتبات (`pwntools`, `angr`, `z3-solver`, `capstone`, `scapy`, `requests`, `pycryptodome`، إلخ) داخل مجلد البيئة الافتراضية **`.venv`**. يمكنك استخدام أي من الطرق الثلاث التالية:

### 🔹 الطريقة الأولى: سكريبت التشغيل المباشر (موصى بها جداً ⚡)
لا تحتاج لتفعيل أو إلغاء تفعيل البيئة يدbox، فقط استخدم سكريبت التشغيل:
```powershell
# في PowerShell:
.\run.ps1 <اسم الملف> [المعاملات]

# في CMD:
run.bat <اسم الملف> [المعاملات]
```

---

### 🔹 الطريقة الثانية: تفعيل البيئة داخل موجه الأوامر (Terminal Activation)

#### في PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```
> ⚠️ **إذا ظهرت رسالة خطأ حول سياسة تنفيذ السكريبتات (ExecutionPolicy)**، نفذ الأمر التالي مرة واحدة في الجلسة:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> ```
> ثم أعد تشغيل `.\.venv\Scripts\Activate.ps1`.

#### في Command Prompt (CMD):
```cmd
.\.venv\Scripts\activate.bat
```

بمجرد تفعيل البيئة سيظهر رمز `(.venv)` في بداية السطر، ويمكنك حينها استخدام الأمر العادي:
```powershell
python tools/decoder.py
python Web/fuzzer.py --help
```

---

### 🔹 الطريقة الثالثة: استدعاء مفسر بايثون الخاص بالبيئة مباشرة
```powershell
.\.venv\Scripts\python.exe tools\decoder.py
.\.venv\Scripts\python.exe Reverse\solve.py -f crackme
```

---

## 2. أسهل طريقة: سكريبتات التشغيل (`run.ps1` و `run.bat`)

تم تزويد المستودع بملفين تنفيذيين في الجذر يضمنان تشغيل أي أداة مع ضبط ترميز النصوص (UTF-8) ومسارات الـ DLLs تلقائياً دون أي تعقيد:

| النظام / الصدفة | الأمر السريع | مثال |
| :--- | :--- | :--- |
| **PowerShell** | `.\run.ps1 <file.py> [args]` | `.\run.ps1 tools\decoder.py -i "SGVsbG8="` |
| **CMD / Batch** | `run.bat <file.py> [args]` | `run.bat Web\fuzzer.py -u "http://target/FUZZ" -w wordlist.txt` |

---

## 3. دليل أوامر التشغيل لكل أداة وقسم

### أ. أداة فك التشفيرات الشاملة (`tools/decoder.py`)
الأداة مجهزة لفك Base16..85 والتشفيرات الكلاسيكية و Single-byte XOR وسلاسل التشفير المتداخلة واستخراج الأعلام.

```powershell
# 1. القراءة التلقائية من ملف tools/cipher.txt (ضع النص المشفر بداخله)
.\run.ps1 tools\decoder.py

# 2. تمرير نص مشفر فوري من سطر الأوامر:
.\run.ps1 tools\decoder.py -i "4644437b6833785f666c34677d"

# 3. قراءة ملف مخصص:
.\run.ps1 tools\decoder.py -f "Crypto\secret.txt"

# 4. تحديد صيغة الفلاج المخصصة (افتراضياً تبحث عن FDC):
.\run.ps1 tools\decoder.py -i "..." --flag "FLAG"
```

---

### ب. قسم الويب (`Web/`)

#### 1. فاحص ومخمن الويب المتقدم (`Web/fuzzer.py`):
```powershell
# تخمين مسارات موقع واستبعاد أخطاء 404:
.\run.ps1 Web\fuzzer.py -u "http://target:8080/FUZZ" -w wordlist.txt -fc 404

# تخمين نموذج تسجيل دخول POST واستخراج الردود التي لا تحتوي "Invalid":
.\run.ps1 Web\fuzzer.py -u "http://target/login" -w passwords.txt -m POST -p "username=admin&password=FUZZ" -fr "Invalid"

# فحص معاملات JSON:
.\run.ps1 Web\fuzzer.py -u "http://target/api/user" -w ids.txt -m POST --json '{"id": "FUZZ"}' --mc 200

# توجيه الطلبات عبر Burp Suite للتحليل:
.\run.ps1 Web\fuzzer.py -u "http://target/FUZZ" -w dirs.txt --proxy "http://127.0.0.1:8080"
```

#### 2. قالب استغلال الويب (`Web/solve.py`):
```powershell
.\run.ps1 Web\solve.py -t "http://challenge.ctf.com:8080"
```

---

### ج. قسم الهندسة العكسية (`Reverse/`)

سكريبت [`Reverse/solve.py`](Reverse/solve.py) مجهز بمحرك التفكيك **Capstone**، ومحلل القيود الرياضية **Z3 Solver**، ومحرك التحليل الرمزي **Angr / Claripy**:

```powershell
# فحص ملف ثنائي، تفكيك كوده، واستخراج نصوصه القابلة للقراءة:
.\run.ps1 Reverse\solve.py -f "path\to\crackme.exe"

# تمرير نص أو معطيات مباشرة:
.\run.ps1 Reverse\solve.py -d "test_input"
```

---

### د. قسم التشفير (`Crypto/`)

سكريبت [`Crypto/solve.py`](Crypto/solve.py) مجهز بمكتبات `pycryptodome` و `sympy` لحساب دوال RSA و AES و Galois Fields:

```powershell
# حل تحدي بقراءة ملف معطيات التشفير:
.\run.ps1 Crypto\solve.py -f "challenge.txt"

# فك تشفير نص مباشر:
.\run.ps1 Crypto\solve.py -d "7f654b3a21..."

# الاتصال بسيرفر مسابقة عبر Socket/HTTP:
.\run.ps1 Crypto\solve.py -t "challenge.ctf.com:1337"
```

---

### هـ. قسم التحقيق الرقمي الجنائي (`Forensics/`)

سكريبت [`Forensics/solve.py`](Forensics/solve.py) مجهز بفحص الهيدر (`python-magic`)، تحليل الصور وبيانات EXIF و LSB (`Pillow`)، وتحليل حزم الشبكة (`scapy`):

```powershell
# فحص ملف مشبوه والتحقق من صحة بصمته وهيدره (Magic Bytes):
.\run.ps1 Forensics\solve.py -f "evidence.bin"

# استخراج بيانات EXIF والبتات المخفية (LSB) من صورة:
.\run.ps1 Forensics\solve.py -f "stego.png"

# تحليل ملف التقاط الشبكة وتصفية الحزم:
.\run.ps1 Forensics\solve.py -f "capture.pcap"
```

---

### و. قسم استغلال الثغرات الثنائية (`Pwn/`)

سكريبت [`Pwn/exploit.py`](Pwn/exploit.py) مجهز بمكتبة **Pwntools** لدعم ROP Chains وحساب الإزاحة cyclic:

```powershell
# التشغيل محلياً:
.\run.ps1 Pwn\exploit.py

# التشغيل والاتصال المباشر بسيرفر المسابقة:
.\run.ps1 Pwn\exploit.py REMOTE

# التشغيل تحت مصحح الأخطاء GDB:
.\run.ps1 Pwn\exploit.py DEBUG
```
> 💡 *ملاحظة*: مكتبة `pwntools` تعمل بكامل قدراتها التفاعلية المتقدمة وتصحيح GDB داخل بيئات Linux / WSL.

---

## 4. تهيئة المحرر تلقائياً

تم تضمين ملف الإعدادات [`.vscode/settings.json`](.vscode/settings.json) لضبط المحرر فور فتحه:
- يختار تلقائياً بيئة `.venv` كمفسر افتراضي (Python Interpreter).
- يضبط ترميز المخرجات في التيرمينال الداخلي على `UTF-8`.
- لن تحتاج إلى إعادة ضبط المفسر يدوياً في كل مرة.

---

## 5. حلول المشاكل الشائعة (Troubleshooting)

### ❓ خطأ: `ExecutionPolicy` في PowerShell
**الحل**:
نفذ الأمر التالي في نافذة الـ PowerShell الحالية:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### ❓ خطأ: الحروف العربية أو الرموز تظهر كعلامات استفهام أو `UnicodeEncodeError`
**الحل**:
تم ضبط `PYTHONUTF8=1` و `PYTHONIOENCODING=utf-8` تلقائياً داخل سكريبتات `run.ps1` و `run.bat`. إذا كنت تشغل بايثون يدوياً، فقط نفذ:
```powershell
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
```

### ❓ خطأ: `ImportError: DLL load failed while importing rustylib` في مكتبة `angr`
**الحل**:
تم حل هذه المشكلة نهائياً بإضافة ملف `sitecustomize.py` داخل البيئة الافتراضية لتحميل مكتبات `libz3.dll` تلقائياً، وتعمل مكتبة `angr` الآن بسلاسة تامة.
