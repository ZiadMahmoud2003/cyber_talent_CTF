# دليل مساحة العمل الشامل لمسابقات السايبر والأمن السيبراني (CTF Blueprint)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Platform-CyberTalents%20%7C%20Global%20CTFs-red" alt="Platform">
  <img src="https://img.shields.io/badge/Framework-Modular%20CTF%20Toolkit-green" alt="Toolkit">
  <img src="https://img.shields.io/badge/Team-FDC-orange" alt="FDC Team">
</p>

**الإصدار**: 2.0 | **الفريق**: FDC Team | **المنصة المستهدفة**: CyberTalents & Global CTFs  
**اللغة**: العربية (شرح تفصيلي تقني احترافي)

---

## 📌 الفهرس العام

1. [نظرة عامة على المشروع وهيكل الفولدرات](#1-نظرة-عامة-على-المشروع-وهيكل-الفولدرات)
2. [التثبيت والإعداد السريع (Quick Setup)](#2-التثبيت-والإعداد-السريع-quick-setup)
3. [الأدوات المركزية المستقلة (`tools/`)](#3-الأدوات-المركزية-المستقلة-tools)
   - [أداة فك التشفيرات الشاملة `decoder.py` وملف `cipher.txt`](#أداة-فك-التشفيرات-الشاملة-toolsdecoderpy)
4. [دليل الامتثال وقفل الذكاء الاصطناعي (`docs/`)](#4-دليل-الامتثال-وقفل-الذكاء-الاصطناعي-docs)
5. [أدلة الاحتراف وخرائط الحلول (Cheat Sheets السريعة)](#5-أدلة-الاحتراف-وخرائط-الحلول-cheat-sheets-السريعة)
6. [شرح مجلدات التحديات الخمسة](#6-شرح-مجلدات-التحديات-الخمسة)
   - [مجلد التشفير (`Crypto/`)](#أ-مجلد-التشفير-crypto)
   - [مجلد الويب واختراق المواقع (`Web/`)](#ب-مجلد-الويب-واختراق-المواقع-web)
   - [مجلد استغلال الثغرات الثنائية (`Pwn/`)](#ج-مجلد-استغلال-الثغرات-الثنائية-pwn)
   - [مجلد الهندسة العكسية (`Reverse/`)](#د-مجلد-الهندسة-العكسية-reverse)
   - [مجلد التحقيق الجنائي الرقمي (`Forensics/`)](#هـ-مجلد-التحقيق-الجنائي-الرقمي-forensics)
7. [بروتوكول إدارة الوقت واستراتيجية حل المسابقة](#7-بروتوكول-إدارة-الوقت-واستراتيجية-حل-المسابقة)

---

## 1. نظرة عامة على المشروع وهيكل الفولدرات

تم تصميم وتجهيز هذه المساحة بالكامل لتكون منصة انطلاق احترافية، سريعة، وحاسمة أثناء خوض مسابقات الأمن السيبراني (CTF)، وتحديداً مسابقات منصة **CyberTalents** والمسابقات الإقليمية والدولية. تم تنظيم المستودع بشكل معياري (Modular) ليكون كل قسم مستقلاً بذاته ومزوداً بدليله الخاص وأدواته والشيت شيت التكتيكي.

### خريطة شجرة الملفات والمجلدات:

```text
cyber_talent_CTF/
├── .gitignore                                   # تصفية الملفات المؤقتة والكاش
├── requirements.txt                             # جميع المكتبات والاعتماديات البرمجية
├── README.md                                    # هذا الدليل الشامل باللغة العربية
├── HOW_TO_RUN.md                                # دليل التشغيل الشامل لجميع الأدوات بالتفصيل
├── run.ps1                                      # سكريبت التشغيل المباشر للبيئة الافتراضية (PowerShell)
├── run.bat                                      # سكريبت التشغيل المباشر للبيئة الافتراضية (CMD)
│
├── Crypto/                                      # مجلد تحديات التشفير
│   ├── README.md                                # دليل حل التشفير واستخدام solve.py
│   ├── Cryptography_CheatSheet.md               # شيت شيت شامل لكسر التشفير (RSA, AES, ECC, Attacks)
│   └── solve.py                                 # قالب الحل الجاهز للربط والكسر الرياضي
│
├── Web/                                         # مجلد تحديات الويب
│   ├── README.md                                # دليل اختراق الويب
│   ├── Web_Exploitation_CheatSheet.md          # شيت شيت شامل لاختراق الويب (أوامر وحقن وثغرات)
│   ├── fuzzer.py                                # أداة التخمين والفحص المتقدمة (Fuzzer متكامل)
│   └── solve.py                                 # قالب استغلال الويب وإدارة الجلسات
│
├── Pwn/                                         # مجلد تحديات استغلال الثغرات الثنائية
│   ├── README.md                                # دليل استغلال الثغرات الثنائية
│   ├── Binary_Exploitation_Pwn_CheatSheet.md    # شيت شيت استغلال الذاكرة (ROP, ret2libc, Format String)
│   ├── exploit.py                               # قالب الاستغلال المتقدم بـ Pwntools
│   └── solve.py                                 # قالب الحل القياسي للمسابقات
│
├── Reverse/                                     # مجلد تحديات الهندسة العكسية
│   ├── README.md                                # دليل الهندسة العكسية
│   ├── Reverse_Engineering_CheatSheet.md        # شيت شيت الهندسة العكسية (Ghidra, IDA, GDB, APK, Anti-Debug)
│   └── solve.py                                 # قالب الربط والتحليل بـ Z3 و Angr
│
├── Forensics/                                   # مجلد تحديات التحقيق الرقمي الجنائي
│   ├── README.md                                # دليل التحقيق الجنائي وفحص الأدلة
│   ├── Forensics_CheatSheet.md                  # شيت شيت التحقيق الجنائي (PCAP, Memory, Steganography, Disk)
│   └── solve.py                                 # أداة فحص الهيدر واستخراج النصوص والبيانات المخفية
│
├── tools/                                       # الأدوات المركزية المشتركة
│   ├── README.md                                # دليل استخدام أدوات المسابقة
│   ├── decoder.py                               # أقوى أداة محلية لفك التشفيرات والترميزات
│   └── cipher.txt                               # ملف إدخال النصوص المشفرة لتفكيكها فوراً
│
└── docs/                                        # التوثيق والسياسات الرسمية
    └── AI_Deactivation_and_Compliance_Guide.md  # الدليل الإلزامي لتعطيل الذكاء الاصطناعي للمسابقات الرسمية
```

---

## 2. التثبيت والإعداد والتشغيل السريع (Quick Setup & Run)

لتشغيل أي أداة أو سكريبت في المشروع، يمكنك مراجعة **[دليل التشغيل الشامل (HOW_TO_RUN.md)](HOW_TO_RUN.md)**.

### ⚡ التشغيل المباشر عبر سكريبتات التشغيل:
تم إعداد سكريبتات تشغيل تلقائية في الجذر تضمن تشغيل أي سكريبت داخل البيئة الافتراضية مع ضبط الترميز ومسارات الـ DLLs تلقائياً:

```powershell
# تشغيل أداة فك التشفير:
.\run.ps1 tools\decoder.py -i "SGVsbG8="

# تشغيل مخمن الويب Fuzzer:
.\run.ps1 Web\fuzzer.py -u "http://target/FUZZ" -w wordlist.txt -fc 404

# تشغيل محلل الهندسة العكسية:
.\run.ps1 Reverse\solve.py -f challenge_binary
```

> **ملاحظة**: لمستخدمي CMD، يمكنك استخدام `run.bat` بنفس الطريقة تماماً.

### 📦 التثبيت اليدوي (عند استنساخ المشروع على جهاز جديد):
```powershell
# 1. إنشاء وتفعيل البيئة الافتراضية
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. تثبيت كافة الاعتماديات
pip install -r requirements.txt
```

> **ملاحظة**: لمسار الـ Pwn واستغلال الثغرات الثنائية المتقدمة، يُوصى بالتشغيل داخل بيئة **Linux** أو **WSL2** لضمان عمل مكتبة `pwntools` بأقصى كفاءة.

---

## 3. الأدوات المركزية المستقلة (`tools/`)

### أداة فك التشفيرات الشاملة [`tools/decoder.py`](tools/decoder.py)

#### ما هي الأداة وما الغرض منها؟
هي أداة سطر أوامر بايثون حتمية (Deterministic) تم بناؤها من الصفر بدون أي اعتمادية على الذكاء الاصطناعي أو الإنترنت، مهمتها أخذ أي نص مشفر أو مرمّز (Ciphertext / Encoded string) وتجربة كل خوارزميات التشفير الكلاسيكية والترميزات المعروفة تلقائياً بضغطة زر واحدة واستخراج الفلاج (Flag) وتلوينه فوراً في الشاشة.

#### كيف تم بناؤها وكيف تعمل برمجياً؟
1. **التعرف والترميزات (Base Encodings)**: تقوم بمعالجة الحشو (Padding) التلقائي لفك:
   - Base64 القياسي و Base64url الآمن للروابط.
   - Base32 و Base16 (Hex).
   - Base85 و Ascii85 (سواء بالأقواس `<~ ~>` أو بدونها).
2. **الأنظمة العددية (Number Systems)**:
   - فك الـ Hexadecimal (بكل أشكاله: `0x`, `\x`, مسافات، أو بدون مسافات).
   - فك الـ Binary (نظام ثنائي 8-bit).
   - فك الـ Octal والـ Decimal (أرقام ASCII مفصولة بمسافات).
3. **التشفيرات الكلاسيكية (Classical Ciphers)**:
   - تجربة الـ ROT13 و ROT47 وعكس الحروف (Atbash).
   - تجربة جميع احتمالات إزاحة قيصر الـ 26 (Caesar Shifts 0..25) وفحص النصوص الناتجة.
4. **كسر تشفير XOR بمفتاح أحادي البايت (Single-Byte XOR Brute Force)**:
   - تقوم بتجربة الـ 256 مفتاحاً الممكنة (`0x00` إلى `0xFF`).
   - تقييم كل ناتج إحصائياً باستخدام تحليل تردد الحروف الإنجليزية (Chi-Squared Test) ومعامل التطابق (Index of Coincidence) لتمييز النص المقروء الحقيقي بدقة خوارزمية فائقة.
5. **الفك المتداخل التلقائي (Recursive Multi-Layer Pipeline)**:
   - في كثير من التحديات، يكون النص مشفراً بأكثر من طبقة (مثلاً: `Base64 -> Hex -> ROT13`). الأداة تقوم بتمرير النواتج بين الطبقات لاكتشاف الفلاج تلقائياً.

#### كيف تستخدم الأداة؟

1. **الطريقة الأسهل والأسرع أثناء المسابقة (قراءة الملف `tools/cipher.txt`)**:
   - ضع النص المشفر داخل [`tools/cipher.txt`](tools/cipher.txt) ثم شغل:
     ```powershell
     python tools/decoder.py
     ```
2. **تمرير نص مباشر في سطر الأوامر**:
   ```powershell
   python tools/decoder.py -i "4644437b6833785f643363306433647d"
   ```
3. **تحديد صيغة فلاج المسابقة للبحث السريع وتلوينه بالأخضر**:
   ```powershell
   python tools/decoder.py --flag "FLAG"
   ```
4. **تحديد ملف مخصص**:
   ```powershell
   python tools/decoder.py -f "Crypto/secret.enc"
   ```

---

## 4. دليل الامتثال وقفل الذكاء الاصطناعي (`docs/`)

### دليل الامتثال [`docs/AI_Deactivation_and_Compliance_Guide.md`](docs/AI_Deactivation_and_Compliance_Guide.md)

في المسابقات الرسمية والنهائيات الحضورية (On-site Finals) أو المسابقات الخاضعة لمراقبة الحكام (Proctors)، يُمنع منعاً باتاً استخدام الذكاء الاصطناعي (مثل GitHub Copilot، Cursor AI، Continue، Tabnine).

هذا الملف عبارة عن دليل تقني أمني متكامل أعده مسؤول التزام وأمن نظم (IT Security Compliance Officer) يوضح:
- خطوات تعطيل الذكاء الاصطناعي من الإعدادات في **VS Code** و **Cursor** و **JetBrains** و **Antigravity**.
- إيقاف الاقتراحات السطرية (`editor.inlineSuggest.enabled = false`).
- سد المنافذ والروابط عبر ملف الـ `hosts` وتوجيه عناوين OpenAI و Anthropic و Google إلى `127.0.0.1`.
- سكريبت تشخيصي موحد يقوم بفحص المنافذ المفتوحة والتطبيقات النشطة وتوليد تقرير رسمي يثبت للحكام نزاهة جهازك وخلوه من أي اتصال خارجي بنماذج الذكاء الاصطناعي.

---

## 5. أدلة الاحتراف وخرائط الحلول (Cheat Sheets السريعة)

تم تزويد بيئة العمل بخمسة ملفات مرجعية ضخمة مبنية وفق منهجية الحل التكتيكي:
> **«عندما تواجه [سيناريو/نمط معين] ⬅️ نفذ [الإجراء التالي] ⬅️ باستخدام [الأداة والأمر الدقيق]»**

| المجال | رابط الشيت شيت | أهم المحاور والتقنيات |
| :--- | :--- | :--- |
| **الويب (Web)** | 📄 [Web Exploitation CheatSheet](Web/Web_Exploitation_CheatSheet.md) | `ffuf`, `gobuster`, SQLi Bypass, NoSQL, SSTI RCE, LFI Wrappers, Command Injection |
| **التشفير (Crypto)** | 📄 [Cryptography CheatSheet](Crypto/Cryptography_CheatSheet.md) | RSA (Small e, Wiener, FactorDB), AES (ECB, CBC Padding Oracle), PRNG, Hashcat |
| **استغلال الثغرات (Pwn)** | 📄 [Binary Exploitation CheatSheet](Pwn/Binary_Exploitation_Pwn_CheatSheet.md) | NX/ASLR/Canary Bypass, Cyclic Offset, ret2win, Shellcode, ROP Chains, ret2libc, Format Strings |
| **الهندسة العكسية (Reverse)** | 📄 [Reverse Engineering CheatSheet](Reverse/Reverse_Engineering_CheatSheet.md) | Ghidra, IDA Pro, GDB+GEF, Anti-Debug Bypass, APK Decompilation, Z3 Solver, Angr |
| **التحقيق الجنائي (Forensics)** | 📄 [Forensics CheatSheet](Forensics/Forensics_CheatSheet.md) | Magic Bytes Repair, Binwalk, Steganography (Steghide, zsteg, LSB), PCAP Wireshark, Volatility 3 |

---

## 6. شرح مجلدات التحديات الخمسة

### أ. مجلد التشفير ([`Crypto/`](Crypto/))
- **دليل الاستخدام الكامل**: [`Crypto/README.md`](Crypto/README.md)
- **شيت شيت التشفير**: [`Crypto/Cryptography_CheatSheet.md`](Crypto/Cryptography_CheatSheet.md)
- **سكريبت الحل [`Crypto/solve.py`](Crypto/solve.py)**:
  - سكريبت بايثون مهيأ مسبقاً بمكتبات التشفير المتقدمة (`pycryptodome`, `sympy`, `hashlib`).
  - دوال جاهزة لمقلوب الضرب النمطي (`inverse`), تحويل الأرقام والنصوص الضخمة (`bytes_to_long`, `long_to_bytes`), وهجمات RSA و AES.
  ```powershell
  cd Crypto
  python solve.py -f challenge.txt
  python solve.py -d "ciphertext_here"
  ```

### ب. مجلد الويب واختراق المواقع ([`Web/`](Web/))
- **دليل الاستخدام الكامل**: [`Web/README.md`](Web/README.md)
- **شيت شيت الويب**: [`Web/Web_Exploitation_CheatSheet.md`](Web/Web_Exploitation_CheatSheet.md)
- **أداة الفحص والتخمين [`Web/fuzzer.py`](Web/fuzzer.py)**:
  - أداة فحص وتخمين مسارات ومعاملات فائقة السرعة تدعم تعدد المسارات (`ThreadPoolExecutor`).
  - دعم كلمة `FUZZ` في المسارات، الهيدرز، والمعاملات مع فلترة متقدمة للردود (`-fc`, `-fr`, `-fw`).
  ```powershell
  cd Web
  python fuzzer.py -u "http://target:8080/FUZZ" -w wordlist.txt -fc 404
  ```
- **سكريبت الحل [`Web/solve.py`](Web/solve.py)**: قالب استغلال الويب وإدارة الجلسات واستخراج الفلاج بـ BeautifulSoup و Regex.

### ج. مجلد استغلال الثغرات الثنائية ([`Pwn/`](Pwn/))
- **دليل الاستخدام الكامل**: [`Pwn/README.md`](Pwn/README.md)
- **شيت شيت استغلال الذاكرة**: [`Pwn/Binary_Exploitation_Pwn_CheatSheet.md`](Pwn/Binary_Exploitation_Pwn_CheatSheet.md)
- **سكريبت الاستغلال المتقدم [`Pwn/exploit.py`](Pwn/exploit.py)**:
  - سكريبت Pwntools متكامل مهيأ للتشغيل المحلي (Local Process)، والاتصال الخارجي (Remote Netcat)، ومصحح الأخطاء GDB.
  - حساب الإزاحة (Offset) تلقائياً بـ `cyclic`، وتسريب عناوين Libc، وبناء ROP Chains للحصول على Interactive Shell.
  ```powershell
  cd Pwn
  python exploit.py         # محلي
  python exploit.py REMOTE  # سيرفر المسابقة
  python exploit.py DEBUG   # تصحيح بـ GDB
  ```
- **سكريبت الحل الأساسي [`Pwn/solve.py`](Pwn/solve.py)**: قالب إضافي مبسط للتعامل مع تحديات الذاكرة البسيطة.

### د. مجلد الهندسة العكسية ([`Reverse/`](Reverse/))
- **دليل الاستخدام الكامل**: [`Reverse/README.md`](Reverse/README.md)
- **شيت شيت الهندسة العكسية**: [`Reverse/Reverse_Engineering_CheatSheet.md`](Reverse/Reverse_Engineering_CheatSheet.md)
- **سكريبت الحل والتحليل [`Reverse/solve.py`](Reverse/solve.py)**:
  - سكريبت مهيأ بمحلل القيود الرياضية **Z3 Solver** لحل معادلات الفحص واستخراج الفلاج آلياً.
  - كود مهيأ لمحرك التنفيذ الرمزي **Angr** لاكتشاف المسارات المؤدية لطباعة الفلاج.
  ```powershell
  cd Reverse
  python solve.py -f ./crackme
  ```

### هـ. مجلد التحقيق الجنائي الرقمي ([`Forensics/`](Forensics/))
- **دليل الاستخدام الكامل**: [`Forensics/README.md`](Forensics/README.md)
- **شيت شيت التحقيق الجنائي**: [`Forensics/Forensics_CheatSheet.md`](Forensics/Forensics_CheatSheet.md)
- **سكريبت الفحص والاستخراج [`Forensics/solve.py`](Forensics/solve.py)**:
  - فحص هيدر الملف (Magic Bytes Verification) لاكتشاف وتصحيح التلف أو تغيير الامتدادات.
  - استخراج نصوص ASCII/Unicode، قراءة بيانات EXIF من الصور، وفحص بتات LSB.
  - قراءة وتصفية ملفات PCAP بـ Scapy واستخراج نصوص وحزم البيانات.
  ```powershell
  cd Forensics
  python solve.py -f challenge.pcap
  python solve.py -f evidence.png
  ```

---

## 7. بروتوكول إدارة الوقت واستراتيجية حل المسابقة

1. **الدقائق العشر الأولى (Triage & Reconnaissance)**:
   - افتح كل التحديات المتاحة في المسابقة وصنفها من الأسهل للأصعب (Low-hanging fruit).
   - قم بتنزيل الملفات وضع كل ملف في مجلده المخصص (`Crypto`, `Web`, `Pwn`, `Reverse`, `Forensics`).
2. **استخدام أدوات الحسم السريع (Immediate Automation)**:
   - أي نص مشفر غير واضح ⬅️ ضعه في [`tools/cipher.txt`](tools/cipher.txt) وشغل `python tools/decoder.py`.
   - أي ملف غريب في الفورنسيك ⬅️ شغله فوراً بـ `python Forensics/solve.py -f file` لمعرفة نوعه وفحص هيدره.
   - أي فورم ويب يحتاج تخمين ⬅️ شغل `python Web/fuzzer.py` فوراً وتجنب إضاعة الوقت.
3. **الرجوع للشيت شيت عند التعطل**:
   - لا تبحث عشوائياً، افتح ملف الـ CheatSheet الخاص بالمجال وابحث عن السيناريو المناسب وانسخ الأمر مباشرة.
4. **توثيق الحلول (Write-up & Flag Submission)**:
   - بمجرد ظهور الفلاج، تأكد من الصيغة المطلوبة وسلمه فوراً في المنصة لكسب النقاط وبونص الوقت المبكر (Early Blood).
