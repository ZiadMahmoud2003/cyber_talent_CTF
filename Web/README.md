# دليل أدوات اختراق الويب (Web Exploitation Tools Guide)
**المجال**: أمن تطبيقات الويب (Web Security) | **الملفات**: `fuzzer.py` و `solve.py` | **اللغة**: بايثون 3

---

## 1. ما هو هذا المجلد والملفات الموجودة به وما الغرض منها؟

مجلد `Web/` يحتوي على ترسانة متكاملة للتعامل مع تحديات الويب في مسابقات CTF:
1. **`fuzzer.py`**: أداة تخمين وفحص واكتشاف ثغرات احترافية وسريعة جداً بديلة لأدوات مثل ffuf و gobuster، ولكن مدمجة بالكامل بالبايثون مع دعم الجلسات والكوكيز وتعدد الخيوط (Multi-threading).
2. **`solve.py`**: قالب استغلال الويب لكتابة سكريبتات إرسال الحمولات (Payloads)، فك التوكنات (JWT)، إدارة الجلسات، وتحليل الردود بـ BeautifulSoup أو Regex.

---

## 2. كيف تم بناء أداة `fuzzer.py` وكيف تعمل برمجياً؟

- **التعامل مع الكلمات المفتاحية (`FUZZ` و `FUZ2Z`)**: يقوم البرنامج بقراءة قائمة الكلمات (Wordlist) واستبدال الرمز `FUZZ` أينما وجد (في الرابط، في معلمات GET، في جسم طلب POST، في الهيدر، أو في كائن JSON).
- **محرك الخيوط المتوازية (Multi-Threading Engine)**: مبني باستخدام `ThreadPoolExecutor` لإرسال عشرات الطلبات في الثانية دون تجميد النظام.
- **إدارة الجلسات والأخطاء**: يستخدم `requests.Session()` مع ميزات إعادة المحاولة التلقائية (Retry Adapter) عند حدوث مشاكل في الشبكة.
- **محرك الفلترة والتصفية (Filtering Engine)**:
  - استبعاد أو تضمين أكواد الحالة (`--mc 200,301` أو `-fc 404`).
  - فلترة الردود بناءً على عدد الكلمات (`-fw` أو `-mw`).
  - فلترة الردود بناءً على عدد الأسطر أو الحجم (`-fs` أو `-ms`).
  - فلترة الردود بناءً على نص أو تعبير نمطي (Regex) يظهر في الرد (`-fr` أو `-mr`).

---

## 3. كيف تستخدم `fuzzer.py` خطوة بخطوة مع أمثلة عملية؟

### أ. تخمين المسارات والمجلدات المخفية (Directory & File Busting):
```powershell
# ابحث في الرابط واستبعد صفحات الخطأ 404
python fuzzer.py -u "http://challenge.ctf.com:8080/FUZZ" -w wordlist.txt -fc 404
```

### ب. تخمين اسم ملف مع امتدادات محددة:
```powershell
python fuzzer.py -u "http://challenge.ctf.com:8080/FUZZ.php" -w wordlist.txt --mc 200,302
```

### ج. تخمين معاملات الـ GET (Parameter Discovery):
```powershell
python fuzzer.py -u "http://challenge.ctf.com:8080/index.php?FUZZ=test" -w params.txt -fc 404
```

### د. كسر وتسجيل الدخول عبر طلب POST (Login Brute Force):
```powershell
python fuzzer.py -u "http://challenge.ctf.com:8080/login" -w passwords.txt -m POST -p "username=admin&password=FUZZ" -fr "Welcome"
```

### هـ. إرسال حمولة في كائن JSON:
```powershell
python fuzzer.py -u "http://challenge.ctf.com:8080/api/check" -w users.txt -m POST --json '{"user":"FUZZ","role":"guest"}' -mr "admin"
```

### و. إضافة كوكي أو هيدر مخصص (مثل توكن الجلسة):
```powershell
python fuzzer.py -u "http://challenge.ctf.com:8080/admin/FUZZ" -w dirs.txt -H "Cookie: session=xyz123" -fc 403,404
```

---

## 4. كيف تستخدم قالب `solve.py`؟

افتح `Web/solve.py` واملأ الرابط:
```python
TARGET_URL = "http://challenge.ctf.com:8080"
```

إذا كنت تريد فحص الطلبات وتوجيهها عبر برنامج **Burp Suite**، فما عليك سوى تفعيل البروكسي في الكود:
```python
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}
```

ثم شغل السكريبت:
```powershell
python solve.py -t "http://challenge.ctf.com:8080"
```
يقوم السكريبت تلقائياً بإنشاء الجلسة، إرسال الحمولات، والبحث عن الفلاج بصيغة `FDC{...}` وطباعته في الشاشة فوراً.
