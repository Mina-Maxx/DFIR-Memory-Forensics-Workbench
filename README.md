# DFIR Memory Forensics Workbench (V2 Architecture)

تطبيق ويب جنائي متكامل ومستقل مبني بلغة بايثون وجافاسكربت الصافية بنسبة 100% لفحص وتحليل الذاكرة العشوائية (Memory Forensics) بالاعتماد على إطار العمل الجنائي **Volatility 3 Framework**.

---

> [!IMPORTANT]
> **المرجع الهندسي والتنفيذي الشامل (Master Engineering Blueprint):**
> تم توثيق المنصة ومعماريتها البرمجية ومحركاتها الجنائية بالكامل في وثيقة مرجعية شاملة ومفصلة:
> 📖 **[دليل المخطط الهندسي والمعماري الشامل (DFIR_PLATFORM_MASTER_DOCUMENTATION.md)](DFIR_PLATFORM_MASTER_DOCUMENTATION.md)**  
> يحتوي هذا الدليل على شرح تشريحي دقيق لكل سطر برمجي، ومخططات DDL لقاعدة البيانات، ومعادلات محرك الجراف الرياضي بالـ SVG، ودليل إعادة بناء الأداة بالكامل من الصفر حتى بالواجهة (UI).

---

## 🚀 المميزات الرئيسية للمنصة (Core Features)

1. **بنية برمجية مستقلة بالكامل (Pure-Python Standalone Backend):**
   - تحرر تام من مكتبات واجهات سطح المكتب الثقيلة (`PySide6` / `Qt`). يعمل الخادم بنمط ويب خالص باستخدام `Flask` و `Threading`.
   - خفيف، فائق السرعة، ويدعم العمل محلياً أو عبر شبكة المختبر الجنائي من خلال متصفحات الويب الحديثة (Chrome, Edge, Firefox).

2. **التيليمتري اللحظي الفوري (Real-Time SSE Telemetry):**
   - استبدال الاستطلاع الدوري (`Polling`) بقناة بث حي عبر Server-Sent Events (`/api/stream`) لعرض تقدم الإضافات وحساب الهاشات في طرفية جنائية داكنة حية.

3. **الرسم البياني الجنائي التفاعلي (Interactive SVG Force-Directed Graph):**
   - محرك فيزياء رياضي مدمج مكتوب بلغة Vanilla JS بدون D3 يولد شجرة العمليات الكاملة وروابط الأبوة والتفريخ (`PPID -> PID` `spawns`)، واتصالات المقابس الشبكية، ومناطق الذاكرة المحقونة، ومطابقات YARA.
   - يدعم 4 تخطيطات طوبولوجية: (Force-Directed, Hierarchical Tree, Concentric Orbital, Risk Severity Clusters).

4. **مساحة عمل إدارة النتائج الجنائية (Findings Workspace):**
   - دورة حياة كاملة للتهديدات بـ 6 حالات تدقيقية (`detected`, `triaged`, `investigating`, `confirmed`, `false_positive`, `closed`).
   - سجل تدقيق للملاحظات الفنية للمحقق مع ربط مباشر بمعرفات مصفوفة **MITRE ATT&CK**.

5. **درج الفحص البؤري المتعمق للعملية (Process Focus Mode Drawer):**
   - فحص تشريحي للعملية المشبوهة عبر 6 تبويبات جنائية: (لماذا مشبوهة؟، بيانات العملية، شجرة الأنساب، مقابس الشبكة، حقن الذاكرة، موديولات DLL).

6. **محركات التحقيق الجنائي المتقدمة:**
   - **Cross-Plugin Correlation Engine**: ربط نتائج العمليات (`pslist`, `psscan`, `pstree`) مع الشبكة والذاكرة لكشف تقنيات التخفي و **DKOM** (مثل إلغاء ارتباط العملية من `ActiveProcessLinks`).
   - **Risk Scoring & Heuristic Engine (0-100)**: تقييم العمليات المشبوهة عبر مصفوفة أوزان وقواعد قابلة للتخصيص.
   - **Threat Hunter & ReDoS-Guarded IOC Engine**: استخراج مؤشرات الاختراق وتصديرها بصيغة **STIX 2.1**.
   - **Forensic Timeline**: تسلسل زمني دقيق لإنشاء العمليات والاتصالات.
   - **Snapshot Diffing**: مقارنة ذاكرتين عشوائيتين (Baseline vs Incident) لرصد مسارات التسلل والتغيرات.
   - **Arabic RTL Forensic Reports**: توليد تقارير جنائية باللغة العربية مصممة للاسترشاد بمبادئ معايير **ISO/IEC 27037** لتوثيق الأدلة الرقمية وسلسلة الحيازة مع عزل النصوص التقنية الإنجليزية وتطهير تصدير CSV ضد هجمات Formula Injection.

---

## 📁 هيكلية المشروع (Project Architecture)

```
DFIR-Web-App/
├── app.py                             # خادم Flask ومسارات REST و SSE
├── requirements.txt                   # الحزم والاعتماديات
├── run.bat                            # ملف الإطلاق الفوري بنقرة واحدة
├── DFIR_PLATFORM_MASTER_DOCUMENTATION.md # المرجع الهندسي الشامل لبناء المنصة
├── backend/                           # معمارية V2: نماذج الدومين، الخدمات، والمحركات
│   ├── models/                        # نماذج البيانات المهيكلة (Case, Evidence, Finding, ...)
│   ├── services/                      # طبقة الخدمات وتنسيق المنطق الجنائي
│   ├── engines/                       # المحركات الموديلار (Correlation, Risk, Graph, ...)
│   └── infrastructure/                # قاعدة بيانات SQLite (WAL) ونظام التيليمتري
├── core/                              # المحركات الجنائية الأساسية وطبقة التوافقية
├── forensics/                         # محول Volatility 3 واستكشاف الإضافات
├── data/                              # قوالب الـ Playbooks وأوزان القواعد
├── templates/index.html               # واجهة المستخدم الأحادية (Cyber Forensic Cockpit)
├── static/                            # أنماط CSS المظلمة ومحرك الجراف في app.js
└── workspace/                         # مساحة العمل والأدلة والتقارير المصدرة
```

---

## 📥 طريقة التنزيل (Download & Clone)

### الخيار 1: عبر Git (مستحسن)
افتح موجه الأوامر (Terminal / Command Prompt) ونفذ الأمر التالي:
```bash
git clone https://github.com/Mina-Maxx/DFIR-Memory-Forensics-Workbench.git
cd DFIR-Memory-Forensics-Workbench
```

### الخيار 2: كملف مضغوط (ZIP)
1. توجه إلى صفحة المستودع على GitHub: [DFIR-Memory-Forensics-Workbench](https://github.com/Mina-Maxx/DFIR-Memory-Forensics-Workbench).
2. اضغط على الزر الأخضر **`< > Code`** ثم اختر **Download ZIP**.
3. قم بفك ضغط الملف في مجلد التحقيقات الخاص بك وافتح المجلد.

---

## ⚙️ خطوات التثبيت بالتفصيل (Step-by-Step Installation)

### 📌 المتطلبات الأساسية (Prerequisites):
* **Python 3.10 أو أحدث** مثبت في النظام.  
  *(تأكد من اختيار `Add python.exe to PATH` أثناء التثبيت على ويندوز)*
* مدير الحزم **pip** ومحرر البيئة الافتراضية **venv**.

---

### 1️⃣ التثبيت على نظام ويندوز (Windows):

1. **افتح موجه الأوامر (CMD أو PowerShell) كمسؤول داخل مجلد المشروع:**
   ```cmd
   cd path\to\DFIR-Memory-Forensics-Workbench
   ```

2. **أنشئ بيئة افتراضية مستقلة (Virtual Environment):**
   ```cmd
   python -m venv venv
   ```

3. **فعّل البيئة الافتراضية:**
   ```cmd
   venv\Scripts\activate
   ```

4. **قم بتثبيت حزم بايثون المطلوبة:**
   ```cmd
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
   *(الحزم تشمل: `flask`, `volatility3`, `pyyaml`, `yara-python`)*

---

### 2️⃣ التثبيت على نظام لينكس / ماك (Linux & macOS):
*(يدعم: Kali Linux, Ubuntu, Debian, SANS SIFT Workstation, REMnux, Fedora, Arch)*

1. **تثبيت متطلبات النظام الأساسية عبر مدير الحزم:**
   - **في أنظمة Debian / Ubuntu / Kali / SIFT:**
     ```bash
     sudo apt update
     sudo apt install -y python3 python3-pip python3-venv python3-dev build-essential libyara-dev git
     ```
   - **في أنظمة Fedora / RedHat:**
     ```bash
     sudo dnf install -y python3 python3-pip python3-devel gcc git
     ```
   - **في أنظمة Arch Linux:**
     ```bash
     sudo pacman -S python python-pip base-devel git
     ```

2. **إنشاء البيئة الافتراضية وتفعيلها:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **تثبيت حزم بايثون والاعتماديات:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **منح صلاحيات التنفيذ لسكربت التشغيل:**
   ```bash
   chmod +x run.sh
   ```

---

### 3️⃣ التثبيت والتشغيل عبر Docker (بدون أي متطلبات سوى Docker):

إذا كنت لا ترغب في تثبيت بايثون وحزمه محلياً، يمكنك بناء وتشغيل الحاوية الجاهزة:
```bash
docker compose up --build -d
```

---

### 🔍 (اختياري ولكن موصى به) إعداد رموز النواة لويندوز (Volatility 3 Symbols):
لكي يعمل إطار عمل **Volatility 3** بأعلى دقة في قراءة هياكل نواة ويندوز المعقدة:
* يقوم Volatility 3 بتنزيل الرموز تلقائياً عبر الإنترنت عند توفر اتصال.
* للعمل في مختبرات التحقيق المعزولة عن الإنترنت (**Air-Gapped Forensic Labs**):  
  يمكنك تنزيل حزمة الرموز الجاهزة من مستودع [volatility3-symbols](https://github.com/volatilityfoundation/volatility3-symbols) ونقلها إلى مجلد الرموز الخاص بالحزمة `volatility3/symbols/windows`.

---

## 🚀 طريقة التشغيل عبر الأنظمة (Cross-Platform Execution)

المنصة متوافقة بنسبة 100% مع أنظمة **Windows** و **Linux** (بما في ذلك توزيعات التحقيق الجنائي مثل Kali Linux و SANS SIFT و REMnux و Ubuntu و Debian) بالإضافة إلى **Docker**.

### 1. على نظام ويندوز (Windows):
* **بنقرة زر واحدة:** اضغط مرتين على الملف `run.bat`
* **أو عبر موجه الأوامر:**
  ```cmd
  python app.py
  ```

### 2. على نظام لينكس / ماك (Linux / macOS):
* **عبر سكربت التشغيل:**
  ```bash
  chmod +x run.sh
  ./run.sh
  ```
* **أو يدوياً عبر موجه الأوامر:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  python3 app.py
  ```
  *(في السيرفرات السحابية ومختبرات التحقيق عن بعد، يمكنك تمرير `HOST=0.0.0.0 PORT=8000 python3 app.py` لإتاحة الوصول للواجهة عبر الشبكة)*

### 3. عبر الحاويات (Docker & Docker Compose):
تشغيل المنصة في حاوية Linux معزولة بضغطة زر واحدة:
```bash
docker compose up -d
```
ثم افتح متصفحك على: `http://localhost:8000`.

### 🔒 متغيرات البيئة والأمان (Security & Environment Variables):
يمكنك تخصيص إعدادات الأمان والتحكم عبر ملف `.env` (راجع النموذج التوضيحي [.env.example](.env.example)):
- **`DFIR_SECRET_KEY`**: مفتاح تشفير جلسات Flask. إذا لم يُحدد، يتم توليد مفتاح عشوائي عالي الأمان (32-bytes CSPRNG) تلقائياً عند الإقلاع.
- **`DFIR_API_KEY`**: مفتاح اختياري لحماية مسارات REST API التعديلية والتنفيذية (`/api/upload`, `/api/cases/<id>` [DELETE], `/api/plugins/run`, إلخ). في الاستخدام المحلي تركه فارغاً يفعّل التمرير التلقائي السلس، بينما في بيئات الشبكة والسيرفرات يتطلب تمرير المفتاح في ترويسة `X-API-Key` أو `Authorization: Bearer <key>`.
- **`DFIR_MAX_UPLOAD_MB`**: الحد الأقصى لحجم صور الذاكرة المرفوعة بالميجابايت (القيمة الافتراضية: `65536` أي 64 جيجابايت مع التحقق من الامتدادات الجنائية المعتمدة ومقاومة التعارض).

---

## 🧪 اختبار الجاهزية والتحقق (Test Suite)

للتحقق من سلامة كافة المسارات والرسم البياني ومحركات التحقيق:
```bash
python test_app.py
```
ولتأكيد معمارية V2 والخدمات الجديدة:
```bash
python -m unittest tests/test_v2_architecture.py
```

---

## 📄 التوثيق الهندسي الكامل
للحصول على شرح تفصيلي عن كود المنصة من الداخل، ومعادلات الجراف، وتصميم الواجهة، وقواعد البيانات وكيفية بناء أداة مماثلة:
يرجى الرجوع إلى [DFIR_PLATFORM_MASTER_DOCUMENTATION.md](DFIR_PLATFORM_MASTER_DOCUMENTATION.md).
