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
   - **Court-Admissible Arabic RTL Reports**: توليد تقارير جنائية رسمية باللغة العربية مطابقة لمعايير **ISO/IEC 27037** مع عزل النصوص التقنية الإنجليزية وتطهير تصدير CSV ضد هجمات Formula Injection.

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

## 🛠️ متطلبات التشغيل (Prerequisites)

- **Python 3.10+** (مُثبت ومُهيأ في مسار النظام)
- تثبيت المتطلبات عبر:
  ```bash
  pip install -r requirements.txt
  ```
  *(تشمل `flask`, `volatility3`, `pyyaml`, `yara-python`)*

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
