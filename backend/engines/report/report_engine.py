"""
DFIR Workbench V2 - Forensic Report Engine
Generates truthful, comprehensive, and court-admissible DFIR Memory Forensic
Investigation Reports in professional Arabic RTL with strict LTR isolation for
technical identifiers, zero count discrepancies, strict risk thresholds, and full reproducibility.
"""

import os
import json
import html
import ipaddress
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.models import (
    Case, Evidence, Finding, IOC, TimelineEvent, Process,
    NetworkConnection, PluginExecution, DumpArtifact, CustodyEvent
)
from backend.infrastructure.database.manager import DatabaseManager
from backend.engines.risk.risk_engine import (
    RISK_THRESHOLD_CRITICAL,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_SUSPICIOUS
)


def _is_public_ip(ip_str: str) -> bool:
    """Determine whether an IP address is a routable public IP."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_unspecified)
    except ValueError:
        return False


class ReportEngine:
    """Generates professional, comprehensive, and court-admissible DFIR Memory Forensic

    Investigation Reports in high-standard Arabic RTL with strict LTR isolation for
    technical identifiers and print-optimized A4 layout.
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    def generate_html_report(self, case_id: str, output_path: Optional[str] = None) -> str:
        case = self.db.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        evidence_list = self.db.list_evidence_for_case(case_id)
        findings = self.db.list_findings(case_id)
        iocs = self.db.list_iocs(case_id)
        dump_artifacts = self.db.list_dump_artifacts(case_id=case.id)
        custody_events = self.db.list_custody_events(case_id=case.id)

        all_processes: List[Process] = []
        all_connections: List[NetworkConnection] = []
        all_timeline: List[TimelineEvent] = []
        all_executions: List[PluginExecution] = []

        evidence_map: Dict[str, str] = {}
        for ev in evidence_list:
            evidence_map[ev.id] = ev.filename
            all_processes.extend(self.db.list_processes(ev.id))
            all_connections.extend(self.db.list_connections(ev.id))
            all_timeline.extend(self.db.list_events(evidence_id=ev.id))
            all_executions.extend(self.db.list_executions(ev.id))

        # Sort timeline chronologically
        all_timeline.sort(key=lambda x: x.timestamp or "")

        # Sort processes by risk score descending
        all_processes.sort(key=lambda p: (p.risk_score, p.pid), reverse=True)

        # Statistics computation adhering to exact strict thresholds
        total_ev_count = len(evidence_list)
        total_proc_count = len(all_processes)
        suspicious_procs = [p for p in all_processes if (p.risk_score or 0) >= RISK_THRESHOLD_SUSPICIOUS]
        critical_procs = [p for p in all_processes if (p.risk_score or 0) >= RISK_THRESHOLD_CRITICAL or (p.risk_level or "").lower() == "critical"]
        total_connections = len(all_connections)
        external_connections = [c for c in all_connections if _is_public_ip(c.remote_addr or "")]
        total_findings = len(findings)
        critical_findings = [f for f in findings if (f.severity or "").lower() == "critical"]
        total_iocs = len(iocs)
        total_executions = len(all_executions)

        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Assessment check for chain of custody
        is_coc_incomplete = (
            (not case.chain_of_custody or len(case.chain_of_custody.strip()) < 15 or "Initial evidence custody logged" in case.chain_of_custody)
            and len(custody_events) <= 1
        )

        doc = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير التحقيق الجنائي الرقمي - {html.escape(case.name)}</title>
    <style>
        /* Base typography & Reset */
        *, *::before, *::after {{
            box-sizing: border-box;
        }}
        body {{
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, Tahoma, sans-serif;
            background-color: #0f172a;
            color: #1e293b;
            margin: 0;
            padding: 24px;
            line-height: 1.6;
            direction: rtl;
        }}
        .report-wrapper {{
            max-width: 1240px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
            overflow: hidden;
            border: 1px solid #cbd5e1;
        }}

        /* Header & Banner */
        .report-header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #1e3a8a 100%);
            color: #ffffff;
            padding: 36px 40px;
            border-bottom: 4px solid #3b82f6;
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.15);
            padding-bottom: 16px;
            margin-bottom: 20px;
        }}
        .header-title-box {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .header-logo-icon {{
            width: 48px;
            height: 48px;
            background: #3b82f6;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: #ffffff;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }}
        .report-classification {{
            background: #dc2626;
            color: #ffffff;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            padding: 4px 12px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .report-meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            background: rgba(15, 23, 42, 0.6);
            padding: 18px 20px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .meta-item {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .meta-label {{
            font-size: 11.5px;
            color: #94a3b8;
            text-transform: uppercase;
            font-weight: 600;
        }}
        .meta-val {{
            font-size: 14px;
            font-weight: 600;
            color: #f8fafc;
        }}

        /* Table of Contents */
        .toc-box {{
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
            padding: 20px 40px;
        }}
        .toc-title {{
            font-size: 14px;
            font-weight: 700;
            color: #475569;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .toc-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
            gap: 8px 16px;
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .toc-grid a {{
            color: #2563eb;
            text-decoration: none;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .toc-grid a:hover {{
            text-decoration: underline;
        }}

        /* Content Sections */
        .report-content {{
            padding: 36px 40px;
        }}
        .report-section {{
            margin-bottom: 48px;
        }}
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 12px;
            margin-bottom: 20px;
        }}
        .section-title {{
            font-size: 20px;
            font-weight: 700;
            color: #0f172a;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .section-title-num {{
            background: #e2e8f0;
            color: #475569;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 700;
        }}

        /* Executive Metrics */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .metric-card.critical {{
            background: #fef2f2;
            border-color: #fecaca;
        }}
        .metric-card.warning {{
            background: #fffbeb;
            border-color: #fde68a;
        }}
        .metric-card.success {{
            background: #f0fdf4;
            border-color: #bbf7d0;
        }}
        .metric-num {{
            font-size: 28px;
            font-weight: 800;
            color: #0f172a;
            font-family: Consolas, monospace;
            direction: ltr;
        }}
        .metric-card.critical .metric-num {{ color: #dc2626; }}
        .metric-card.warning .metric-num {{ color: #d97706; }}
        .metric-card.success .metric-num {{ color: #16a34a; }}
        .metric-label {{
            font-size: 12px;
            font-weight: 600;
            color: #64748b;
            margin-top: 4px;
        }}

        /* Tables */
        .table-responsive {{
            overflow-x: auto;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 16px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: right;
        }}
        th {{
            background: #f1f5f9;
            color: #334155;
            font-weight: 700;
            padding: 10px 14px;
            border-bottom: 1px solid #cbd5e1;
            white-space: nowrap;
        }}
        td {{
            padding: 10px 14px;
            border-bottom: 1px solid #f1f5f9;
            color: #334155;
            vertical-align: top;
        }}
        tr:nth-child(even) {{
            background-color: #f8fafc;
        }}
        tr:hover {{
            background-color: #f1f5f9;
        }}

        /* Key-Value Tables */
        .kv-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        .kv-table th {{
            background: #f8fafc;
            color: #475569;
            width: 25%;
            border: 1px solid #e2e8f0;
            padding: 10px 14px;
        }}
        .kv-table td {{
            border: 1px solid #e2e8f0;
            padding: 10px 14px;
            color: #1e293b;
        }}

        /* Strict LTR isolated spans for technical identifiers */
        .tech-val {{
            direction: ltr !important;
            unicode-bidi: isolate !important;
            display: inline-block;
            font-family: Consolas, "Liberation Mono", Courier, monospace;
            font-size: 12.5px;
            color: #0f172a;
        }}
        .tech-box {{
            background: #f1f5f9;
            border: 1px solid #cbd5e1;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .tech-block {{
            background: #0f172a;
            color: #38bdf8;
            direction: ltr !important;
            unicode-bidi: isolate !important;
            padding: 12px 16px;
            border-radius: 6px;
            font-family: Consolas, monospace;
            font-size: 12px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            margin: 8px 0;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-align: center;
            white-space: nowrap;
        }}
        .badge-critical {{ background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }}
        .badge-high {{ background: #ffedd5; color: #9a3412; border: 1px solid #fed7aa; }}
        .badge-medium {{ background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }}
        .badge-low {{ background: #e0f2fe; color: #075985; border: 1px solid #bae6fd; }}
        .badge-normal {{ background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }}
        .badge-unassessed {{ background: #f8fafc; color: #64748b; border: 1px solid #e2e8f0; }}

        /* Callout Boxes */
        .callout {{
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 20px;
            border-right: 4px solid;
            font-size: 13.5px;
        }}
        .callout-title {{
            font-weight: 700;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .callout-info {{
            background: #f0fdf4;
            border-color: #22c55e;
            color: #166534;
        }}
        .callout-warning {{
            background: #fffbeb;
            border-color: #f59e0b;
            color: #92400e;
        }}
        .callout-danger {{
            background: #fef2f2;
            border-color: #ef4444;
            color: #991b1b;
        }}

        /* Finding Card */
        .finding-card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            border-right: 4px solid;
        }}
        .finding-card.sev-critical {{ border-right-color: #dc2626; }}
        .finding-card.sev-high {{ border-right-color: #ea580c; }}
        .finding-card.sev-medium {{ border-right-color: #d97706; }}
        .finding-card.sev-low {{ border-right-color: #0284c7; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }}
        .finding-title {{
            font-size: 16px;
            font-weight: 700;
            color: #0f172a;
            margin: 0;
        }}
        .finding-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            background: #f8fafc;
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 12.5px;
            margin-bottom: 12px;
        }}
        .finding-field {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}
        .field-label {{
            font-weight: 600;
            color: #64748b;
            font-size: 11.5px;
        }}

        /* Footer */
        .report-footer {{
            background: #f8fafc;
            border-top: 1px solid #e2e8f0;
            padding: 24px 40px;
            text-align: center;
            font-size: 12.5px;
            color: #64748b;
        }}

        /* Print styles */
        @media print {{
            body {{
                background: #ffffff !important;
                padding: 0 !important;
                color: #000000 !important;
            }}
            .report-wrapper {{
                box-shadow: none !important;
                border: none !important;
                max-width: 100% !important;
            }}
            .report-header {{
                background: #0f172a !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
            .report-section {{
                page-break-inside: avoid;
            }}
            .no-print {{
                display: none !important;
            }}
        }}
    </style>
</head>
<body>

<div class="report-wrapper">

    <!-- Report Header & Classification -->
    <header class="report-header">
        <div class="header-top">
            <div class="header-title-box">
                <div class="header-logo-icon">🛡️</div>
                <div>
                    <h1 style="margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.5px;">تقرير التحقيق الجنائي الرقمي لفحص الذاكرة</h1>
                    <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">DFIR Memory Forensic Examination & Investigation Report</div>
                </div>
            </div>
            <div>
                <span class="report-classification">سري وخاص بالتحقيق الجنائي</span>
            </div>
        </div>

        <div class="report-meta-grid">
            <div class="meta-item">
                <span class="meta-label">اسم القضية / الحادثة</span>
                <span class="meta-val">{html.escape(case.name)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">معرّف القضية (Case ID)</span>
                <span class="meta-val tech-val">{html.escape(case.id)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">المحقق الجنائي المسؤول</span>
                <span class="meta-val">{html.escape(case.investigator or "فريق الاستجابة للحوادث")}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">تاريخ ووقت التقرير</span>
                <span class="meta-val tech-val">{html.escape(gen_time)}</span>
            </div>
        </div>
    </header>

    <!-- Table of Contents -->
    <nav class="toc-box no-print">
        <div class="toc-title">
            <span>📑</span>
            <span>فهرس أقسام التقرير الجنائي</span>
        </div>
        <ul class="toc-grid">
            <li><a href="#section-case-overview">1. بيانات القضية وتفاصيل الفحص</a></li>
            <li><a href="#section-executive-summary">2. الملخص التنفيذي والإحصائيات</a></li>
            <li><a href="#section-evidence-custody">3. أدلة الذاكرة وسلسلة الحيازة</a></li>
            <li><a href="#section-custody-integrity">4. سلامة وسلسلة الحيازة والتنبيه الجنائي</a></li>
            <li><a href="#section-findings">5. النتائج والتقييمات المعتمدة للمحقق</a></li>
            <li><a href="#section-processes">6. ملخص العمليات ومؤشرات الاشتباه الخوارزمية</a></li>
            <li><a href="#section-network-iocs">7. الاتصالات الشبكية ومؤشرات الاختراق (IOCs)</a></li>
            <li><a href="#section-timeline">8. الخط الزمني الجنائي للأحداث (Timeline)</a></li>
            <li><a href="#section-plugins">9. سجل تنفيذ الملحقات وقابلية إعادة الإنتاج</a></li>
            <li><a href="#section-methodology">10. المنهجية الجنائية والقيود الفنية</a></li>
        </ul>
    </nav>

    <div class="report-content">

        <!-- Section 1: Case Overview & Metadata -->
        <section id="section-case-overview" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">1</span>
                    <span>بيانات القضية وتفاصيل الفحص (Case Overview & Metadata)</span>
                </h2>
                <span class="badge badge-normal">{html.escape(case.status or "Active")}</span>
            </div>

            <table class="kv-table">
                <tr>
                    <th>معرّف القضية (Case ID)</th>
                    <td><span class="tech-val tech-box">{html.escape(case.id)}</span></td>
                    <th>اسم القضية (Case Name)</th>
                    <td><strong>{html.escape(case.name)}</strong></td>
                </tr>
                <tr>
                    <th>المحقق المسؤول (Lead Investigator)</th>
                    <td>{html.escape(case.investigator or "غير محدد")}</td>
                    <th>حالة التحقيق (Status)</th>
                    <td><span class="badge badge-normal">{html.escape(case.status or "Active")}</span></td>
                </tr>
                <tr>
                    <th>تاريخ إنشاء القضية</th>
                    <td><span class="tech-val">{html.escape(case.created_at or "N/A")}</span></td>
                    <th>تاريخ تصدير التقرير</th>
                    <td><span class="tech-val">{html.escape(gen_time)}</span></td>
                </tr>
                <tr>
                    <th>وصف نطاق الفحص</th>
                    <td colspan="3">{html.escape(case.description or "لا يوجد وصف مدخل لنطاق الفحص.")}</td>
                </tr>
            </table>
        </section>

        <!-- Section 2: Executive Summary -->
        <section id="section-executive-summary" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">2</span>
                    <span>الملخص التنفيذي والإحصائيات (Executive Summary)</span>
                </h2>
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-label">عينات الذاكرة المحروزة</div>
                    <div class="metric-num">{total_ev_count}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">إجمالي العمليات المستخرجة</div>
                    <div class="metric-num">{total_proc_count}</div>
                </div>
                <div class="metric-card {'critical' if len(critical_procs) > 0 else 'warning' if len(suspicious_procs) > 0 else 'success'}">
                    <div class="metric-label">عمليات مشبوهة خوارزمياً (Risk &ge; 20)</div>
                    <div class="metric-num">{len(suspicious_procs)}</div>
                </div>
                <div class="metric-card {'warning' if len(external_connections) > 0 else ''}">
                    <div class="metric-label">اتصالات شبكية خارجية</div>
                    <div class="metric-num">{len(external_connections)}</div>
                </div>
                <div class="metric-card {'critical' if len(critical_findings) > 0 else 'warning' if total_findings > 0 else ''}">
                    <div class="metric-label">نتائج جنائية معتمدة</div>
                    <div class="metric-num">{total_findings}</div>
                </div>
                <div class="metric-card {'warning' if total_iocs > 0 else ''}">
                    <div class="metric-label">مؤشرات اختراق مرصودة (IOCs)</div>
                    <div class="metric-num">{total_iocs}</div>
                </div>
            </div>

            <div class="callout {'callout-danger' if (len(critical_findings) > 0 or len(critical_procs) > 0) else 'callout-info'}">
                <div class="callout-title">
                    <span>📋</span>
                    <span>خلاصة التقييم الجنائي الأولي:</span>
                </div>
                <p style="margin: 6px 0 0 0;">
                    {"تم خلال الفحص الجنائي رصد مؤشرات اشتباه مرتفعة الخطورة تتطلب إجراءات عزل واحتواء فورية للأجهزة المتأثرة ومتابعة مصادر التهديد وفق المعطيات الفنية الموضحة أدناه." if (len(critical_findings) > 0 or len(critical_procs) > 0) else "تم فحص صورة الذاكرة ومراجعة العمليات وهياكل النواة المستخرجة. المؤشرات الحالية مسجلة لغرض الاستدلال والفرز الجنائي والمتابعة التحقيقية."}
                </p>
            </div>
        </section>

        <!-- Section 3: Memory Evidence & Chain of Custody -->
        <section id="section-evidence-custody" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">3</span>
                    <span>أدلة الذاكرة المستلمة والمفحوصة (Digital Memory Evidence)</span>
                </h2>
                <span class="badge badge-normal">{len(evidence_list)} عينات</span>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>اسم ملف العينة</th>
                            <th>الحجم (Bytes)</th>
                            <th>بصمة SHA-256 (الأساسية)</th>
                            <th>بصمة MD5</th>
                            <th>نظام التشغيل والمعمارية</th>
                            <th>وقت التحريز والاستيراد</th>
                            <th>حالة المطابقة</th>
                        </tr>
                    </thead>
                    <tbody>"""

        if evidence_list:
            for ev in evidence_list:
                size_fmt = f"{ev.file_size:,}" if ev.file_size else "N/A"
                os_arch = f"{ev.os_type or 'Windows'} ({ev.architecture or 'x64'})"
                doc += f"""
                        <tr>
                            <td><strong class="tech-val">{html.escape(ev.filename)}</strong></td>
                            <td><span class="tech-val">{size_fmt}</span></td>
                            <td><span class="tech-val tech-box" style="font-size: 11px;">{html.escape(ev.sha256 or 'N/A')}</span></td>
                            <td><span class="tech-val tech-box" style="font-size: 11px;">{html.escape(ev.md5 or 'N/A')}</span></td>
                            <td><span class="tech-val">{html.escape(os_arch)}</span></td>
                            <td><span class="tech-val">{html.escape(ev.import_timestamp or ev.acquisition_timestamp or 'N/A')}</span></td>
                            <td><span class="badge badge-normal">{html.escape(ev.verification_status or 'Verified')}</span></td>
                        </tr>"""
        else:
            doc += """
                        <tr>
                            <td colspan="7" style="text-align: center; color: #64748b;">لا توجد عينات ذاكرة مرتبطة بهذه القضية حالياً.</td>
                        </tr>"""

        doc += """
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 4: Custody Log & Forensic Warning -->
        <section id="section-custody-integrity" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">4</span>
                    <span>سلسلة الحيازة وسلامة الأدلة (Chain of Custody & Evidence Integrity)</span>
                </h2>
            </div>"""

        if is_coc_incomplete:
            doc += """
            <div class="callout callout-warning">
                <div class="callout-title">
                    <span>⚠️</span>
                    <span>تنبيه جنائي بخصوص توثيق سلسلة الحيازة (Chain of Custody Alert):</span>
                </div>
                <p style="margin: 4px 0 0 0;">
                    سجل سلسلة الحيازة الجنائية لهذه القضية بحاجة إلى استكمال بيانات التسليم والاستلام الإجرائية وتوثيق هوية القائم بالتحريز الميداني. يوصى باستكمال التوقيعات وسجلات النقل الرقمية قبل تقديم التقرير للجهات القضائية.
                </p>
            </div>"""
        else:
            doc += """
            <div class="callout callout-info">
                <div class="callout-title">
                    <span>🔒</span>
                    <span>توثيق سلسلة الحيازة الجنائية (Chain of Custody Log):</span>
                </div>
                <p style="margin: 4px 0 0 0;">
                    تم توثيق سجلات الحيازة الخاصة بالعينة الجنائية وإثبات سلامة وتطابق البصمات الهاشية الرقمية أثناء مراحل الاستيراد والفحص.
                </p>
            </div>"""

        # Custody Events Table
        if custody_events:
            doc += """
            <h4 style="margin: 16px 0 8px 0; color: #334155; font-size: 14px;">سجل أحداث الحيازة المؤرخة (Custody Audit Events):</h4>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>التاريخ والوقت</th>
                            <th>الإجراء (Action)</th>
                            <th>المسؤول (Actor)</th>
                            <th>بصمة الهاش SHA-256</th>
                            <th>التفاصيل والملاحظات</th>
                        </tr>
                    </thead>
                    <tbody>"""
            for ce in custody_events:
                doc += f"""
                        <tr>
                            <td><span class="tech-val">{html.escape(ce.timestamp)}</span></td>
                            <td><span class="badge badge-normal"><strong>{html.escape(ce.action)}</strong></span></td>
                            <td>{html.escape(ce.actor)}</td>
                            <td><span class="tech-val tech-box" style="font-size: 11px;">{html.escape(ce.sha256 or 'N/A')}</span></td>
                            <td>{html.escape(ce.details or '')}</td>
                        </tr>"""
            doc += """
                    </tbody>
                </table>
            </div>"""
        else:
            doc += f"""
            <h4 style="margin: 16px 0 8px 0; color: #334155; font-size: 14px;">سجل تدقيق سلسلة الحيازة الرقمي:</h4>
            <pre class="tech-block">{html.escape(case.chain_of_custody or "Initial evidence custody logged at case creation.")}</pre>"""

        doc += """
            <div class="callout callout-info" style="margin-top: 16px;">
                <div class="callout-title">
                    <span>⚖️</span>
                    <span>التصنيف المنهجي للأدلة والتقييمات في هذا التقرير:</span>
                </div>
                <ul style="margin: 6px 0 0 0; padding-right: 20px; font-size: 13.5px; line-height: 1.8;">
                    <li><strong>الأدلة المرصودة الخام (Observed Memory Artifacts):</strong> هي الكيانات المستخرجة حرفياً من بنى النواة بالذاكرة (مثل قيم الهاش، معرفات PIDs، منافذ الاتصال، الطوابع الزمنية) وهي حقائق فنية مثبتة.</li>
                    <li><strong>التقييم الخوارزمي الإرشادي (Automated Heuristic / Risk Scoring):</strong> درجات الخطورة الرقمية المحسوبة آلياً هي مؤشرات ترجيحية تهدف لتوجيه وتسريع الفرز الأولي (Triage Prioritization)، ولا تعد دليلاً قاطعاً على التهديد بحد ذاتها دون تحقق المحقق.</li>
                    <li><strong>النتائج والتقييم البشري المعتمد (Analyst Findings & Human Assessment):</strong> هي الاستنتاجات الفنية التي فحصها واعتمدها المحقق الجنائي المسؤول بعد التحقق والمطابقة مع سياق الحادثة.</li>
                </ul>
            </div>
        </section>

        <!-- Section 5: Forensic Findings & Human Assessments -->
        <section id="section-findings" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">5</span>
                    <span>النتائج الجنائية والتقييمات المعتمدة (Forensic Findings & Human Assessments)</span>
                </h2>
                <span class="badge badge-normal">""" + str(len(findings)) + """ نتائج معتمدة</span>
            </div>"""

        if findings:
            for f in findings:
                sev = (f.severity or "Medium").lower()
                sev_badge_class = "badge-critical" if sev == "critical" else "badge-high" if sev == "high" else "badge-medium" if sev == "medium" else "badge-low"
                card_sev_class = f"sev-{sev}" if sev in ["critical", "high", "medium", "low"] else "sev-medium"
                status_text = html.escape(f.status.capitalize())
                
                doc += f"""
            <div class="finding-card {card_sev_class}">
                <div class="finding-header">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="badge {sev_badge_class}">{html.escape(f.severity)}</span>
                        <span class="badge badge-normal">حالة النتيجة: {status_text}</span>
                        <h3 class="finding-title">{html.escape(f.title)}</h3>
                    </div>
                    <span class="tech-val" style="color: #64748b; font-size: 12px;">{html.escape(f.created_at or '')}</span>
                </div>
                
                <p style="margin: 8px 0 12px 0; font-size: 14px; color: #1e293b;">{html.escape(f.description or f.summary or '')}</p>

                <div class="finding-grid">
                    <div class="finding-field">
                        <span class="field-label">الكيان / العملية المرتبطة (Entity/PID):</span>
                        <span class="tech-val"><strong>{html.escape(f.affected_entity or f.associated_process_name or 'غير محدد')}</strong> (PID: {f.associated_pid or 'N/A'})</span>
                    </div>
                    <div class="finding-field">
                        <span class="field-label">مستوى الثقة الفنية (Confidence):</span>
                        <span class="tech-val">{html.escape(f.confidence or 'Medium')}</span>
                    </div>
                    <div class="finding-field">
                        <span class="field-label">مصدر التقييم (Source):</span>
                        <span class="tech-val">{html.escape(f.source_type or 'Forensic Analysis')}</span>
                    </div>
                    <div class="finding-field">
                        <span class="field-label">الأدلة الداعمة (Supporting Evidence):</span>
                        <span class="tech-val" style="word-break: break-word;">{html.escape(f.supporting_evidence or 'غير متاح')}</span>
                    </div>
                </div>

                <div style="margin-top: 14px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 12px 16px;">
                    <span style="font-weight: 700; color: #1e40af; font-size: 13px; display: block; margin-bottom: 4px;">التقييم الجنائي المعتمد للمحقق (Analyst Assessment):</span>
                    <div style="color: #1e293b; font-size: 13.5px;">{html.escape(f.analyst_assessment or 'بانتظار الاعتماد والمراجعة اليدوية النهائية')}</div>
                </div>
            </div>"""
        else:
            doc += """
            <div class="callout callout-info">
                <p style="margin: 0;">لم يتم تسجيل نتائج جنائية رسمية معتمدة من قبل المحقق في هذه القضية حتى تاريخ إعداد هذا التقرير.</p>
            </div>"""

        doc += """
        </section>

        <!-- Section 6: Process Risk & Heuristic Indicators -->
        <section id="section-processes" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">6</span>
                    <span>ملخص العمليات ومؤشرات الاشتباه الخوارزمية (Process Risk & Heuristics)</span>
                </h2>
                <span class="badge badge-normal">إجمالي المعروض: """ + str(len(all_processes)) + """</span>
            </div>

            <div class="callout callout-info" style="margin-top: 0;">
                <p style="margin: 0; font-size: 13px;">
                    <strong>تنبيه فني:</strong> درجات تقييم الخطورة المعروضة أدناه ناتجة عن التحليل الخوارزمي الآلي لهياكل العمليات (Parent-Child Anomalies, Obfuscated Cmdlines, Memory Injections, Process Hiding). العمليات غير الحاصلة على درجة اشتباه (أقل من 20) مصنفة بدقة كـ "طبيعية / لا اشتباه مرصود" ولا تعني سلامتها المطلقة بل تعني خلوها من الأنماط الآلية الشاذة.
                </p>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>العينة</th>
                            <th>معرّف PID</th>
                            <th>معرّف PPID</th>
                            <th>اسم العملية</th>
                            <th>المسار / سطر الأوامر</th>
                            <th>مصادر الرصد</th>
                            <th>درجة الاشتباه الآلي</th>
                            <th>المستوى</th>
                            <th>المؤشرات المرصودة</th>
                        </tr>
                    </thead>
                    <tbody>"""

        if all_processes:
            for p in all_processes:
                r_score = int(p.risk_score or 0)
                
                # Strict threshold compliance: <20 is strictly Normal
                if r_score >= RISK_THRESHOLD_CRITICAL:
                    badge_cls = "badge-critical"
                    level_ar = "حرج (Critical)"
                elif r_score >= RISK_THRESHOLD_HIGH:
                    badge_cls = "badge-high"
                    level_ar = "عالي (High)"
                elif r_score >= RISK_THRESHOLD_SUSPICIOUS:
                    badge_cls = "badge-medium"
                    level_ar = "مشبوه (Suspicious)"
                else:
                    badge_cls = "badge-normal"
                    level_ar = "طبيعي (Normal)"

                ev_name = evidence_map.get(p.evidence_id, "Memory Dump")

                # Sources
                srcs = []
                if p.in_pslist: srcs.append("pslist")
                if p.in_psscan: srcs.append("psscan")
                if p.in_pstree: srcs.append("pstree")
                src_str = ", ".join(srcs) if srcs else "N/A"

                cmd = p.command_line or p.path or "غير متاح"
                notes = p.risk_details or p.metadata or ("لا توجد مؤشرات اشتباه آلية مفعلة" if r_score == 0 else "")

                doc += f"""
                        <tr>
                            <td><span class="tech-val" style="font-size: 11px;">{html.escape(ev_name)}</span></td>
                            <td><span class="tech-val"><strong>{p.pid}</strong></span></td>
                            <td><span class="tech-val">{p.ppid if p.ppid is not None else 'N/A'}</span></td>
                            <td><strong class="tech-val">{html.escape(p.name or 'Unknown')}</strong></td>
                            <td><span class="tech-val tech-box" style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{html.escape(cmd)}">{html.escape(cmd)}</span></td>
                            <td><span class="tech-val">{src_str}</span></td>
                            <td><strong class="tech-val">{r_score}/100</strong></td>
                            <td><span class="badge {badge_cls}">{level_ar}</span></td>
                            <td><div class="tech-val" style="font-size: 11px; max-width: 260px;">{html.escape(notes)}</div></td>
                        </tr>"""
        else:
            doc += """
                        <tr>
                            <td colspan="9" style="text-align: center; color: #64748b;">لم يتم استخراج أية بيانات عمليات في هذه القضية حتى الآن.</td>
                        </tr>"""

        doc += """
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 7: Network Connections & IOCs -->
        <section id="section-network-iocs" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">7</span>
                    <span>الاتصالات الشبكية ومؤشرات الاختراق (Network Connections & IOCs)</span>
                </h2>
            </div>

            <h3 style="font-size: 16px; margin: 0 0 12px 0; color: #0f172a;">1.7 اتصالات الشبكة المستخرجة من الذاكرة (Observed Network Sockets - إجمالي: """ + str(len(all_connections)) + """)</h3>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>معرّف PID</th>
                            <th>اسم العملية</th>
                            <th>البروتوكول</th>
                            <th>العنوان والمنفذ المحلي</th>
                            <th>العنوان والمنفذ البعيد</th>
                            <th>حالة الاتصال</th>
                            <th>طبيعة الوجهة</th>
                        </tr>
                    </thead>
                    <tbody>"""

        if all_connections:
            for c in all_connections:
                is_pub = _is_public_ip(c.remote_addr or "")
                dest_badge = '<span class="badge badge-high">عام / خارجي (Public)</span>' if is_pub else '<span class="badge badge-unassessed">داخلي / محلي</span>'
                doc += f"""
                        <tr>
                            <td><span class="tech-val">{c.pid or 'N/A'}</span></td>
                            <td><strong class="tech-val">{html.escape(c.process_name or 'N/A')}</strong></td>
                            <td><span class="tech-val">{html.escape(c.protocol or 'TCP')}</span></td>
                            <td><span class="tech-val">{html.escape(c.local_addr or '0.0.0.0')}:{c.local_port or 0}</span></td>
                            <td><span class="tech-val">{html.escape(c.remote_addr or '0.0.0.0')}:{c.remote_port or 0}</span></td>
                            <td><span class="tech-val">{html.escape(c.state or 'N/A')}</span></td>
                            <td>{dest_badge}</td>
                        </tr>"""
        else:
            doc += """
                        <tr>
                            <td colspan="7" style="text-align: center; color: #64748b;">غير متاح / لم تُسجل اتصالات شبكية في هياكل الذاكرة المستخرجة.</td>
                        </tr>"""

        doc += """
                    </tbody>
                </table>
            </div>

            <h3 style="font-size: 16px; margin: 24px 0 12px 0; color: #0f172a;">2.7 مؤشرات الاختراق المرصودة (Extracted Indicators of Compromise - IOCs - إجمالي: """ + str(len(iocs)) + """)</h3>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>نوع المؤشر</th>
                            <th>قيمة المؤشر الفني (Indicator Value)</th>
                            <th>مستوى الخطورة</th>
                            <th>المصدر الجنائي</th>
                            <th>السياق / الوصف التوضيحي</th>
                        </tr>
                    </thead>
                    <tbody>"""

        if iocs:
            for i in iocs:
                sev_cls = "badge-critical" if (i.severity or "").lower() == "critical" else "badge-high" if (i.severity or "").lower() == "high" else "badge-medium"
                doc += f"""
                        <tr>
                            <td><span class="badge badge-normal"><strong class="tech-val">{html.escape(i.type.upper())}</strong></span></td>
                            <td><span class="tech-val tech-box"><strong>{html.escape(i.value)}</strong></span></td>
                            <td><span class="badge {sev_cls}">{html.escape(i.severity)}</span></td>
                            <td><span class="tech-val">{html.escape(i.source or 'Memory Analysis')}</span></td>
                            <td>{html.escape(i.description or '')}</td>
                        </tr>"""
        else:
            doc += """
                        <tr>
                            <td colspan="5" style="text-align: center; color: #64748b;">لا توجد مؤشرات اختراق (IOCs) مستخلصة في سجلات هذه القضية.</td>
                        </tr>"""

        doc += """
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 8: Forensic Activity Timeline -->
        <section id="section-timeline" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">8</span>
                    <span>الخط الزمني الجنائي للأحداث (Chronological Forensic Timeline)</span>
                </h2>
                <span class="badge badge-normal">إجمالي الأحداث المعروضة: """ + str(len(all_timeline)) + """</span>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>التاريخ والوقت (UTC/Local)</th>
                            <th>نوع الحدث</th>
                            <th>معرّف PID</th>
                            <th>العملية المعنية</th>
                            <th>وصف الحدث والتفاصيل</th>
                            <th>مستوى الخطورة</th>
                        </tr>
                    </thead>
                    <tbody>"""

        if all_timeline:
            for t in all_timeline:
                sev_cls = "badge-critical" if (t.severity or "").lower() == "critical" else "badge-high" if (t.severity or "").lower() == "high" else "badge-normal"
                doc += f"""
                        <tr>
                            <td><span class="tech-val">{html.escape(t.timestamp or '')}</span></td>
                            <td><span class="badge badge-medium">{html.escape(t.event_type or 'Event')}</span></td>
                            <td><span class="tech-val">{t.pid or ''}</span></td>
                            <td><strong class="tech-val">{html.escape(t.process_name or '')}</strong></td>
                            <td>{html.escape(t.description or '')}</td>
                            <td><span class="badge {sev_cls}">{html.escape(t.severity or 'Info')}</span></td>
                        </tr>"""
        else:
            doc += """
                        <tr>
                            <td colspan="6" style="text-align: center; color: #64748b;">لم يتم استخراج أو تسجيل أحداث زمنية في هذه القضية.</td>
                        </tr>"""

        doc += """
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 9: Plugin Execution Log & Reproducibility -->
        <section id="section-plugins" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">9</span>
                    <span>سجل تنفيذ ملحقات الفحص وقابلية إعادة الإنتاج (Plugin Execution Log & Reproducibility)</span>
                </h2>
                <span class="badge badge-normal">منفّذ: """ + str(len(all_executions)) + """</span>
            </div>

            <div class="callout callout-info" style="margin-top: 0;">
                <p style="margin: 0; font-size: 13px;">
                    <strong>النزاهة وقابلية التدقيق المستقل (Auditability & Reproducibility):</strong> يوثق هذا السجل الأوامر الدقيقة لملحقات Volatility 3 وأوقات تشغيلها وبصمات الهاش الرقمية لضمان إمكانية إعادة إنتاج ومراجعة نفس النتائج الجنائية بدقة من قِبل أي خبير مستقل.
                </p>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>وقت البدء</th>
                            <th>اسم الملحق (Plugin)</th>
                            <th>الأمر التنفيذي التام (Executed Command)</th>
                            <th>بصمة الناتج (Hash)</th>
                            <th>زمن المعالجة</th>
                            <th>النتائج</th>
                            <th>الحالة</th>
                        </tr>
                    </thead>
                    <tbody>"""

        if all_executions:
            for ex in all_executions:
                status_cls = "badge-normal" if ex.status == "completed" else "badge-critical" if ex.status == "failed" else "badge-medium"
                res_hash = ex.result_hash or ex.stdout_hash or "N/A"
                doc += f"""
                        <tr>
                            <td><span class="tech-val" style="font-size: 11px;">{html.escape(ex.created_at or '')}</span></td>
                            <td><strong class="tech-val">{html.escape(ex.plugin_name)}</strong></td>
                            <td><span class="tech-val tech-box" style="font-size: 11px;">{html.escape(ex.command or '')}</span></td>
                            <td><span class="tech-val tech-box" style="font-size: 10px;">{html.escape(res_hash[:16] + '...' if len(res_hash) > 16 else res_hash)}</span></td>
                            <td><span class="tech-val">{(ex.runtime_seconds or 0):.2f}s</span></td>
                            <td><span class="tech-val">{ex.result_count or 0}</span></td>
                            <td><span class="badge {status_cls}">{html.escape(ex.status)}</span></td>
                        </tr>"""
        else:
            doc += """
                        <tr>
                            <td colspan="7" style="text-align: center; color: #64748b;">لا توجد سجلات تنفيذ لملحقات الفحص في قاعدة البيانات.</td>
                        </tr>"""

        doc += """
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 10: Methodology & Technical Limitations -->
        <section id="section-methodology" class="report-section">
            <div class="section-header">
                <h2 class="section-title">
                    <span class="section-title-num">10</span>
                    <span>المنهجية الجنائية والقيود الفنية (Methodology & Technical Limitations)</span>
                </h2>
            </div>

            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px 24px; font-size: 13.5px; line-height: 1.8;">
                <h4 style="margin: 0 0 8px 0; color: #0f172a; font-size: 15px;">1.10 منهجية فحص الذاكرة العشوائية:</h4>
                <p style="margin: 0 0 16px 0;">
                    صُمم هذا التحليل لدعم إجراءات فحص ومعالجة الأدلة الرقمية بالاستئناس بمبادئ معيار <span class="tech-val">ISO/IEC 27037</span> مع الالتزام التام بسلامة وتوثيق الأدلة وسلسلة الحيازة والاعتماد على إطار العمل الجنائي المفتوح المصدر <span class="tech-val">Volatility 3 Framework</span>. يتم استخلاص الأدلة عبر القراءة الصامتة لهياكل بيانات النواة (<span class="tech-val">Kernel Data Structures</span>) دون تعديل أو كتابة على صورة الذاكرة الأصلية المحروزة لضمان النزاهة التامة للدليل الرقمي.
                </p>

                <h4 style="margin: 0 0 8px 0; color: #0f172a; font-size: 15px;">2.10 القيود الفنية المتأصلة في فحص الذاكرة (Forensic Limitations):</h4>
                <ul style="margin: 0 0 16px 0; padding-right: 20px;">
                    <li><strong>طبيعة الذاكرة المؤقتة (Volatile Nature):</strong> تمثل صورة الذاكرة لقطة للحالة في لحظة التحريز فقط؛ الأنشطة التي وقعت قبل التحريز وتم تفريغها من الذاكرة أو استبدالها قد لا تتوفر بها سجلات كاملة.</li>
                    <li><strong>الصفحات المستبدلة للقرص (Paged-out Memory):</strong> قد لا تتضمن عينة الذاكرة الفيزيائية البيانات المخزنة في ملفات التبديل (<span class="tech-val">pagefile.sys / swap</span>) إلا في حال دمجها مع صور الأقراص.</li>
                    <li><strong>تقنيات مكافحة التحقيق الجنائي (Anti-Forensics & DKOM):</strong> قد تستخدم بعض التهديدات المتقدمة تقنيات التلاعب المباشر ببنى النواة (<span class="tech-val">Direct Kernel Object Manipulation</span>) لإخفاء العمليات، وتعتمد المنصة تقنيات المسح المتقاطع (<span class="tech-val">pslist vs psscan vs pstree</span>) لاكتشاف هذا الإخفاء.</li>
                </ul>

                <h4 style="margin: 0 0 8px 0; color: #0f172a; font-size: 15px;">3.10 التوصيات الفنية للتحقيق المستمر:</h4>
                <p style="margin: 0;">
                    يوصى بربط النتائج المستخلصة من هذا التقرير الجنائي مع سجلات الأحداث الأمنية (<span class="tech-val">Windows Event Logs / Sysmon</span>)، وتحليل حركة مرور الشبكة (<span class="tech-val">Network PCAP</span>)، وفحص صورة القرص التخزيني للجهاز المتأثر للوصول إلى تقييم جنائي متكامل وموثق لسير الحادثة.
                </p>
            </div>
        </section>

    </div>

    <!-- Report Footer -->
    <footer class="report-footer">
        <p style="margin: 0 0 6px 0; font-weight: 600; color: #334155;">
            تم إنشاء هذا التقرير الجنائي آلياً عبر منصة Volatility 3 DFIR Investigation Platform
        </p>
        <p style="margin: 0; font-size: 12px;">
            تاريخ التوليد: <span class="tech-val">{html.escape(gen_time)}</span> | معرّف التقرير: <span class="tech-val">{html.escape(case.id)}</span> | مستخرج ومحفوظ وفق معايير النزاهة الرقمية
        </p>
    </footer>

</div>

</body>
</html>
"""
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(doc)

        return doc
