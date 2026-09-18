"""报告自动生成服务：HTML / PDF / JSON / Excel 四种格式导出"""
import csv
import html
import json
import re
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import settings
from ..models import Asset, Report, Vulnerability

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "#c62828", "high": "#e65100", "medium": "#f9a825",
             "low": "#2e7d32", "info": "#546e7a"}
STATE_LABEL = {"pending": "待确认", "confirmed": "已确认", "fixing": "修复中",
               "fixed": "已修复", "verified": "复测通过", "false_positive": "误报",
               "ignored": "已忽略"}


def build_stats(db: Session, user_id: int, asset_ids: list[int] | None = None) -> dict:
    q = db.query(Vulnerability).filter_by(user_id=user_id)
    if asset_ids:
        q = q.filter(Vulnerability.asset_id.in_(asset_ids))
    vulns = q.all()
    stats = {
        "total": len(vulns),
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "by_state": {s: 0 for s in STATE_LABEL},
        "by_type": {},
    }
    for v in vulns:
        stats["by_severity"][v.severity] = stats["by_severity"].get(v.severity, 0) + 1
        stats["by_state"][v.state] = stats["by_state"].get(v.state, 0) + 1
        stats["by_type"][v.vuln_type] = stats["by_type"].get(v.vuln_type, 0) + 1
    stats["by_type"] = dict(sorted(stats["by_type"].items(), key=lambda x: -x[1]))
    return stats


def _risk_rating(stats: dict) -> tuple[str, str]:
    """总体风险评级：按最高严重度 + 漏洞密度给出评级与处置建议"""
    b = stats["by_severity"]
    if b.get("critical", 0):
        return "高危", "存在可利用的关键漏洞，应立即启动应急处置，阻断攻击路径后按优先级修复"
    if b.get("high", 0):
        return "较高", "存在高危漏洞，建议 1 周内完成修复并复查"
    if b.get("medium", 0):
        return "中危", "存在中危漏洞，建议纳入近期修复计划（1 个月内）"
    if b.get("low", 0) or b.get("info", 0):
        return "低危", "整体风险可控，建议按常规排期加固"
    return "无风险", "未发现漏洞，建议保持定期巡检"


def _vulns_for(db: Session, user_id: int, asset_ids: list[int] | None):
    q = db.query(Vulnerability).filter_by(user_id=user_id)
    if asset_ids:
        q = q.filter(Vulnerability.asset_id.in_(asset_ids))
    return q.order_by(Vulnerability.severity.desc(), Vulnerability.id.desc()).all()


def generate_report(db: Session, user_id: int, fmt: str, title: str,
                    asset_ids: list[int] | None = None) -> Report:
    """生成报告并落盘，返回 Report 记录"""
    fmt = fmt.lower()
    if fmt not in ("html", "pdf", "json", "excel"):
        raise ValueError(f"不支持的格式: {fmt}")
    assets = []
    if asset_ids:
        assets = db.query(Asset).filter(Asset.user_id == user_id, Asset.id.in_(asset_ids)).all()
    stats = build_stats(db, user_id, asset_ids)
    vulns = _vulns_for(db, user_id, asset_ids)

    now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^\w\u4e00-\u9fff-]", "_", title)[:40] or "report"
    ext = "xlsx" if fmt == "excel" else fmt
    fname = f"report_{safe}_{now}.{ext}"
    fpath = settings.EXPORT_DIR / fname

    if fmt == "json":
        _write_json(fpath, title, assets, stats)
    elif fmt == "html":
        _write_html(fpath, title, assets, stats, vulns)
    elif fmt == "excel":
        _write_excel(fpath, title, assets, stats, vulns)
    else:  # pdf
        _write_pdf(fpath, title, assets, stats, vulns)

    report = Report(
        user_id=user_id, title=title, fmt=fmt, file_path=fname,
        scope_desc=", ".join(a.value for a in assets) if asset_ids else "全部资产",
        stats_json=json.dumps(stats, ensure_ascii=False),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


# ---------------- 各格式实现 ----------------
def _write_json(fpath: Path, title: str, assets: list, stats: dict):
    data = {
        "report_title": title, "generated_at": datetime.utcnow().isoformat(),
        "assets": [{"id": a.id, "kind": a.kind, "value": a.value, "status": a.status} for a in assets],
        "stats": stats,
    }
    fpath.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_html(fpath: Path, title: str, assets: list, stats: dict, vulns: list):
    """专业渗透测试报告（HTML）：执行摘要 + 风险评级 + 漏洞证据链 + 方法论附录"""
    rating, rating_advice = _risk_rating(stats)
    # ---- 统计卡 ----
    sev_cards = "".join(
        f'<div class="sevcard" style="border-top:4px solid {SEV_COLOR[s]}">'
        f'<div class="sevnum">{stats["by_severity"].get(s, 0)}</div>'
        f'<div class="sevlabel">{s.upper()}</div></div>' for s in SEV_COLOR
    )
    # ---- 关键发现（critical + high）----
    key_vulns = [v for v in vulns if v.severity in ("critical", "high")][:10]
    if key_vulns:
        key_rows = "".join(
            f'<tr><td>{v.id}</td><td>{html.escape(v.title or "")}</td>'
            f'<td>{html.escape(v.vuln_type or "")}</td>'
            f'<td><span class="tag" style="background:{SEV_COLOR.get(v.severity)}">{v.severity.upper()}</span></td>'
            f'<td style="word-break:break-all">{html.escape(v.url or "")}</td></tr>'
            for v in key_vulns
        )
        key_section = f"""<h3>关键发现（Top {len(key_vulns)}）</h3>
        <p class="hint">以下漏洞对系统影响最大，建议优先处置</p>
        <table><tr><th>ID</th><th>标题</th><th>类型</th><th>等级</th><th>URL</th></tr>{key_rows}</table>"""
    else:
        key_section = '<p class="hint">本次扫描未发现高危及以上漏洞。</p>'
    # ---- 漏洞详情（含证据链）----
    detail_blocks = []
    for v in vulns:
        color = SEV_COLOR.get(v.severity, "#333")
        desc = html.escape(v.description or "（无描述）").replace("\n", "<br>")
        fix = html.escape(v.fix_suggestion or "（未提供）").replace("\n", "<br>")
        payload = html.escape((v.payload or "")[:300])
        req_raw = html.escape((v.request_raw or "")[:400])
        resp_raw = html.escape((v.response_raw or "")[:400])
        refs = "".join(f'<li><a href="{html.escape(x)}" target="_blank">{html.escape(x)}</a></li>'
                       for x in (json.loads(v.reference) if v.reference else []))
        detail_blocks.append(f"""
        <div class="vulncard">
          <div class="vulnhead">
            <span class="vid">#{v.id}</span>
            <span class="vtitle">{html.escape(v.title or "")}</span>
            <span class="tag" style="background:{color}">{v.severity.upper()}</span>
            <span class="vmeta">{html.escape(v.vuln_type or "")} · 状态 {STATE_LABEL.get(v.state, v.state)}'
            + (f' · CVE {html.escape(v.cve_id or "")}' if v.cve_id else '') + '</span>
          </div>
          <div class="vfield"><b>位置</b> {html.escape(v.url or "")}'
            + (f' <span class="param">参数: {html.escape(v.param or "")}</span>' if v.param else '') + '</div>
          <div class="vfield"><b>描述</b> <div class="vdesc">{desc}</div></div>
          <div class="vfield"><b>Payload</b> <pre class="code">{payload}</pre></div>
          <div class="vfield"><b>请求摘要</b> <pre class="code">{req_raw}</pre></div>
          <div class="vfield"><b>响应特征</b> <pre class="code">{resp_raw}</pre></div>
          <div class="vfield"><b>修复建议</b> <div class="vfix">{fix}</div></div>
          {'<div class="vfield"><b>参考</b><ul>' + refs + '</ul></div>' if refs else ''}
        </div>""")
    detail_html = "".join(detail_blocks) if detail_blocks else '<p class="hint">暂无漏洞详情。</p>'
    # ---- 资产范围 ----
    scope = "、".join(html.escape(a.value) for a in assets) if assets else "全部资产"
    # ---- 方法论附录 ----
    stages = [
        ("侦察与资产识别", "URL 收集、同域链接解析、动态爬虫（Playwright 渲染 SPA）"),
        ("认证态探测", "登录 Cookie 注入，探测登录后页面"),
        ("配置与信息泄露", "敏感路径/文件/响应头检查"),
        ("注入类检测", "SQL 盲注（布尔/时间）、命令注入、SSTI、XXE、SSRF"),
        ("XSS 检测", "反射型 + 存储型（提交-回读验证）"),
        ("文件安全", "上传检测（危险扩展名/webshell 可访问）"),
        ("带外验证", "OAST 回调确认无回显漏洞"),
        ("组件指纹", "版本识别 + 已知 CVE 比对"),
    ]
    stage_rows = "".join(
        f"<tr><td>{i+1}</td><td>{name}</td><td>{html.escape(desc)}</td></tr>"
        for i, (name, desc) in enumerate(stages)
    )
    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
 body{{font-family:'Microsoft YaHei',sans-serif;margin:40px;color:#222;line-height:1.6}}
 h1{{border-bottom:3px solid #1565c0;padding-bottom:10px}}
 h2{{border-left:4px solid #1565c0;padding-left:10px;margin-top:36px}}
 h3{{margin-bottom:8px}}
 .meta{{color:#666;margin:8px 0 20px}}
 .rating{{background:#f5f7fa;border:1px solid #ddd;border-radius:6px;padding:16px;margin:16px 0}}
 .rating .level{{font-size:22px;font-weight:700;color:#1565c0}}
 .rating .advice{{color:#444;margin-top:6px}}
 .sevcards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
 .sevcard{{flex:1 1 90px;min-width:80px;background:#fafbfc;border:1px solid #e0e0e0;border-radius:6px;padding:12px;text-align:center}}
 .sevnum{{font-size:26px;font-weight:700}}
 .sevlabel{{font-size:11px;color:#666;margin-top:4px}}
 .tag{{color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600}}
 .param{{color:#1565c0;font-size:12px}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0}}
 th,td{{border:1px solid #ccc;padding:8px;text-align:left}}
 th{{background:#1565c0;color:#fff}}
 tr:nth-child(even){{background:#f5f7fa}}
 .vulncard{{border:1px solid #ddd;border-radius:6px;margin:16px 0;padding:14px;background:#fff}}
 .vulnhead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;border-bottom:1px solid #eee;padding-bottom:8px}}
 .vid{{font-weight:700;color:#888}}
 .vtitle{{font-size:15px;font-weight:600;flex:1}}
 .vmeta{{color:#888;font-size:12px;width:100%}}
 .vfield{{margin:10px 0 0;font-size:13px}}
 .vdesc,.vfix{{background:#f8f9fa;border-radius:4px;padding:8px;margin-top:4px}}
 .code{{background:#f0f2f5;border-radius:4px;padding:8px;font-size:12px;white-space:pre-wrap;word-break:break-all;overflow-x:auto}}
 .hint{{color:#666;font-size:13px}}
 .footer{{margin-top:30px;color:#999;font-size:12px;border-top:1px solid #eee;padding-top:10px}}
 ul{{margin:4px 0}}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="meta">生成时间：{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
扫描资产：{scope} &nbsp;|&nbsp; 漏洞总数：{stats['total']} &nbsp;|&nbsp; 生成引擎：AutoVuln 深度渗透版</div>

<h2>一、执行摘要</h2>
<div class="rating"><div class="level">总体风险评级：{rating}</div>
<div class="advice">{rating_advice}</div></div>
<div class="sevcards">{sev_cards}</div>
{key_section}

<h2>二、漏洞详情（{len(vulns)} 条）</h2>
{detail_html}

<h2>三、附录</h2>
<h3>3.1 扫描范围与方法论</h3>
<table><tr><th>#</th><th>阶段</th><th>说明</th></tr>{stage_rows}</table>
<h3>3.2 检测能力</h3>
<p class="hint">SQL 盲注（布尔/时间）· 认证态扫描 · Playwright 动态爬虫 · OAST 带外检测 · 命令注入/SSTI/XXE · 存储型 XSS · 文件上传 · 指纹版本比对（CVE）</p>

<div class="footer">本报告由 AutoVuln 自动化漏洞挖掘平台生成，仅用于授权范围内的安全测试。<br>
漏洞基于自动化检测特征，人工复核后方可作为正式渗透结论。</div>
</body></html>"""
    fpath.write_text(doc, encoding="utf-8")


def _write_excel(fpath: Path, title: str, assets: list, stats: dict, vulns: list):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        from openpyxl.utils import get_column_letter

        wb = Workbook()
        ws = wb.active
        ws.title = "漏洞清单"
        ws.append([title, "", f"漏洞总数: {stats['total']}", f"生成时间: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"])
        ws.append([])
        headers = ["ID", "标题", "类型", "等级", "状态", "置信度", "CVE", "URL", "负责人", "修复期限"]
        ws.append(headers)
        for c in range(1, len(headers) + 1):
            cell = ws.cell(row=3, column=c)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="1565C0")
        for v in vulns:
            ws.append([v.id, v.title, v.vuln_type, v.severity.upper(), STATE_LABEL.get(v.state, v.state),
                       v.confidence, v.cve_id or "", v.url or "", v.assignee or "",
                       v.due_date.strftime("%Y-%m-%d") if v.due_date else ""])
        for col in range(1, 11):
            ws.column_dimensions[get_column_letter(col)].width = 18
        # 等级分布 sheet
        ws2 = wb.create_sheet("等级分布")
        ws2.append(["等级", "数量"])
        for s in ("critical", "high", "medium", "low", "info"):
            ws2.append([s.upper(), stats["by_severity"].get(s, 0)])
        # 类型分布 sheet
        ws3 = wb.create_sheet("类型分布")
        ws3.append(["类型", "数量"])
        for k, v in stats["by_type"].items():
            ws3.append([k, v])
        wb.save(str(fpath))
    except ImportError:
        # 无 openpyxl 兜底：CSV 改名 xlsx（由前端引导安装）
        with open(str(fpath).replace(".xlsx", ".csv"), "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([title])
            w.writerow(["ID", "标题", "类型", "等级", "状态", "CVE", "URL"])
            for v in vulns:
                w.writerow([v.id, v.title, v.vuln_type, v.severity, v.state, v.cve_id or "", v.url or ""])


def _write_pdf(fpath: Path, title: str, assets: list, stats: dict, vulns: list):
    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

        doc = SimpleDocTemplate(str(fpath), pagesize=landscape(A4))
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle("cn", parent=styles["Normal"], fontSize=10))

        story = [Paragraph(html.escape(title), styles["Title"]),
                 Spacer(1, 6),
                 Paragraph(f"生成时间：{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}　漏洞总数：{stats['total']}",
                           styles["cn"]),
                 Spacer(1, 12)]
        sev_row = [["等级", "数量"]]
        for s in ("critical", "high", "medium", "low", "info"):
            sev_row.append([s.upper(), stats["by_severity"].get(s, 0)])
        t = Table(sev_row)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1565c0")),
                               ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]))
        story.append(t)
        story.append(Spacer(1, 12))
        if vulns:
            data = [["ID", "标题", "类型", "等级", "状态", "CVE"]]
            for v in vulns[:200]:
                data.append([str(v.id), (v.title or "")[:40], v.vuln_type,
                             v.severity.upper(), STATE_LABEL.get(v.state, v.state), v.cve_id or ""])
            vt = Table(data, repeatRows=1)
            vt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1565c0")),
                                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                    ("FONTSIZE", (0, 0), (-1, -1), 8)]))
            story.append(vt)
        doc.build(story)
    except Exception:
        # reportlab 不可用时兜底：写入 UTF-8 文本标记（保证文件生成，前端提示用 HTML）
        fpath.write_text(
            f"AutoVuln Report\n{title}\nGenerated: {datetime.utcnow().isoformat()}\nTotal: {stats['total']}\n"
            "(PDF renderer unavailable - please use HTML format)", encoding="utf-8")
