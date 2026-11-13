"""Create a clean, paginated PDF summary for a passive website scan."""

import re


WIDTH, HEIGHT = 595, 842  # A4
NAVY = (0.035, 0.075, 0.14)
INK = (0.10, 0.16, 0.24)
MUTED = (0.38, 0.45, 0.54)
PALE = (0.95, 0.97, 0.99)
TEAL = (0.0, 0.78, 0.59)
RED = (0.78, 0.19, 0.23)
AMBER = (0.75, 0.45, 0.04)
GREEN = (0.12, 0.48, 0.32)


def _safe(value):
    return str(value or "").encode("ascii", "replace").decode("ascii")


def _pdf_string(value):
    return _safe(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(value, limit):
    words = re.sub(r"\s+", " ", _safe(value)).strip().split(" ")
    lines, current = [], ""
    for word in words:
        while len(word) > limit:
            if current:
                lines.append(current)
                current = ""
            lines.append(word[:limit])
            word = word[limit:]
        candidate = f"{current} {word}".strip()
        if len(candidate) > limit and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def _text(x, y, value, size=10, color=INK, font="F1"):
    r, g, b = color
    return f"q {r:.3f} {g:.3f} {b:.3f} rg BT /{font} {size} Tf 1 0 0 1 {x:.1f} {y:.1f} Tm ({_pdf_string(value)}) Tj ET Q"


def _rect(x, y, w, h, color, stroke=None):
    r, g, b = color
    command = f"q {r:.3f} {g:.3f} {b:.3f} rg"
    if stroke:
        sr, sg, sb = stroke
        command += f" {sr:.3f} {sg:.3f} {sb:.3f} RG 0.7 w"
    return f"{command} {x} {y} {w} {h} re {'B' if stroke else 'f'} Q"


def _line(x1, y1, x2, y2, color):
    r, g, b = color
    return f"q {r:.3f} {g:.3f} {b:.3f} RG 0.7 w {x1} {y1} m {x2} {y2} l S Q"


def build_site_report_pdf(report):
    checks = report.get("checks") if isinstance(report.get("checks"), list) else []
    checks = [item for item in checks[:100] if isinstance(item, dict)]
    issues = [item for item in checks if item.get("status") in ("fail", "warn")]
    counts = report.get("counts") if isinstance(report.get("counts"), dict) else {}
    pages, commands = [], []

    def start_page(first=False):
        nonlocal commands, y
        if commands:
            pages.append(commands)
        commands = [_rect(0, 0, WIDTH, HEIGHT, PALE)]
        if first:
            commands.extend([_rect(0, 682, WIDTH, 160, NAVY),
                             _text(42, 801, "CYBER SENTINEL  /  SECURITY ASSESSMENT", 9, TEAL, "F2"),
                             _text(42, 767, "Website Security Report", 25, (1, 1, 1), "F2"),
                             _text(42, 743, _wrap(report.get("url", ""), 65)[0], 10, (0.78, 0.84, 0.90)),
                             _text(42, 725, f"Checked {report.get('checked_at', '—')}   |   HTTP {report.get('status_code', '—')}", 9, (0.70, 0.78, 0.86)),
                             _rect(422, 710, 131, 93, (0.08, 0.15, 0.23), (0.22, 0.32, 0.41)),
                             _text(435, 783, "RISK LEVEL", 8, (0.69, 0.77, 0.84), "F2"),
                             _text(435, 754, _safe(report.get("risk_level", "Unknown")).upper(), 16, TEAL if str(report.get("risk_level", "")).lower() == "low" else AMBER, "F2"),
                             _text(435, 733, f"Score  {report.get('risk_score', 0)} / 100", 9, (1, 1, 1)),
                             _text(435, 718, f"Website grade  {report.get('grade', '—')}", 8, (0.78, 0.84, 0.90))])
            commands.append(_text(42, 651, "SCAN OVERVIEW", 10, MUTED, "F2"))
            metrics = [("ISSUES", len(issues), RED), ("WARNINGS", counts.get("warn", sum(c.get("status") == "warn" for c in checks)), AMBER),
                       ("PASSED CHECKS", counts.get("pass", sum(c.get("status") == "pass" for c in checks)), GREEN)]
            for index, (label, value, color) in enumerate(metrics):
                x = 42 + index * 174
                commands.extend([_rect(x, 585, 160, 49, (1, 1, 1), (0.86, 0.89, 0.92)),
                                 _text(x + 12, 615, label, 8, MUTED, "F2"),
                                 _text(x + 12, 593, value, 17, color, "F2")])
            commands.append(_text(42, 557, "FINDINGS & RECOMMENDATIONS", 10, MUTED, "F2"))
            y = 538
        else:
            commands.extend([_rect(0, 785, WIDTH, 57, NAVY),
                             _text(42, 811, "CYBER SENTINEL  /  WEBSITE SECURITY REPORT", 9, TEAL, "F2"),
                             _text(42, 793, _wrap(report.get("url", ""), 80)[0], 9, (0.82, 0.87, 0.92))])
            y = 755

    start_page(first=True)
    if not issues:
        commands.extend([_rect(42, 474, 511, 54, (1, 1, 1), (0.86, 0.89, 0.92)),
                         _text(58, 504, "No issues found", 12, GREEN, "F2"),
                         _text(58, 485, "No failing or warning checks were reported in this scan.", 9, MUTED)])
    for item in issues:
        status = str(item.get("status", "warn")).lower()
        title_lines = _wrap(item.get("title", "Security check"), 68)
        detail_lines = _wrap(item.get("detail", ""), 88)
        fix_lines = _wrap(item.get("fix", "Review this configuration."), 88) if item.get("fix") else []
        height = 38 + len(title_lines) * 13 + len(detail_lines) * 12 + (17 + len(fix_lines) * 12 if fix_lines else 0)
        if y - height < 62:
            start_page()
        accent = RED if status == "fail" else AMBER
        commands.extend([_rect(42, y - height, 511, height, (1, 1, 1), (0.86, 0.89, 0.92)),
                         _rect(42, y - height, 4, height, accent),
                         _text(58, y - 20, status.upper(), 7, accent, "F2")])
        cursor = y - 36
        for line in title_lines:
            commands.append(_text(58, cursor, line, 11, INK, "F2")); cursor -= 13
        cursor -= 2
        for line in detail_lines:
            commands.append(_text(58, cursor, line, 8.5, MUTED)); cursor -= 12
        if fix_lines:
            cursor -= 3
            commands.append(_text(58, cursor, "RECOMMENDATION", 7, TEAL, "F2")); cursor -= 13
            for line in fix_lines:
                commands.append(_text(58, cursor, line, 8.5, INK)); cursor -= 12
        y -= height + 10

    if not checks:
        commands.append(_text(42, 520, "No individual checks were included in this report.", 9, MUTED))

    page_count = len(pages) + 1
    pages.append(commands)
    for page_number, page in enumerate(pages, 1):
        page.extend([_line(42, 43, 553, 43, (0.84, 0.88, 0.92)),
                     _text(42, 27, "CYBER SENTINEL  |  Passive website security checks", 8, MUTED),
                     _text(505, 27, f"{page_number} / {page_count}", 8, MUTED)])

    objects = [b"<< /Type /Catalog /Pages 2 0 R >>"]
    page_ids = [3 + 2 * i for i in range(len(pages))]
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())
    for page_id, page in zip(page_ids, pages):
        stream = "\n".join(page).encode("ascii")
        content_id = page_id + 1
        objects.extend([
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {WIDTH} {HEIGHT}] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> /F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> >> >> /Contents {content_id} 0 R >>".encode(),
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        ])

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())
    pdf.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(pdf)
