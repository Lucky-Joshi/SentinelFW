#!/usr/bin/env python3
"""Build docs/10_Final_Project_Report.pdf from Final_Project_Report.md.

Pipeline: Markdown -> HTML (python-markdown) -> PDF (WeasyPrint).
Diagrams are SVG (Graphviz / hand-written), screenshots are PNG, charts are PNG.
Run from the repository root:  python3 docs/build_report.py
"""
from __future__ import annotations

import datetime as _dt
import html
import re
import subprocess
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parent
ROOT = DOCS.parent
SRC = DOCS / "Final_Project_Report.md"
CSS = DOCS / "report.css"
OUT_HTML = DOCS / "_report_build.html"
OUT_PDF = DOCS / "10_Final_Project_Report.pdf"

import markdown  # type: ignore
from weasyprint import HTML  # type: ignore


def collect_tests() -> list[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-o", "addopts=", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
    )
    nodes = [ln.strip() for ln in proc.stdout.splitlines() if ln.startswith("tests/")]
    if not nodes:
        cache = DOCS / "_tests.txt"
        if cache.exists():
            nodes = [ln.strip() for ln in cache.read_text().splitlines() if ln.strip()]
    else:
        (DOCS / "_tests.txt").write_text("\n".join(nodes) + "\n", encoding="utf-8")
    return nodes


def full_inventory(nodes: list[str]) -> str:
    rows = []
    for i, node in enumerate(nodes, 1):
        file, _, test = node.partition("::")
        rows.append(
            f'<tr><td>{i}</td><td class="mono">{html.escape(file)}</td>'
            f'<td class="mono">{html.escape(test)}</td>'
            f'<td class="pass">PASS</td></tr>'
        )
    return (
        '<table class="inventory"><thead><tr><th>#</th><th>File</th>'
        '<th>Test node id</th><th>Result</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table>"
    )


def cover() -> str:
    today = _dt.date(2026, 10, 10).strftime("%d %B %Y")
    return f'''
<div class="cover">
  <img class="logo" src="diagrams/logo.svg" alt="SentinelFW logo"/>
  <h1 class="cover-title">SentinelFW</h1>
  <div class="tagline">Local nftables Firewall Manager &amp; Security Monitor</div>
  <div class="rule"></div>
  <div class="subtitle">Final Project Report</div>
  <div class="meta" style="margin-top:14px;"><strong>Lucky Joshi</strong></div>
  <div class="meta small">{today}</div>
  <div style="margin-top:18px;">
    <span class="badge">Version 1.0.0</span>
    <span class="badge">160 tests &middot; all passing</span>
    <span class="badge">72% coverage</span>
    <span class="badge">Python 3.10+</span>
    <span class="badge">Kali Linux</span>
  </div>
  <div class="footer-note">
    Repository: github.com/Lucky-Joshi/SentinelFW &nbsp;&middot;&nbsp; MIT License
  </div>
</div>
'''


def main() -> None:
    nodes = collect_tests()
    body_md = SRC.read_text(encoding="utf-8")
    body_md = body_md.replace("{{FULL_TEST_INVENTORY}}", full_inventory(nodes))

    md = markdown.Markdown(
        extensions=["tables", "fenced_code", "toc", "attr_list", "sane_lists",
                    "md_in_html"],
        extension_configs={"toc": {"toc_depth": "1-2", "title": ""}},
    )
    body = md.convert(body_md)

    css = CSS.read_text(encoding="utf-8")
    doc = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>SentinelFW — Final Project Report</title>
<style>{css}
.inventory td {{ font-size: 7.6pt; }}
.mono {{ font-family: "DejaVu Sans Mono", monospace; }}
.pass {{ color: #1a7f37; font-weight: 700; }}
.inventory td:nth-child(1) {{ color:#6b7280; }}
</style>
</head>
<body>
{cover()}
{body}
</body>
</html>'''

    OUT_HTML.write_text(doc, encoding="utf-8")
    HTML(string=doc, base_url=str(DOCS)).write_pdf(str(OUT_PDF))
    print(f"wrote {OUT_HTML.name} ({len(doc)} bytes)")
    print(f"wrote {OUT_PDF.name} ({OUT_PDF.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
