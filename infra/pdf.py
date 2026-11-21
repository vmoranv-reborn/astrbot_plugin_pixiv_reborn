"""PDF 生成工具。

字体路径以插件包根目录为准，避免不同模块各自拼接路径导致字体丢失。
"""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

FONT_PATH = Path(__file__).resolve().parent.parent / "data" / "SmileySans-Oblique.ttf"


def create_pdf_from_text(title: str, text: str, font_path: Path | None = None) -> bytes:
    """将纯文本渲染为中文 PDF 字节流。"""

    resolved_font = font_path or FONT_PATH
    if not resolved_font.exists():
        raise FileNotFoundError(f"字体文件不存在: {resolved_font}")

    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("SmileySans", "", str(resolved_font))
    pdf.set_font("SmileySans", size=20)
    pdf.multi_cell(0, 10, title, align="C")
    pdf.ln(10)
    pdf.set_font_size(12)
    pdf.multi_cell(0, 10, text)
    return bytes(pdf.output())
