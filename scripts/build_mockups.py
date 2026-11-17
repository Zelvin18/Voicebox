"""Render docs/mockups/voicebox-mockups.html to a PDF and per-page PNG previews.

Usage:  python scripts/build_mockups.py
Needs:  Google Chrome (or Edge) and `pip install pymupdf`
"""
import os
import subprocess
import sys
from pathlib import Path

import pymupdf

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "mockups" / "voicebox-mockups.html"
PDF = ROOT / "docs" / "Voicebox-Mockups.pdf"
SCREENS = ROOT / "docs" / "screens"
NAMES = [
    "00-cover", "01-design-language", "02-sign-in", "03-student-dashboard",
    "04-new-complaint", "05-complaint-detail", "06-staff-cases",
    "07-admin-assign", "08-audit-log", "09-mobile",
]
BROWSERS = [
    os.environ.get("CHROME_PATH", ""),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
]


def main() -> int:
    browser = next((b for b in BROWSERS if b and Path(b).exists()), None)
    if browser is None:
        print("Chrome or Edge not found. Set CHROME_PATH.", file=sys.stderr)
        return 1

    subprocess.run(
        [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
         f"--print-to-pdf={PDF}", SOURCE.as_uri()],
        check=True,
    )

    SCREENS.mkdir(exist_ok=True)
    with pymupdf.open(PDF) as doc:
        for page, name in zip(doc, NAMES):
            page.get_pixmap(dpi=96).save(SCREENS / f"{name}.png")
        print(f"Wrote {PDF.name} ({len(doc)} pages) and previews in docs/screens/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
