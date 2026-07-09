"""
PrivaVault — PyMuPDF + Tesseract Text Extraction Service
Phase 3-5 | branch: feature/ai_privacy_flow

Extraction strategy (per-page two-pass):
  Pass 1 — PyMuPDF native text extraction (fast, zero dependencies)
  Pass 2 — Tesseract OCR fallback per page (for scanned/image-only pages)

Pass 2 only runs on pages where Pass 1 yields fewer than OCR_MIN_CHARS
characters — meaning that specific page has no embedded text layer.
This handles mixed PDFs (some pages text, some pages scanned) correctly.

OCR setup:
  pip install pytesseract Pillow
  Ubuntu VM : sudo apt install tesseract-ocr
  Windows   : install from https://github.com/UB-Mannheim/tesseract/wiki
              add to .env: TESSERACT_PATH=C:\\Program Files\\Tesseract-OCR\\tesseract.exe

Input:  Raw file bytes (bytearray from upload route)
Output: Extracted raw text string → passed to anonymizer.py

Position in Stream A:
  file bytes → [extractor.py] → raw text → anonymizer.py → gemini.py
"""

import io
import os

import fitz  # PyMuPDF


# ---------------------------------------------------------------------------
# Graceful OCR availability check
# ---------------------------------------------------------------------------
# App starts fine without pytesseract/Pillow installed.
# Text-based PDFs work normally. Image-only PDFs get a clear error message
# telling the user what to install — no cryptic ImportError crash.

try:
    import pytesseract
    from PIL import Image

    # Windows: Tesseract binary not on PATH by default.
    # Set TESSERACT_PATH in .env → used locally on Windows.
    # Ubuntu VM: variable not set → pytesseract uses system PATH automatically.
    # One codebase, works both environments.
    _tesseract_path = os.getenv("TESSERACT_PATH")
    if _tesseract_path:
        pytesseract.pytesseract.tesseract_cmd = _tesseract_path

    _OCR_AVAILABLE = True
    print("[PrivaVault] Tesseract OCR available.")

except ImportError:
    _OCR_AVAILABLE = False
    print("[PrivaVault] pytesseract/Pillow not installed — image-only PDFs not supported.")


# ---------------------------------------------------------------------------
# Tuning knobs
# ---------------------------------------------------------------------------

# Pages with fewer than this many characters are considered image-only
# and get passed to Tesseract. Aadhaar cards yield 400-800 chars normally.
# 20 chars catches pages that have only a header or footer embedded as text.
OCR_MIN_CHARS = 20

# 300 DPI is the standard for document OCR.
# Formula: DPI / 72 = PyMuPDF zoom factor (72 is fitz's base resolution)
# 2.0x ≈ 144 DPI — too low, misses small text on ID cards
# 4.17x ≈ 300 DPI — standard, catches all normal document text
OCR_DPI_ZOOM  = 300 / 72   # 4.17x zoom → 300 DPI

# Tesseract page segmentation mode:
# 6 = "Assume a single uniform block of text" — best for ID cards and forms
OCR_LANG      = "eng"
OCR_CONFIG    = "--psm 6"


# ---------------------------------------------------------------------------
# Internal OCR helper — one page at a time
# ---------------------------------------------------------------------------

def _ocr_page(page: fitz.Page) -> str:
    """
    Rasterizes a single PDF page at 300 DPI and runs Tesseract OCR on it.

    Why render through fitz instead of pdf2image/poppler?
        We already have the page object open — get_pixmap() gives us
        pixel data with zero extra system dependencies. No poppler needed.

    Args:
        page: An open fitz.Page object

    Returns:
        str: OCR'd text (empty string if OCR yields nothing)

    Raises:
        RuntimeError: If Tesseract binary is not found — deployment issue,
                      not a bad PDF. Surfaced separately from other errors.
    """
    try:
        matrix  = fitz.Matrix(OCR_DPI_ZOOM, OCR_DPI_ZOOM)
        pixmap  = page.get_pixmap(matrix=matrix, colorspace=fitz.csRGB)
        img     = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
        text    = pytesseract.image_to_string(img, lang=OCR_LANG, config=OCR_CONFIG)
        return text

    except pytesseract.TesseractNotFoundError:
        # Surface this separately — it's a config/deployment issue
        raise RuntimeError(
            "Tesseract binary not found. "
            "Ubuntu: sudo apt install tesseract-ocr | "
            "Windows: install from UB-Mannheim and set TESSERACT_PATH in .env"
        )
    except Exception as ocr_err:
        print(f"[PrivaVault] WARNING: OCR failed on page: {ocr_err}")
        return ""


# ---------------------------------------------------------------------------
# Primary function — called by routes/upload.py Stream A block
# ---------------------------------------------------------------------------

def extract_text(file_bytes: bytes, max_pages: int = None, use_ocr: bool = True) -> str:
    """
    Extracts text from a PDF using a per-page two-pass strategy.

    For each page:
      - Try PyMuPDF native extraction first (fast)
      - If result < OCR_MIN_CHARS, fall back to Tesseract OCR
      - Use whichever result is longer

    This handles mixed PDFs correctly — a 5-page document where pages
    1-3 are text and pages 4-5 are scanned images works fine.

    Args:
        file_bytes : Raw PDF bytes
        max_pages  : Cap at N pages. None = all pages.
        use_ocr    : Set False to skip OCR entirely (faster, text PDFs only)

    Returns:
        str: Full extracted text. OCR'd pages tagged with [OCR] in header.

    Raises:
        ValueError   : PDF invalid, corrupted, or yields no text after all passes
        RuntimeError : Tesseract binary missing (surfaces as deployment error)
    """
    try:
        with fitz.open(stream=io.BytesIO(file_bytes), filetype="pdf") as pdf:
            total_pages    = pdf.page_count
            pages_to_read  = min(total_pages, max_pages) if max_pages else total_pages

            extracted      = []
            ocr_page_count = 0

            for page_num in range(pages_to_read):
                try:
                    page      = pdf[page_num]
                    page_text = page.get_text()
                    was_ocrd  = False

                    # OCR fallback — only if native text is sparse
                    if use_ocr and len(page_text.strip()) < OCR_MIN_CHARS:

                        if not _OCR_AVAILABLE:
                            raise ValueError(
                                "PDF page appears image-only but pytesseract/Pillow "
                                "are not installed.\n"
                                "Fix: pip install pytesseract Pillow\n"
                                "Then install Tesseract binary:\n"
                                "  Ubuntu: sudo apt install tesseract-ocr\n"
                                "  Windows: https://github.com/UB-Mannheim/tesseract/wiki"
                            )

                        ocr_text = _ocr_page(page)

                        # Use OCR result only if it found more text than native
                        if len(ocr_text.strip()) > len(page_text.strip()):
                            page_text = ocr_text
                            was_ocrd  = True
                            ocr_page_count += 1

                    # Page header — [OCR] tag signals lower-confidence text to Gemini
                    tag = " [OCR]" if was_ocrd else ""
                    if page_num == 0:
                        extracted.append(f"Page 1{tag}\n{'-' * 60}\n")
                    else:
                        extracted.append(f"\n{'=' * 60}\nPage {page_num + 1}{tag}\n{'=' * 60}\n")

                    extracted.append(page_text)

                except (ValueError, RuntimeError):
                    raise   # let these through — they're not page-level errors
                except Exception as page_err:
                    print(f"[PrivaVault] WARNING: Skipping page {page_num + 1}: {page_err}")
                    continue

        full_text = "".join(extracted)

        if not full_text.strip():
            raise ValueError(
                "PDF contains no extractable text even after OCR. "
                "File may be blank, corrupted, or a non-standard scan."
                if use_ocr else
                "PDF contains no extractable text. "
                "File may be image-only — retry with OCR enabled."
            )

        print(
            f"[PrivaVault] Extracted {pages_to_read}/{total_pages} pages "
            f"({len(full_text):,} characters, {ocr_page_count} page(s) via OCR)"
        )
        return full_text

    except (ValueError, RuntimeError):
        raise
    except Exception as e:
        raise ValueError(f"PDF extraction failed: {e}")


# ---------------------------------------------------------------------------
# PDF validator
# ---------------------------------------------------------------------------

def validate_pdf(file_bytes: bytes) -> bool:
    """
    Returns True if file_bytes is a valid non-empty PDF.
    Never raises — returns False on any problem.
    """
    try:
        with fitz.open(stream=io.BytesIO(file_bytes), filetype="pdf") as pdf:
            return pdf.page_count > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Metadata extractor
# ---------------------------------------------------------------------------

def extract_metadata(file_bytes: bytes) -> dict:
    """
    Pulls embedded PDF metadata (title, author, creation date, etc.)
    Returns empty dict on failure — never blocks the main pipeline.
    """
    try:
        with fitz.open(stream=io.BytesIO(file_bytes), filetype="pdf") as pdf:
            raw = pdf.metadata or {}
        metadata = {k: v for k, v in raw.items() if v}
        print(f"[PrivaVault] PDF metadata: {metadata}")
        return metadata
    except Exception as e:
        print(f"[PrivaVault] WARNING: Metadata extraction failed: {e}")
        return {}