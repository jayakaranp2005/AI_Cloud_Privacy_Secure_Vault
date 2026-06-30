"""
PrivaVault — PyMuPDF + Tesseract Text Extraction Service
Phase 3-5 | branch: feature/ai_privacy_flow

Responsibilities:
  - Extract raw text from PDF bytes in RAM
  - Fall back to OCR (Tesseract) for pages with no embedded text
    (scanned pages / image-only PDFs)
  - Preserve document structure (newlines, spacing, page breaks)
  - Handle per-page errors gracefully without killing the whole job
  - Validate PDFs before processing

Input:  Raw file bytes (bytearray from upload route)
Output: Extracted raw text string → passed to anonymizer.py

Position in Stream A:
  file bytes → [extractor.py] → raw text → anonymizer.py → gemini.py

Dependencies:
  pip install pymupdf pytesseract pillow
  System: tesseract-ocr binary must be installed
    - Ubuntu/Debian: apt-get install tesseract-ocr
    - macOS:         brew install tesseract
    - Windows:        install from UB-Mannheim build, set pytesseract.pytesseract.tesseract_cmd
"""

import io
import fitz          # PyMuPDF (pip install pymupdf)
import pytesseract   # pip install pytesseract
from PIL import Image


# ---------------------------------------------------------------------------
# Tuning knobs
# ---------------------------------------------------------------------------
OCR_MIN_CHARS = 20          # below this char count, treat page as "no text" -> OCR it
OCR_DPI_ZOOM = 2.0          # 2.0x zoom ~= 144 DPI; bump to 3.0 for tiny/blurry scans
OCR_LANG = "eng"            # tesseract language pack, e.g. "eng+fra" for multi-lang
OCR_CONFIG = "--psm 6"      # 6 = assume a uniform block of text; tune per doc type


# ---------------------------------------------------------------------------
# OCR helper — renders a single PDF page to an image and runs Tesseract
# ---------------------------------------------------------------------------
def _ocr_page(page: "fitz.Page") -> str:
    """
    Rasterizes a PDF page via PyMuPDF and extracts text with Tesseract.

    Why render through fitz instead of pdf2image/poppler?
        We already have the page object open in this process, so we can
        get pixel data directly via get_pixmap() with zero extra system
        dependencies (no poppler-utils needed, just the tesseract binary).

    Args:
        page: An open fitz.Page object

    Returns:
        str: OCR'd text for the page (empty string on failure)
    """
    try:
        matrix = fitz.Matrix(OCR_DPI_ZOOM, OCR_DPI_ZOOM)
        pix = page.get_pixmap(matrix=matrix, colorspace=fitz.csRGB)

        img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)

        text = pytesseract.image_to_string(img, lang=OCR_LANG, config=OCR_CONFIG)
        return text

    except pytesseract.TesseractNotFoundError:
        # Surface this distinctly — it's a deployment/config issue, not a bad PDF
        raise RuntimeError(
            "Tesseract binary not found on PATH. Install tesseract-ocr "
            "and/or set pytesseract.pytesseract.tesseract_cmd."
        )
    except Exception as ocr_err:
        print(f"[PrivaVault] WARNING: OCR failed on page: {ocr_err}")
        return ""


# ---------------------------------------------------------------------------
# Primary function — called by routes/upload.py Stream A block
# ---------------------------------------------------------------------------
def extract_text(file_bytes: bytes, max_pages: int = None, use_ocr: bool = True) -> str:
    """
    Extracts all text from a PDF, preserving page structure.
    Falls back to OCR per-page when embedded text is missing or sparse
    (e.g. scanned documents, image-only pages).

    Args:
        file_bytes : Raw PDF bytes (from UploadFile.read() in upload route)
        max_pages  : Cap extraction at N pages. None = all pages.
        use_ocr    : If True, OCR pages that yield < OCR_MIN_CHARS of text.
                     Set False to disable OCR fallback entirely (faster,
                     text-only PDFs).

    Returns:
        str: Full extracted text with page separators. Pages that were
             OCR'd are tagged "[OCR]" in their header so downstream
             consumers (anonymizer/Gemini) know confidence may be lower.

    Raises:
        ValueError: If the PDF is invalid, corrupted, or yields no text
                    even after OCR fallback
        RuntimeError: If OCR is requested but the tesseract binary is missing

    Why context manager?
        fitz.Document holds file handles internally. Without `with`, an
        exception between open() and close() leaks those handles until GC.
        The `with` block closes the document no matter what.
    """
    try:
        with fitz.open(stream=io.BytesIO(file_bytes), filetype="pdf") as pdf:
            total_pages   = pdf.page_count
            pages_to_read = min(total_pages, max_pages) if max_pages else total_pages

            extracted = []
            ocr_page_count = 0

            for page_num in range(pages_to_read):
                try:
                    page      = pdf[page_num]
                    page_text = page.get_text()   # plain text, structure preserved
                    was_ocrd  = False

                    # Fallback: sparse/empty embedded text -> try OCR
                    if use_ocr and len(page_text.strip()) < OCR_MIN_CHARS:
                        ocr_text = _ocr_page(page)
                        if len(ocr_text.strip()) > len(page_text.strip()):
                            page_text = ocr_text
                            was_ocrd = True
                            ocr_page_count += 1

                    # Page header so Gemini can reference page numbers
                    tag = " [OCR]" if was_ocrd else ""
                    if page_num == 0:
                        extracted.append(f"Page 1{tag}\n{'-' * 60}\n")
                    else:
                        extracted.append(f"\n{'=' * 60}\nPage {page_num + 1}{tag}\n{'=' * 60}\n")

                    extracted.append(page_text)

                except Exception as page_err:
                    # One bad page should not abort the entire document
                    print(f"[PrivaVault] WARNING: Skipping page {page_num + 1}: {page_err}")
                    continue

        full_text = "".join(extracted)

        if not full_text.strip():
            raise ValueError(
                "PDF contains no extractable text — "
                "even OCR fallback found nothing readable."
                if use_ocr else
                "PDF contains no extractable text — "
                "file may be a scanned image-only PDF (try use_ocr=True)."
            )

        print(
            f"[PrivaVault] Extracted {pages_to_read}/{total_pages} pages "
            f"({len(full_text):,} characters, {ocr_page_count} page(s) via OCR)"
        )
        return full_text

    except ValueError:
        raise   # pass ValueError through cleanly — upload route catches it
    except RuntimeError:
        raise   # pass tesseract-missing error through distinctly
    except Exception as e:
        raise ValueError(f"PDF extraction failed: {e}")


# ---------------------------------------------------------------------------
# PDF validator — call before extract_text to fail fast on bad uploads
# ---------------------------------------------------------------------------
def validate_pdf(file_bytes: bytes) -> bool:
    """
    Returns True if the bytes represent a valid, non-empty PDF.
    Use this in the upload route before running the full extraction.

    Does NOT raise — returns False on any problem so the caller
    can return a clean HTTP 400 instead of an unhandled 500.
    """
    try:
        with fitz.open(stream=io.BytesIO(file_bytes), filetype="pdf") as pdf:
            return pdf.page_count > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Metadata extractor — optional, useful for enriching Gemini's context
# ---------------------------------------------------------------------------
def extract_metadata(file_bytes: bytes) -> dict:
    """
    Pulls embedded PDF metadata (title, author, subject, creation date).

    Returns an empty dict on failure — never raises so it never
    blocks the main extraction pipeline.

    Useful for:
      - Supplementing Gemini's context with the document's declared title
      - Detecting document type from the 'subject' field
      - Debug logging
    """
    try:
        with fitz.open(stream=io.BytesIO(file_bytes), filetype="pdf") as pdf:
            raw = pdf.metadata or {}

        # Strip None values and empty strings
        metadata = {k: v for k, v in raw.items() if v}
        print(f"[PrivaVault] PDF metadata: {metadata}")
        return metadata

    except Exception as e:
        print(f"[PrivaVault] WARNING: Metadata extraction failed: {e}")
        return {}