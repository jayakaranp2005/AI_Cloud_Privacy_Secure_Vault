"""
PrivaVault — PyMuPDF Text Extraction Service
Phase 3-5 | branch: feature/ai_privacy_flow

Responsibilities:
  - Extract text from PDF files using PyMuPDF (fitz)
  - Support multiple document types (PDFs, images embedded in PDFs)
  - Return raw text preserving structure (newlines, spacing)
  - Handle extraction errors gracefully

Input: Raw file bytes (PDF from upload)
Output: Extracted raw text (sent to anonymizer.py)

Note:
  This service runs early in Stream A, before any Presidio scanning.
  Extracted text MUST preserve document structure — headers, lists,
  tables — so the anonymizer can maintain context, and Gemini can
  understand the semantic structure.
"""

import io

import fitz  # PyMuPDF


# ---------------------------------------------------------------------------
# Extract text from PDF bytes
# ---------------------------------------------------------------------------
def extract_text(file_bytes: bytes, max_pages: int = None) -> str:
    """
    Extracts text from a PDF file.
    
    Args:
        file_bytes (bytes): Raw PDF file data
        max_pages (int, optional): Limit extraction to first N pages.
                                  None = extract all pages (default)
    
    Returns:
        str: Extracted text with structure preserved (newlines, spacing)
    
    Raises:
        ValueError: If file is not a valid PDF or extraction fails
    
    Flow:
      1. Open PDF from bytes using fitz.open()
      2. Iterate through pages (limited by max_pages if set)
      3. Extract text from each page
      4. Join pages with page separator for clarity
      5. Return full text
    
    Example:
        >>> pdf_bytes = open("invoice.pdf", "rb").read()
        >>> text = extract_text(pdf_bytes)
        >>> print(text[:100])
        "Invoice #12345..."
    """
    try:
        # Open PDF from bytes
        pdf_document = fitz.open(stream=file_bytes, filetype="pdf")
        
        # Determine page count
        total_pages = pdf_document.page_count
        pages_to_extract = min(total_pages, max_pages) if max_pages else total_pages
        
        extracted_text = []
        
        for page_num in range(pages_to_extract):
            try:
                page = pdf_document[page_num]
                page_text = page.get_text()  # Extract text from page
                
                # Add page separator if not the first page
                if page_num > 0:
                    extracted_text.append(f"\n{'='*60}\nPage {page_num + 1}\n{'='*60}\n")
                else:
                    extracted_text.append(f"Page {page_num + 1}\n{'-'*60}\n")
                
                extracted_text.append(page_text)
            
            except Exception as page_error:
                print(f"[PrivaVault] WARNING: Could not extract text from page {page_num + 1}: {page_error}")
                # Continue with next page instead of failing entirely
                continue
        
        pdf_document.close()
        
        full_text = "".join(extracted_text)
        
        if not full_text.strip():
            raise ValueError("PDF extracted text is empty — file may be image-only or corrupted")
        
        print(f"[PrivaVault] Extracted {pages_to_extract} pages from PDF ({len(full_text)} characters)")
        return full_text
    
    except Exception as e:
        print(f"[PrivaVault] ERROR extracting text from PDF: {e}")
        raise ValueError(f"PDF extraction failed: {str(e)}")


# ---------------------------------------------------------------------------
# Extract text with OCR fallback (future enhancement)
# ---------------------------------------------------------------------------
def extract_text_with_ocr_fallback(
    file_bytes: bytes,
    use_ocr: bool = False,
    max_pages: int = None
) -> str:
    """
    Extracts text from PDF with optional OCR fallback for image-only PDFs.
    
    Args:
        file_bytes (bytes): Raw PDF file data
        use_ocr (bool): If True, attempt OCR on image-only pages
                       (requires Tesseract installed — not in Phase 1-2)
        max_pages (int, optional): Limit extraction to first N pages
    
    Returns:
        str: Extracted text
    
    Note:
        OCR support is a Phase 3+ enhancement. In Phase 1-2, use_ocr
        is ignored and we rely on PyMuPDF's native text extraction.
        
        To enable OCR in the future:
          pip install pytesseract
          Install Tesseract-OCR from https://github.com/UB-Mannheim/tesseract/wiki
    """
    try:
        # Try standard text extraction first
        text = extract_text(file_bytes, max_pages=max_pages)
        return text
    
    except ValueError as e:
        if use_ocr:
            print(f"[PrivaVault] Standard extraction failed ({e}) — attempting OCR...")
            # TODO: Implement pytesseract OCR fallback in Phase 3+
            # For now, re-raise the error
            raise
        else:
            raise


# ---------------------------------------------------------------------------
# Extract metadata from PDF
# ---------------------------------------------------------------------------
def extract_metadata(file_bytes: bytes) -> dict:
    """
    Extracts metadata from PDF (title, author, creation date, etc.).
    
    Args:
        file_bytes (bytes): Raw PDF file data
    
    Returns:
        dict: Metadata dictionary with keys like 'title', 'author', 'subject', etc.
    
    Useful for:
      - Logging/debugging
      - Supplementing Gemini summaries with document title
      - Detecting document classification from embedded metadata
    """
    try:
        pdf_document = fitz.open(stream=file_bytes, filetype="pdf")
        metadata = pdf_document.metadata
        pdf_document.close()
        
        # Clean up metadata (some values may be None)
        clean_metadata = {k: v for k, v in (metadata or {}).items() if v is not None}
        
        print(f"[PrivaVault] Extracted PDF metadata: {clean_metadata}")
        return clean_metadata
    
    except Exception as e:
        print(f"[PrivaVault] WARNING: Could not extract PDF metadata: {e}")
        return {}


# ---------------------------------------------------------------------------
# Validate PDF structure
# ---------------------------------------------------------------------------
def validate_pdf(file_bytes: bytes) -> bool:
    """
    Checks if file is a valid PDF.
    
    Args:
        file_bytes (bytes): Raw file data
    
    Returns:
        bool: True if valid PDF, False otherwise
    
    Useful for early validation before processing.
    """
    try:
        pdf_document = fitz.open(stream=file_bytes, filetype="pdf")
        is_valid = pdf_document.page_count > 0
        pdf_document.close()
        return is_valid
    
    except Exception as e:
        print(f"[PrivaVault] PDF validation failed: {e}")
        return False


print("[PrivaVault] PyMuPDF text extraction service initialized.")
