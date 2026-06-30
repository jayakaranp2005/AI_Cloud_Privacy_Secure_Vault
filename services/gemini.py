"""
PrivaVault — Gemini API Service
Phase 3-5 | branch: feature/ai_privacy_flow

Responsibilities:
  - Send anonymized document text to Gemini
  - Parse structured JSON response (summary + tags)
  - Retry on transient API errors
  - Never receive or log raw PII — only sanitized text arrives here

Input:  Sanitized text from anonymizer.py  (placeholders only, no real PII)
Output: {"summary": "...", "tags": [...]}  → stored in documents table

Position in Stream A:
  extractor.py → anonymizer.py → sanitized text → [gemini.py] → summary + tags

CRITICAL BOUNDARY:
  This file is the last step in Stream A. By the time text arrives here,
  Presidio has already replaced all PII with placeholders. This file must
  NEVER receive raw_text directly from extractor.py — always from anonymizer.py.
  The upload route enforces this order. Do not bypass it.
"""

import json
import os
import re
import time
from typing import Optional

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY")

# Model is configurable via env so you can switch between
# gemini-1.5-flash / gemini-2.0-flash / gemini-2.5-flash-lite
# without touching code. Default matches docs spec (free tier).
_GEMINI_MODEL    = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")

_MAX_RETRIES     = 3      # how many times to retry on transient errors
_RETRY_DELAY     = 2.0    # seconds between retries (doubles each attempt)
_MAX_INPUT_CHARS = 30_000 # safety cap — truncate very long docs before sending


# ---------------------------------------------------------------------------
# Singleton model instance
# ---------------------------------------------------------------------------
# Initializing the Gemini client is cheap, but we still cache it to avoid
# re-reading env vars and re-configuring on every upload request.

_model: Optional[genai.GenerativeModel] = None


def _get_model() -> genai.GenerativeModel:
    """
    Configures and caches the Gemini GenerativeModel.
    Raises RuntimeError if GEMINI_API_KEY is not set.
    """
    global _model
    if _model is not None:
        return _model

    if not _GEMINI_API_KEY:
        raise RuntimeError(
            "GEMINI_API_KEY not set in environment. "
            "Get a free key at https://aistudio.google.com and add it to .env"
        )

    genai.configure(api_key=_GEMINI_API_KEY)
    _model = genai.GenerativeModel(_GEMINI_MODEL)
    print(f"[PrivaVault] Gemini model ready: {_GEMINI_MODEL}")
    return _model


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------
# Key design decisions in this prompt:
#
# 1. Tell Gemini the text is pre-anonymized.
#    Without this, Gemini may try to infer real names from context and
#    mention them in the summary — exactly what we're trying to prevent.
#
# 2. Explicitly forbid placeholder values in output.
#    We don't want "[PERSON_1] submitted the form" in the summary.
#    Gemini should describe roles/actions without naming entities.
#
# 3. Strict JSON only — no markdown, no explanation, no preamble.
#    Easier to parse reliably. We strip code fences as a fallback.
#
# 4. 2-sentence summary cap keeps ai_summary column manageable
#    and forces Gemini to be precise rather than verbose.

_PROMPT_TEMPLATE = """
You are a document classification assistant for a secure enterprise document vault.

The document text below has been pre-processed for privacy — personal identifiers
such as names, ID numbers, phone numbers, and addresses have been replaced with
anonymization placeholders like [PERSON_1], [AADHAAR_REDACTED], [PAN_REDACTED],
[EMAIL_1], [PHONE_1], [LOCATION_1], etc.

Do NOT attempt to guess or restore the original values behind these placeholders.
Do NOT include placeholder tokens like [PERSON_1] in your output.
Describe document roles and actions in general terms (e.g. "the applicant", "the issuing authority").

Analyze the document's content and purpose, then return ONLY a valid JSON object
in this exact format — no markdown, no code fences, no explanation, just the JSON:

{{
  "summary": "First sentence describing the document type and primary purpose. Second sentence describing the key content or outcome.",
  "tags": ["tag1", "tag2", "tag3"]
}}

Rules:
- summary: exactly 2 sentences. Factual, based on document content only.
- tags: 3 to 5 short searchable keywords. Use document category terms like:
  "Government ID", "Medical Record", "Invoice", "Legal Document",
  "Tax Filing", "Bank Statement", "Insurance", "Property", "Employment", etc.
- Both fields are required. Return nothing outside the JSON object.

Document text:
---
{text}
---
""".strip()


# ---------------------------------------------------------------------------
# JSON extraction helper
# ---------------------------------------------------------------------------

def _extract_json(raw_response: str) -> dict:
    """
    Parses Gemini's response text into a Python dict.

    Handles two cases:
      1. Clean JSON  — just parse directly
      2. Markdown wrapped — ```json { ... } ``` — strip fences first

    Raises:
        ValueError: if the response cannot be parsed as valid JSON
                    or if required keys are missing / wrong types
    """
    text = raw_response.strip()

    # Strip markdown code fences if present (```json ... ``` or ``` ... ```)
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Gemini returned non-JSON response: {e}\nRaw: {text[:300]}")

    # Validate required keys
    if "summary" not in data or not isinstance(data["summary"], str):
        raise ValueError(f"Gemini response missing valid 'summary' field: {data}")

    if "tags" not in data or not isinstance(data["tags"], list):
        raise ValueError(f"Gemini response missing valid 'tags' list: {data}")

    # Enforce tag count constraints (3-5 per GeminiResponse schema)
    tags = [str(t).strip() for t in data["tags"] if str(t).strip()]
    if len(tags) < 3:
        raise ValueError(f"Gemini returned fewer than 3 tags: {tags}")

    return {
        "summary": data["summary"].strip(),
        "tags":    tags[:5],   # cap at 5 even if Gemini returns more
    }


# ---------------------------------------------------------------------------
# Main function — called by routes/upload.py Stream A block
# ---------------------------------------------------------------------------

def get_summary_and_tags(sanitized_text: str) -> dict:
    """
    Sends sanitized (anonymized) text to Gemini and returns
    a structured summary + tag list.

    Args:
        sanitized_text: Output from anonymizer.anonymize()["sanitized_text"]
                        Must NOT be raw extracted text — PII must already
                        be replaced with placeholders before calling this.

    Returns:
        dict with keys:
          summary : str        — 2-sentence document description
          tags    : list[str]  — 3-5 searchable category keywords

    Raises:
        RuntimeError: If GEMINI_API_KEY is not configured
        ValueError:   If Gemini returns unparseable output after all retries
        Exception:    Re-raised API errors after retry exhaustion

    Retry strategy:
        Up to _MAX_RETRIES attempts with exponential backoff.
        Retries on any exception (network errors, rate limits, API errors).
        Raises the last exception if all retries fail.
    """
    model = _get_model()

    # Safety cap — very long documents cost more tokens and risk timeouts
    # Truncate at a sentence boundary near the limit where possible
    if len(sanitized_text) > _MAX_INPUT_CHARS:
        truncated = sanitized_text[:_MAX_INPUT_CHARS]
        # Try to end at the last full sentence
        last_period = truncated.rfind(".")
        if last_period > _MAX_INPUT_CHARS * 0.8:
            truncated = truncated[: last_period + 1]
        sanitized_text = truncated
        print(
            f"[PrivaVault] Document truncated to {len(sanitized_text):,} chars "
            f"for Gemini (original exceeded {_MAX_INPUT_CHARS:,})"
        )

    prompt = _PROMPT_TEMPLATE.format(text=sanitized_text)

    last_error = None
    delay = _RETRY_DELAY

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            print(f"[PrivaVault] Gemini API call (attempt {attempt}/{_MAX_RETRIES})...")

            response      = model.generate_content(prompt)
            raw_text      = response.text
            result        = _extract_json(raw_text)

            print(
                f"[PrivaVault] Gemini: summary generated, "
                f"{len(result['tags'])} tags: {result['tags']}"
            )
            return result

        except Exception as e:
            last_error = e
            print(f"[PrivaVault] Gemini attempt {attempt} failed: {e}")

            if attempt < _MAX_RETRIES:
                print(f"[PrivaVault] Retrying in {delay:.0f}s...")
                time.sleep(delay)
                delay *= 2   # exponential backoff: 2s → 4s → 8s

    # All retries exhausted
    raise Exception(
        f"Gemini failed after {_MAX_RETRIES} attempts. "
        f"Last error: {last_error}"
    )