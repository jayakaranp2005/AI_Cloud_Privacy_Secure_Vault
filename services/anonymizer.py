"""
PrivaVault — Presidio Anonymization Service
Phase 3-5 | branch: feature/ai_privacy_flow

Responsibilities:
  - Detect PII in raw extracted text using Presidio + spaCy
  - Custom recognizers for Indian identifiers (Aadhaar, PAN, mobile)
  - Deterministic placeholder mapping — same entity always gets same ID
  - Return sanitized text safe to send to Gemini

Input:  Raw text from extractor.py
Output: Sanitized text + entity mapping → gemini.py receives sanitized text

Position in Stream A:
  extractor.py → raw text → [anonymizer.py] → sanitized text → gemini.py

Why deterministic mapping?
  "Rajesh Kumar" appears 3 times → all 3 become [PERSON_1], not
  [PERSON_1], [PERSON_2], [PERSON_3]. Consistent placeholders preserve
  the coreference chains Gemini needs to understand the document.
  A pre-pass collects ALL unique entity texts first, assigns IDs,
  then replaces every span using that lookup table.
"""

import re
from typing import Optional

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider


# ---------------------------------------------------------------------------
# SECTION 1: Verhoeff check-digit algorithm for Aadhaar validation
# ---------------------------------------------------------------------------
# Plain regex catches any 12-digit string — far too many false positives.
# Verhoeff is the actual check-digit algorithm UIDAI uses on Aadhaar numbers.
# A 12-digit string that fails Verhoeff is not an Aadhaar number.

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def _verhoeff_validate(number: str) -> bool:
    """
    Returns True if `number` passes the Verhoeff check-digit test.
    Input must be a string of digits only (no spaces or hyphens).

    How it works:
      Process digits right-to-left. At each position i, look up the
      permuted digit in _VERHOEFF_P[i % 8], then combine it with the
      running checksum using _VERHOEFF_D. A valid number yields c == 0.
    """
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


# ---------------------------------------------------------------------------
# SECTION 2: Custom Indian PII recognizers
# ---------------------------------------------------------------------------

class AadhaarRecognizer(PatternRecognizer):
    """
    Detects Aadhaar numbers in three formats:
      - Spaced:   1234 5678 9012
      - Hyphenated: 1234-5678-9012
      - Plain:    123456789012

    Validated with Verhoeff checksum to eliminate false positives.
    First digit 0 or 1 is also rejected (UIDAI spec).

    Context words boost confidence when the pattern appears near
    known Aadhaar-related terms.
    """

    _PATTERNS = [
        Pattern(
            name="AADHAAR_SPACED",
            regex=r"\b\d{4}\s\d{4}\s\d{4}\b",
            score=0.85,
        ),
        Pattern(
            name="AADHAAR_HYPHENATED",
            regex=r"\b\d{4}-\d{4}-\d{4}\b",
            score=0.85,
        ),
        Pattern(
            name="AADHAAR_PLAIN",
            regex=r"\b\d{12}\b",
            score=0.5,   # lower confidence — plain 12 digits could be anything
        ),
    ]

    _CONTEXT = [
        "aadhaar", "aadhar", "aadhaar number", "aadhar number",
        "uid", "uidai", "unique identification", "enrolment",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="AADHAAR_NUMBER",
            patterns=self._PATTERNS,
            context=self._CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """
        Called by Presidio on each regex match before accepting it.
        Returns False to reject, True to accept, None to leave score unchanged.
        """
        digits = re.sub(r"[\s\-]", "", pattern_text)

        if len(digits) != 12:
            return False

        # UIDAI spec: first digit cannot be 0 or 1
        if digits[0] in ("0", "1"):
            return False

        # Verhoeff checksum — the definitive validation
        return _verhoeff_validate(digits)


class PANRecognizer(PatternRecognizer):
    """
    Detects Indian Permanent Account Numbers.
    Format: [A-Z]{5}[0-9]{4}[A-Z]
    Example: ABCDE1234F

    The 4th character encodes entity type:
      P = individual, C = company, H = HUF, F = firm, etc.
    We validate this to reject random strings that match the regex.
    """

    _VALID_4TH_CHARS = set("PCHABGJLFT")

    _PATTERNS = [
        Pattern(
            name="IN_PAN",
            regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
            score=0.85,
        ),
    ]

    _CONTEXT = [
        "pan", "permanent account", "income tax", "it department",
        "pan card", "pan number", "tax", "tds",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_PAN",
            patterns=self._PATTERNS,
            context=self._CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """
        Validates PAN format beyond regex:
          - Exactly 10 characters
          - 4th character must be a valid entity type code
          - 5th character must be the first letter of the holder's surname
            (we can't validate this without the holder's name, so skip)
        """
        text = pattern_text.strip()

        if len(text) != 10:
            return False

        # 4th character (index 3) = entity type
        if text[3].upper() not in self._VALID_4TH_CHARS:
            return False

        return True


class IndianMobileRecognizer(PatternRecognizer):
    """
    Detects Indian mobile numbers in common formats:
      - +91 9876543210
      - 91 9876543210
      - 09876543210
      - 9876543210

    Valid mobile numbers in India start with 6, 7, 8, or 9.
    Numbers starting with 0-5 after the country code are landlines
    or invalid — rejected in validate_result.
    """

    _PATTERNS = [
        Pattern(
            name="IN_MOBILE_WITH_COUNTRY_CODE",
            regex=r"(?:\+91|91)[\s\-]?[6-9]\d{9}\b",
            score=0.9,
        ),
        Pattern(
            name="IN_MOBILE_WITH_LEADING_ZERO",
            regex=r"\b0[6-9]\d{9}\b",
            score=0.85,
        ),
        Pattern(
            name="IN_MOBILE_PLAIN",
            regex=r"\b[6-9]\d{9}\b",
            score=0.6,   # lower — 10-digit numbers starting 6-9 could be non-mobile
        ),
    ]

    _CONTEXT = [
        "mobile", "phone", "contact", "call", "whatsapp",
        "number", "mob", "ph", "cell",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_MOBILE",
            patterns=self._PATTERNS,
            context=self._CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Strip formatting and validate the core 10-digit mobile number."""
        digits = re.sub(r"[\s\-\+]", "", pattern_text)

        # Strip leading 91 (country code)
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]

        # Strip leading 0
        if digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]

        if len(digits) != 10:
            return False

        # Must start with 6, 7, 8, or 9
        if digits[0] not in "6789":
            return False

        return True


# ---------------------------------------------------------------------------
# SECTION 3: Placeholder rules
# ---------------------------------------------------------------------------
# Fixed: these entity types always use the same placeholder regardless of
#        how many appear. An Aadhaar number is always [AADHAAR_REDACTED].
# Numbered: these get sequential IDs so Gemini can track multiple entities.
#           [PERSON_1], [PERSON_2] lets Gemini know they are different people.

_FIXED_PLACEHOLDERS = {
    "AADHAAR_NUMBER": "[AADHAAR_REDACTED]",
    "IN_PAN":         "[PAN_REDACTED]",
}

_NUMBERED_TYPES = {
    "PERSON", "LOCATION", "ORGANIZATION", "EMAIL_ADDRESS",
    "IN_MOBILE", "PHONE_NUMBER", "DATE_TIME", "URL",
    "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS", "NRP",
}


# ---------------------------------------------------------------------------
# SECTION 4: Analyzer singleton
# ---------------------------------------------------------------------------
# Loading spaCy's NER model takes ~1–2 seconds. We do it once at first call
# and cache the result. All subsequent requests share the same engine.

_analyzer: Optional[AnalyzerEngine] = None


def _get_analyzer() -> AnalyzerEngine:
    """
    Builds and caches the AnalyzerEngine with:
      - spaCy en_core_web_sm NLP backend
      - All built-in Presidio recognizers (PERSON, EMAIL, etc.)
      - Our three custom Indian recognizers added on top
    """
    global _analyzer
    if _analyzer is not None:
        return _analyzer

    print("[PrivaVault] Initializing Presidio analyzer (loading spaCy model)...")

    # Configure spaCy as the NLP backend
    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

    engine = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["en"],
    )

    # Register custom Indian recognizers
    engine.registry.add_recognizer(AadhaarRecognizer())
    engine.registry.add_recognizer(PANRecognizer())
    engine.registry.add_recognizer(IndianMobileRecognizer())

    _analyzer = engine
    print("[PrivaVault] Presidio analyzer ready.")
    return _analyzer


# ---------------------------------------------------------------------------
# SECTION 5: Deterministic placeholder mapping
# ---------------------------------------------------------------------------

def _build_placeholder_map(entities_with_text: list) -> dict:
    """
    Pre-pass: collect all unique entity texts and assign consistent placeholders.

    Rules:
      - Fixed types (Aadhaar, PAN) → always the same string
      - Numbered types (PERSON, EMAIL, etc.) → [TYPE_N] where N increments
        per unique text value within that type
      - Same text always gets the same placeholder throughout the document

    Args:
        entities_with_text: list of dicts with keys:
            entity_type, text, start, end, score

    Returns:
        dict: { original_text → placeholder_string }

    Example:
        "Rajesh Kumar" → "[PERSON_1]"
        "Priya Sharma" → "[PERSON_2]"
        "Rajesh Kumar" → "[PERSON_1]"  ← same text, same placeholder
    """
    mapping = {}        # text → placeholder
    type_counters = {}  # entity_type → next available counter

    for entity in entities_with_text:
        text        = entity["text"]
        entity_type = entity["entity_type"]

        if text in mapping:
            continue   # already assigned — determinism guaranteed

        if entity_type in _FIXED_PLACEHOLDERS:
            mapping[text] = _FIXED_PLACEHOLDERS[entity_type]
        else:
            count = type_counters.get(entity_type, 0) + 1
            type_counters[entity_type] = count
            mapping[text] = f"[{entity_type}_{count}]"

    return mapping


# ---------------------------------------------------------------------------
# SECTION 6: Main anonymization function
# ---------------------------------------------------------------------------

def anonymize(raw_text: str) -> dict:
    """
    Full PII anonymization pipeline.

    Flow:
      1. Run Presidio analyzer → list of detected entity spans
      2. Extract actual text for each span
      3. Pre-pass: build deterministic text → placeholder mapping
      4. Replace spans right-to-left (preserves character offsets)
      5. Return sanitized text + mapping for audit

    Args:
        raw_text: Extracted document text from extractor.py

    Returns:
        dict with keys:
          sanitized_text     : str   — text safe to send to Gemini
          entities_detected  : list  — all detected PII (for audit/logging)
          placeholder_mapping: dict  — { original_text → placeholder }

    Raises:
        RuntimeError: If Presidio fails to initialize or analyze

    Why replace right-to-left?
        Each replacement changes the string length. If we go left-to-right,
        the character offsets of all subsequent spans shift — we'd replace
        the wrong text. Going right-to-left means earlier spans are never
        affected by later replacements.
    """
    analyzer = _get_analyzer()

    # Step 1 — detect all PII spans
    results = analyzer.analyze(text=raw_text, language="en")

    if not results:
        print("[PrivaVault] No PII detected in document.")
        return {
            "sanitized_text":      raw_text,
            "entities_detected":   [],
            "placeholder_mapping": {},
        }

    # Step 2 — attach actual matched text to each result
    entities_with_text = []
    for result in results:
        matched_text = raw_text[result.start:result.end]
        entities_with_text.append({
            "entity_type": result.entity_type,
            "text":        matched_text,
            "start":       result.start,
            "end":         result.end,
            "score":       round(result.score, 3),
        })

    # Step 3 — build deterministic placeholder map (pre-pass)
    placeholder_map = _build_placeholder_map(entities_with_text)

    # Step 4 — replace spans right-to-left to preserve offsets
    sanitized = raw_text
    sorted_entities = sorted(entities_with_text, key=lambda x: x["start"], reverse=True)

    for entity in sorted_entities:
        placeholder = placeholder_map[entity["text"]]
        sanitized = (
            sanitized[: entity["start"]]
            + placeholder
            + sanitized[entity["end"]:]
        )

    entity_types_found = list({e["entity_type"] for e in entities_with_text})
    print(
        f"[PrivaVault] Anonymized {len(entities_with_text)} entities "
        f"({', '.join(entity_types_found)}) — "
        f"{len(placeholder_map)} unique values replaced."
    )

    return {
        "sanitized_text":      sanitized,
        "entities_detected":   entities_with_text,
        "placeholder_mapping": placeholder_map,
    }