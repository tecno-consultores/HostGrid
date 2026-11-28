"""Base Pydantic schemas, NFKC normalization, and pagination envelopes."""

from __future__ import annotations

import re
import unicodedata

from pydantic import BaseModel, ConfigDict, Field

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_MULTILINE_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_single_line(value: str) -> str:
    """Apply Unicode NFKC normalization and reject ASCII control characters."""
    normalized = unicodedata.normalize("NFKC", value)
    if _CONTROL_CHAR_RE.search(normalized):
        raise ValueError("Control characters are not allowed in single-line strings.")
    return normalized


def sanitize_multiline(value: str) -> str:
    """Apply Unicode NFKC normalization allowing CR/LF/TAB in multiline payloads."""
    normalized = unicodedata.normalize("NFKC", value)
    if _MULTILINE_CTRL_RE.search(normalized):
        raise ValueError("Disallowed control characters in multiline payload.")
    return normalized


class StrictBaseModel(BaseModel):
    """Base DTO enforcing extra='forbid' and strict field validation."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class PaginatedResponse[T](StrictBaseModel):
    """Standard bounded pagination envelope."""

    items: list[T]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
