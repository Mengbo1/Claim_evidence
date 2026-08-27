from __future__ import annotations

import re
from typing import Any


def text(value: Any) -> str:
    return str(value or "").strip()


def normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9.:-]+", " ", text(value).lower()).strip()


def headers_to_index(headers: list[Any]) -> dict[str, int]:
    return {text(value): index for index, value in enumerate(headers)}


def contains_word(text_value: str, word: str) -> bool:
    return bool(re.search(rf"\b{re.escape(word)}\b", text_value, re.IGNORECASE))
