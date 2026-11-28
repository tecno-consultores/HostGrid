"""Distro-aware package version comparison (dpkg / rpm / apk backport-safe)."""

from __future__ import annotations

import re

_TOKEN_RE = re.compile(r"(\d+|~|\D)")


def _split_epoch(version: str) -> tuple[int, str]:
    if ":" not in version:
        return 0, version
    epoch_str, rest = version.split(":", 1)
    try:
        return int(epoch_str), rest
    except ValueError:
        return 0, version


def _char_rank(ch: str) -> int:
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _compare_non_digit(left: str, right: str) -> int:
    for c1, c2 in zip(left, right, strict=False):
        r1, r2 = _char_rank(c1), _char_rank(c2)
        if r1 != r2:
            return -1 if r1 < r2 else 1
    if len(left) == len(right):
        return 0
    return -1 if len(left) < len(right) else 1


def _compare_numeric_tokens(tl: str, tr: str) -> int:
    il, ir = int(tl), int(tr)
    if il == ir:
        return 0
    return -1 if il < ir else 1


def _compare_token_pair(tl: str, tr: str) -> int:
    if tl == tr:
        return 0
    if tl == "~":
        return -1
    if tr == "~":
        return 1
    if tl.isdigit() and tr.isdigit():
        return _compare_numeric_tokens(tl, tr)
    return _compare_non_digit(tl, tr)


def _compare_segment(left: str, right: str) -> int:
    tokens_l = _TOKEN_RE.findall(left)
    tokens_r = _TOKEN_RE.findall(right)
    max_len = max(len(tokens_l), len(tokens_r))
    for i in range(max_len):
        tl = tokens_l[i] if i < len(tokens_l) else ""
        tr = tokens_r[i] if i < len(tokens_r) else ""
        cmp = _compare_token_pair(tl, tr)
        if cmp != 0:
            return cmp
    return 0


def compare_distro_versions(installed: str, fixed: str) -> int:
    """Compare two distro package versions returning -1 (<), 0 (==), or 1 (>)."""
    epoch_l, body_l = _split_epoch(installed.strip())
    epoch_r, body_r = _split_epoch(fixed.strip())
    if epoch_l != epoch_r:
        return -1 if epoch_l < epoch_r else 1

    up_l, _, rev_l = body_l.rpartition("-") if "-" in body_l else (body_l, "", "")
    up_r, _, rev_r = body_r.rpartition("-") if "-" in body_r else (body_r, "", "")
    cmp_up = _compare_segment(up_l, up_r)
    if cmp_up != 0:
        return cmp_up
    return _compare_segment(rev_l, rev_r)


def is_version_vulnerable(installed: str, fixed_version: str | None) -> bool:
    """Return True if installed version is strictly older than fixed_version (or no fix exists)."""
    if fixed_version is None or not fixed_version.strip():
        return True
    return compare_distro_versions(installed, fixed_version) < 0
