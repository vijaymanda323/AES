"""
visualization.py — Chart-Ready Data Builders
---------------------------------------------
Pure functions that transform raw cryptographic analysis data into
JSON-serialisable structures that a frontend (Chart.js / Recharts / D3)
can consume directly.

    build_key_evolution_chart(round_keys)
    build_avalanche_heatmap(orig_ct_bytes, mod_ct_bytes)
    build_entropy_histogram(ciphertext_bytes)
    build_performance_chart(std_enc, dyn_enc, std_dec, dyn_dec)
"""

from __future__ import annotations

from collections import Counter


# ---------------------------------------------------------------------------
# Key evolution chart
# ---------------------------------------------------------------------------

def build_key_evolution_chart(round_keys: list[str]) -> dict:
    """Convert 11 round-key hex strings into a line-chart dataset.

    For each round key we take the **first byte** value (0-255) as the
    representative numeric value shown on the Y-axis.  This is a
    compact, visually meaningful proxy for key change per round.

    Args:
        round_keys: 11 hex strings (each 32 chars / 16 bytes).

    Returns:
        ``{"labels": [...], "key_values": [...]}``
    """
    labels: list[str] = [f"Round {i}" for i in range(len(round_keys))]
    # Use first byte of each round key as the plotted scalar
    key_values: list[int] = [int(rk[:2], 16) for rk in round_keys]
    return {
        "labels": labels,
        "key_values": key_values,
    }


# ---------------------------------------------------------------------------
# Avalanche heatmap
# ---------------------------------------------------------------------------

def build_avalanche_heatmap(
    orig_ct_bytes: bytes, mod_ct_bytes: bytes
) -> dict:
    """Build a bit-change array for rendering a heatmap.

    Each position in the returned list is 1 if that bit differs between the
    two ciphertexts, 0 otherwise.  We compare the shorter of the two buffers.

    Args:
        orig_ct_bytes: Ciphertext bytes from the original plaintext.
        mod_ct_bytes:  Ciphertext bytes from the bit-flipped plaintext.

    Returns:
        ``{"changed_bits": [0, 1, 1, ...]}``  (one entry per ciphertext bit)
    """
    min_len = min(len(orig_ct_bytes), len(mod_ct_bytes))
    changed_bits: list[int] = []
    for byte_idx in range(min_len):
        diff_byte = orig_ct_bytes[byte_idx] ^ mod_ct_bytes[byte_idx]
        for bit in range(8):
            changed_bits.append((diff_byte >> bit) & 1)
    return {"changed_bits": changed_bits}


# ---------------------------------------------------------------------------
# Entropy histogram
# ---------------------------------------------------------------------------

def build_entropy_histogram(ciphertext_bytes: bytes) -> dict:
    """Build a byte-frequency histogram for entropy bar charts.

    Args:
        ciphertext_bytes: Raw ciphertext byte sequence.

    Returns:
        ``{"byte_frequency": [{"byte": 0, "count": 3}, ...]}``
        Only byte values that appear at least once are included.
    """
    freq: Counter = Counter(ciphertext_bytes)
    byte_frequency: list[dict] = [
        {"byte": byte_val, "count": count}
        for byte_val, count in sorted(freq.items())
    ]
    return {"byte_frequency": byte_frequency}


# ---------------------------------------------------------------------------
# Performance chart
# ---------------------------------------------------------------------------

def build_performance_chart(
    std_enc: float,
    dyn_enc: float,
    std_dec: float,
    dyn_dec: float,
) -> dict:
    """Build chart-ready data for a bar chart comparing operation times.

    Args:
        std_enc: Standard AES encrypt time (seconds).
        dyn_enc: Dynamic AES encrypt time (seconds).
        std_dec: Standard AES decrypt time (seconds).
        dyn_dec: Dynamic AES decrypt time (seconds).

    Returns:
        ``{"labels": [...], "values": [...]}``
    """
    return {
        "labels": ["Std Encrypt", "Dyn Encrypt", "Std Decrypt", "Dyn Decrypt"],
        "values": [
            round(std_enc, 6),
            round(dyn_enc, 6),
            round(std_dec, 6),
            round(dyn_dec, 6),
        ],
    }
