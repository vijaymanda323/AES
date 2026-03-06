"""
lfsr.py — Linear Feedback Shift Register (LFSR) Pseudorandom Generator
-----------------------------------------------------------------------
Implements a Galois LFSR with a configurable 32-bit seed and a standard
maximal-length polynomial:  x^32 + x^22 + x^2 + x^1 + 1

The LFSR is used to produce a stream of pseudorandom bytes that feed into
the key-evolution stage.  Given the same seed, the output sequence is
fully deterministic and reproducible — which is essential so that both
the encryptor and the decryptor can derive the same evolved AES key
without transmitting extra state.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Galois LFSR (32-bit) — maximal-length polynomial
# Feedback taps (bit positions, 1-indexed from LSB):
#   32, 22, 2, 1  →  0x80200003
# ---------------------------------------------------------------------------
_FEEDBACK_POLYNOMIAL: int = 0x80200003


class LFSR:
    """32-bit Galois Linear Feedback Shift Register.

    Args:
        seed: Initial 32-bit state (must be non-zero).

    Raises:
        ValueError: If *seed* is zero (degenerate state).
    """

    def __init__(self, seed: int) -> None:
        if seed == 0:
            raise ValueError("LFSR seed must be non-zero.")
        self._state: int = seed & 0xFFFFFFFF  # enforce 32-bit width

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def next_bit(self) -> int:
        """Advance the register by one clock cycle and return the output bit."""
        lsb: int = self._state & 1
        self._state >>= 1
        if lsb:
            self._state ^= _FEEDBACK_POLYNOMIAL
        return lsb

    def next_byte(self) -> int:
        """Produce one pseudorandom byte (8 clock cycles)."""
        byte: int = 0
        for i in range(8):
            byte |= self.next_bit() << i
        return byte

    def generate_bytes(self, n: int) -> bytes:
        """Generate *n* pseudorandom bytes.

        Args:
            n: Number of bytes to generate.

        Returns:
            A :class:`bytes` object of length *n*.
        """
        return bytes(self.next_byte() for _ in range(n))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def seed_from_key(aes_key: bytes) -> int:
        """Derive a deterministic, non-zero 32-bit LFSR seed from an AES key.

        The seed is computed by XOR-folding the 16-byte key into a 4-byte
        integer.  This ensures identical seeds — and therefore identical
        LFSR sequences — on both the encrypt and decrypt sides as long as
        the same raw key is used.

        Args:
            aes_key: 16-byte (128-bit) AES key.

        Returns:
            A non-zero 32-bit integer suitable as an LFSR seed.
        """
        if len(aes_key) != 16:
            raise ValueError("AES key must be exactly 16 bytes for seed derivation.")

        seed: int = 0
        for i in range(0, 16, 4):
            word = int.from_bytes(aes_key[i : i + 4], "big")
            seed ^= word

        # Guard against the degenerate all-zero seed
        return seed if seed != 0 else 0xDEADBEEF
