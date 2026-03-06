"""
key_evolution.py — Dynamic AES Key Evolution via XOR with LFSR Output
----------------------------------------------------------------------
Produces a *derived* 128-bit key by XOR-ing every byte of the raw AES
key with the corresponding byte from the LFSR pseudorandom stream.

    DynamicKey[i] = AESKey[i] XOR LFSR_Output[i]   for i in 0..15

Because the LFSR seed is derived deterministically from the raw key
(see :func:`LFSR.seed_from_key`), both the encryption and decryption
sides will always compute the *same* evolved key — without any additional
out-of-band exchange.
"""

from __future__ import annotations

from .lfsr import LFSR


def evolve_key(raw_key: bytes) -> bytes:
    """Evolve a 16-byte AES key using LFSR-based XOR mutation.

    1. Derive a deterministic seed from *raw_key*.
    2. Initialise the LFSR with that seed.
    3. Generate 16 pseudorandom bytes from the LFSR.
    4. XOR each byte of *raw_key* with the corresponding LFSR byte.

    Args:
        raw_key: The original 16-byte (128-bit) AES key.

    Returns:
        A new 16-byte evolved key: ``raw_key XOR lfsr_stream``.

    Raises:
        ValueError: If *raw_key* is not exactly 16 bytes.
    """
    if len(raw_key) != 16:
        raise ValueError(
            f"AES key must be exactly 16 bytes; got {len(raw_key)} byte(s)."
        )

    seed: int = LFSR.seed_from_key(raw_key)
    lfsr: LFSR = LFSR(seed)
    lfsr_stream: bytes = lfsr.generate_bytes(16)

    evolved: bytes = bytes(k ^ l for k, l in zip(raw_key, lfsr_stream))
    return evolved
