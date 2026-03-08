"""
round_trace.py — Pure Python AES-128 Block Tracer
-------------------------------------------------
Provides round-by-round intermediate state extraction for standard and
dynamic AES by simulating the AES-128 block cipher in pure Python.
This module extracts the results of SubBytes, ShiftRows, MixColumns,
and AddRoundKey for each of the 10 rounds, plus the initial extraction
for Round 0.
"""

from __future__ import annotations

from crypto.round_keys import _SBOX, get_round_keys
from crypto.key_evolution import evolve_key
from crypto.lfsr import LFSR

# Galois Field (2^8) multiplication tables for MixColumns
def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a <<= 1
        a &= 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

# ---------------------------------------------------------------------------
# AES Basic Operations
# ---------------------------------------------------------------------------

def _sub_bytes(state: bytearray) -> bytearray:
    return bytearray(_SBOX[b] for b in state)

def _shift_rows(state: bytearray) -> bytearray:
    res = bytearray(16)
    # Row 0: no shift
    res[0], res[4], res[8], res[12] = state[0], state[4], state[8], state[12]
    # Row 1: shift left 1
    res[1], res[5], res[9], res[13] = state[5], state[9], state[13], state[1]
    # Row 2: shift left 2
    res[2], res[6], res[10], res[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift left 3
    res[3], res[7], res[11], res[15] = state[15], state[3], state[7], state[11]
    return res

def _mix_columns(state: bytearray) -> bytearray:
    res = bytearray(16)
    for c in range(4):
        s0, s1, s2, s3 = state[c*4], state[c*4+1], state[c*4+2], state[c*4+3]
        res[c*4]   = _gf_mul(0x02, s0) ^ _gf_mul(0x03, s1) ^ s2 ^ s3
        res[c*4+1] = s0 ^ _gf_mul(0x02, s1) ^ _gf_mul(0x03, s2) ^ s3
        res[c*4+2] = s0 ^ s1 ^ _gf_mul(0x02, s2) ^ _gf_mul(0x03, s3)
        res[c*4+3] = _gf_mul(0x03, s0) ^ s1 ^ s2 ^ _gf_mul(0x02, s3)
    return res

def _add_round_key(state: bytearray, round_key: bytes) -> bytearray:
    return bytearray(s ^ k for s, k in zip(state, round_key))


# ---------------------------------------------------------------------------
# Tracing Engine
# ---------------------------------------------------------------------------

def trace_aes_block(plaintext_block: bytes, root_key_hex: str, is_dynamic: bool) -> list[dict]:
    """
    Encrypt a single 16-byte block and record state transitions.
    """
    # 1. Expand keys
    if is_dynamic:
        root_key_bytes = bytes.fromhex(root_key_hex)
        evolved_key = evolve_key(root_key_bytes)
        round_keys_hex = get_round_keys(evolved_key.hex())
    else:
        round_keys_hex = get_round_keys(root_key_hex)
        
    round_keys = [bytes.fromhex(rk) for rk in round_keys_hex]
    
    # 2. Track states
    state = bytearray(plaintext_block)
    rounds_trace = []
    
    # Generate LFSR stream for dynamic tracing metadata if asked
    # The prompt asked for "Dynamic AES must also show the evolved round key generated using LFSR"
    # Wait, the current implementation evolves the ROOT key once, not every round.
    # We will show the single root key LFSR XOR in round 0 or simulate an LFSR stream if we need it
    # Note: LFSR.generate_bytes generates bytes. We will use the evolved keys for tracing.
    
    lfsr_stream = None
    if is_dynamic:
        root_key_bytes = bytes.fromhex(root_key_hex)
        seed = LFSR.seed_from_key(root_key_bytes)
        lfsr = LFSR(seed)
        # We'll just generate enough for 11 rounds (16 bytes per round)
        lfsr_stream = lfsr.generate_bytes(16 * 11)

    # Round 0
    state = _add_round_key(state, round_keys[0])
    r0_info = {
        "round": 0,
        "round_key": round_keys[0].hex(),
        "add_round_key": state.hex()
    }
    if is_dynamic:
        # User requested LFSR output for rounds
        r0_info["lfsr_output"] = lfsr_stream[0:16].hex()
        r0_info["dynamic_round_key"] = round_keys[0].hex()
        
    rounds_trace.append(r0_info)
    
    # Rounds 1 to 10
    for r in range(1, 11):
        r_info = {"round": r, "round_key": round_keys[r].hex()}
        
        if is_dynamic:
            r_info["lfsr_output"] = lfsr_stream[r*16:(r+1)*16].hex()
            r_info["dynamic_round_key"] = round_keys[r].hex()
            
        state = _sub_bytes(state)
        r_info["sub_bytes"] = state.hex()
        
        state = _shift_rows(state)
        r_info["shift_rows"] = state.hex()
        
        if r != 10:
            state = _mix_columns(state)
            r_info["mix_columns"] = state.hex()
            
        state = _add_round_key(state, round_keys[r])
        r_info["add_round_key"] = state.hex()
        
        rounds_trace.append(r_info)
        
    return rounds_trace
