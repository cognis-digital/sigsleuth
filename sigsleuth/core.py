"""Core engine: real ABI calldata + EIP-712 decoding using only the stdlib.

We implement just enough of the EVM ABI spec (static + dynamic head/tail layout)
to decode the common token/approval/swap functions a wallet is asked to sign,
plus a Keccak-256 implementation so we can compute 4-byte selectors and EIP-712
struct hashes WITHOUT any third-party crypto library.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple


class SigsleuthError(ValueError):
    """Raised when input cannot be parsed as calldata / typed data."""


# --------------------------------------------------------------------------- #
# Keccak-256 (pure python). Needed for selectors + EIP-712 hashing.           #
# --------------------------------------------------------------------------- #
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(state: List[List[int]]) -> None:
    for rnd in range(24):
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) & _MASK
        state[0][0] ^= _KECCAK_RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Pure-python Keccak-256 (Ethereum variant, 0x01 padding domain)."""
    rate = 136  # 1088 bits for 256-bit output
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)
    out = bytearray()
    for i in range(4):
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out[:32])


def selector_of(signature: str) -> str:
    """Return the 4-byte function selector (0x-prefixed hex) for an ABI signature."""
    sig = re.sub(r"\s+", "", signature)
    return "0x" + keccak256(sig.encode()).hex()[:8]


# --------------------------------------------------------------------------- #
# Known-function database. We store canonical signatures and derive selectors. #
# --------------------------------------------------------------------------- #
_FUNCTION_SIGS = [
    # ERC-20 / ERC-721 / common
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
    "approve(address,uint256)",
    "increaseAllowance(address,uint256)",
    "decreaseAllowance(address,uint256)",
    "safeTransferFrom(address,address,uint256)",
    "setApprovalForAll(address,bool)",
    "mint(address,uint256)",
    "burn(uint256)",
    "deposit()",
    "withdraw(uint256)",
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    # DEX / router
    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "swapExactETHForTokens(uint256,address[],address,uint256)",
    "multicall(bytes[])",
]
KNOWN_SELECTORS: Dict[str, str] = {selector_of(s): s for s in _FUNCTION_SIGS}

# Risk annotations for human-readable intent.
_UINT256_MAX = (1 << 256) - 1


def _parse_types(sig: str) -> Tuple[str, List[str]]:
    name = sig[: sig.index("(")]
    inner = sig[sig.index("(") + 1: sig.rindex(")")]
    if not inner:
        return name, []
    # split top-level commas (no nested tuples in our DB beyond arrays)
    return name, inner.split(",")


def _hexstrip(s: str) -> bytes:
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    s = re.sub(r"\s+", "", s)
    if len(s) % 2 != 0:
        raise SigsleuthError("hex string has odd length")
    if not re.fullmatch(r"[0-9a-fA-F]*", s):
        raise SigsleuthError("input contains non-hex characters")
    return bytes.fromhex(s)


def _word(data: bytes, idx: int) -> bytes:
    off = idx * 32
    if off + 32 > len(data):
        raise SigsleuthError("calldata truncated: missing argument word")
    return data[off:off + 32]


def _decode_address(word: bytes) -> str:
    return "0x" + word[-20:].hex()


def _decode_uint(word: bytes) -> int:
    return int.from_bytes(word, "big")


def _decode_one(typ: str, data: bytes, head_idx: int) -> Any:
    """Decode a single static argument or a dynamic head pointer."""
    word = _word(data, head_idx)
    if typ == "address":
        return _decode_address(word)
    if typ == "bool":
        return bool(_decode_uint(word))
    if typ.startswith("uint") or typ.startswith("int"):
        return _decode_uint(word)
    if typ in ("bytes32",) or re.fullmatch(r"bytes\d+", typ):
        return "0x" + word.hex()
    if typ == "address[]":
        return _decode_dyn_array(data, _decode_uint(word), "address")
    if typ == "bytes[]":
        return _decode_dyn_array(data, _decode_uint(word), "bytes")
    if typ == "bytes":
        return _decode_bytes(data, _decode_uint(word))
    # Fallback: present raw word as hex.
    return "0x" + word.hex()


def _decode_dyn_array(data: bytes, offset: int, elem: str) -> List[Any]:
    if offset + 32 > len(data):
        raise SigsleuthError("dynamic array offset out of range")
    length = int.from_bytes(data[offset:offset + 32], "big")
    out = []
    base = offset + 32
    for i in range(length):
        w = data[base + i * 32: base + i * 32 + 32]
        if len(w) < 32:
            raise SigsleuthError("dynamic array truncated")
        if elem == "address":
            out.append(_decode_address(w))
        elif elem == "bytes":
            # element is itself a pointer relative to array data region
            rel = int.from_bytes(w, "big")
            out.append(_decode_bytes(data, base + rel))
        else:
            out.append(int.from_bytes(w, "big"))
    return out


def _decode_bytes(data: bytes, offset: int) -> str:
    if offset + 32 > len(data):
        raise SigsleuthError("bytes offset out of range")
    length = int.from_bytes(data[offset:offset + 32], "big")
    start = offset + 32
    return "0x" + data[start:start + length].hex()


def _risk_notes(name: str, types: List[str], values: List[Any]) -> List[str]:
    notes: List[str] = []
    for typ, val in zip(types, values):
        if typ.startswith("uint") and isinstance(val, int):
            if val == _UINT256_MAX:
                notes.append("UNLIMITED amount/allowance (uint256 max) requested")
    if name == "approve":
        if values and isinstance(values[-1], int) and values[-1] == _UINT256_MAX:
            notes.append("Grants UNLIMITED token spending allowance to the spender")
        elif values and isinstance(values[-1], int) and values[-1] > 0:
            notes.append("Grants a finite token spending allowance to the spender")
    if name == "setApprovalForAll" and len(values) == 2 and values[1] is True:
        notes.append("Grants operator control over ALL of your NFTs in this collection")
    if name == "transferFrom":
        notes.append("Moves tokens FROM a third party (relies on prior allowance)")
    if name == "permit":
        notes.append("Gasless approval via signature — verify spender and deadline")
    return notes


def decode_calldata(calldata: str, signatures: Optional[List[str]] = None) -> Dict[str, Any]:
    """Decode raw EVM calldata into structured, human-readable intent.

    Args:
        calldata: 0x-prefixed (or bare) hex string, at least the 4-byte selector.
        signatures: optional extra ABI signatures to recognize (augments the DB).

    Returns a dict with selector, matched function, decoded args, and risk notes.
    """
    raw = _hexstrip(calldata)
    if len(raw) < 4:
        raise SigsleuthError("calldata too short: need at least a 4-byte selector")
    selector = "0x" + raw[:4].hex()
    body = raw[4:]

    db = dict(KNOWN_SELECTORS)
    if signatures:
        for s in signatures:
            db[selector_of(s)] = re.sub(r"\s+", "", s)

    result: Dict[str, Any] = {
        "kind": "calldata",
        "selector": selector,
        "function": None,
        "args": [],
        "risk": [],
        "recognized": False,
    }

    sig = db.get(selector)
    if sig is None:
        result["risk"].append("Unknown selector — function not in signature DB; intent UNVERIFIED")
        return result

    name, types = _parse_types(sig)
    values: List[Any] = []
    for i, typ in enumerate(types):
        values.append(_decode_one(typ, body, i))

    args = []
    for i, (typ, val) in enumerate(zip(types, values)):
        args.append({"index": i, "type": typ, "value": val})

    result["function"] = sig
    result["name"] = name
    result["args"] = args
    result["recognized"] = True
    result["risk"] = _risk_notes(name, types, values)
    return result


# --------------------------------------------------------------------------- #
# EIP-712 typed-data hashing + intent.                                        #
# --------------------------------------------------------------------------- #
def _encode_type(primary: str, types: Dict[str, List[Dict[str, str]]]) -> str:
    """Return the canonical encodeType string per EIP-712."""
    deps = set()

    def collect(t: str) -> None:
        if t in deps or t not in types:
            return
        deps.add(t)
        for field in types[t]:
            base = field["type"].split("[")[0]
            if base in types:
                collect(base)

    collect(primary)
    deps.discard(primary)
    ordered = [primary] + sorted(deps)

    def enc(t: str) -> str:
        fields = ",".join(f"{f['type']} {f['name']}" for f in types[t])
        return f"{t}({fields})"

    return "".join(enc(t) for t in ordered)


def _type_hash(primary: str, types: Dict[str, List[Dict[str, str]]]) -> bytes:
    return keccak256(_encode_type(primary, types).encode())


def _encode_value(typ: str, value: Any, types: Dict[str, List[Dict[str, str]]]) -> bytes:
    if typ in types:
        return _hash_struct(typ, value, types)
    if typ.endswith("]"):
        base = typ[: typ.rindex("[")]
        encoded = b"".join(_encode_value(base, v, types) for v in value)
        return keccak256(encoded)
    if typ == "string":
        return keccak256(value.encode())
    if typ == "bytes":
        return keccak256(_hexstrip(value) if isinstance(value, str) else bytes(value))
    if typ == "bool":
        return (1 if value else 0).to_bytes(32, "big")
    if typ == "address":
        return bytes(12) + _hexstrip(value)[-20:]
    if typ.startswith("uint") or typ.startswith("int"):
        iv = int(value, 0) if isinstance(value, str) else int(value)
        return (iv & _UINT256_MAX).to_bytes(32, "big")
    if re.fullmatch(r"bytes\d+", typ):
        b = _hexstrip(value) if isinstance(value, str) else bytes(value)
        return b.ljust(32, b"\x00")[:32]
    raise SigsleuthError(f"unsupported EIP-712 field type: {typ}")


def _hash_struct(primary: str, data: Dict[str, Any], types: Dict[str, List[Dict[str, str]]]) -> bytes:
    enc = _type_hash(primary, types)
    for field in types[primary]:
        enc += _encode_value(field["type"], data[field["name"]], types)
    return keccak256(enc)


def decode_eip712(payload: Any) -> Dict[str, Any]:
    """Decode an EIP-712 typed-data payload and compute its signing hash.

    Accepts a dict or a JSON string with the standard keys:
    types, primaryType, domain, message.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as e:
            raise SigsleuthError(f"invalid EIP-712 JSON: {e}") from e
    if not isinstance(payload, dict):
        raise SigsleuthError("EIP-712 payload must be an object")
    for key in ("types", "primaryType", "domain", "message"):
        if key not in payload:
            raise SigsleuthError(f"EIP-712 payload missing '{key}'")

    types = payload["types"]
    primary = payload["primaryType"]
    domain = payload["domain"]
    message = payload["message"]

    if "EIP712Domain" not in types:
        # Derive a minimal domain type from present keys (common in real wallets).
        order = [
            ("name", "string"), ("version", "string"),
            ("chainId", "uint256"), ("verifyingContract", "address"),
            ("salt", "bytes32"),
        ]
        types = dict(types)
        types["EIP712Domain"] = [{"name": n, "type": t} for n, t in order if n in domain]

    domain_sep = _hash_struct("EIP712Domain", domain, types)
    struct_hash = _hash_struct(primary, message, types)
    signing_hash = keccak256(b"\x19\x01" + domain_sep + struct_hash)

    risk: List[str] = []
    msg_lower = {k.lower(): v for k, v in message.items()} if isinstance(message, dict) else {}
    if "value" in msg_lower and isinstance(msg_lower["value"], (int, str)):
        try:
            v = int(msg_lower["value"], 0) if isinstance(msg_lower["value"], str) else int(msg_lower["value"])
            if v == _UINT256_MAX:
                risk.append("UNLIMITED value (uint256 max) in message")
        except (ValueError, TypeError):
            pass
    if primary.lower() in ("permit", "permitsingle", "permitbatch"):
        risk.append("Token approval via signature (Permit) — verify spender, amount, deadline")
    if "spender" in msg_lower:
        risk.append(f"Authorizes spender: {msg_lower['spender']}")
    if "deadline" in msg_lower:
        risk.append(f"Deadline/expiry present: {msg_lower['deadline']}")

    return {
        "kind": "eip712",
        "primaryType": primary,
        "domain": domain,
        "message": message,
        "domainSeparator": "0x" + domain_sep.hex(),
        "structHash": "0x" + struct_hash.hex(),
        "signingHash": "0x" + signing_hash.hex(),
        "risk": risk,
        "recognized": True,
    }
