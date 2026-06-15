"""Smoke tests for SIGSLEUTH. No network. Exercises core + CLI on the demo files."""
import json
import os
import subprocess
import sys

import pytest

from sigsleuth import (
    decode_calldata,
    decode_eip712,
    selector_of,
    KNOWN_SELECTORS,
    TOOL_VERSION,
    SigsleuthError,
)
from sigsleuth.core import keccak256

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic")


def test_keccak_known_vector():
    # Keccak-256 of the empty string (Ethereum's empty-hash constant).
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_selector_known():
    # Canonical selectors from the ABI spec.
    assert selector_of("transfer(address,uint256)") == "0xa9059cbb"
    assert selector_of("approve(address,uint256)") == "0x095ea7b3"
    assert "0x095ea7b3" in KNOWN_SELECTORS


def test_decode_transfer():
    cd = ("0xa9059cbb"
          "000000000000000000000000ab5801a7d398351b8be11c439e05c5b3259aec9b"
          "00000000000000000000000000000000000000000000000000000000000f4240")
    r = decode_calldata(cd)
    assert r["recognized"] is True
    assert r["function"] == "transfer(address,uint256)"
    assert r["args"][0]["value"] == "0xab5801a7d398351b8be11c439e05c5b3259aec9b"
    assert r["args"][1]["value"] == 1000000


def test_decode_approve_unlimited_from_demo():
    with open(os.path.join(DEMO, "approve.hex")) as fh:
        cd = fh.read().strip()
    r = decode_calldata(cd)
    assert r["function"] == "approve(address,uint256)"
    assert r["args"][1]["value"] == (1 << 256) - 1
    assert any("UNLIMITED" in note for note in r["risk"])


def test_unknown_selector():
    r = decode_calldata("0xdeadbeef")
    assert r["recognized"] is False
    assert r["risk"]


def test_bad_hex_raises():
    with pytest.raises(SigsleuthError):
        decode_calldata("0xzz")


def test_swap_dynamic_array():
    # swapExactETHForTokens(uint amountOutMin, address[] path, address to, uint deadline)
    sel = selector_of("swapExactETHForTokens(uint256,address[],address,uint256)")
    body = (
        "0000000000000000000000000000000000000000000000000000000000000064"  # amountOutMin=100
        "0000000000000000000000000000000000000000000000000000000000000080"  # offset to path
        "000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # to
        "0000000000000000000000000000000000000000000000000000000000001234"  # deadline
        "0000000000000000000000000000000000000000000000000000000000000002"  # path len=2
        "000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"
    )
    r = decode_calldata(sel + body)
    assert r["recognized"] is True
    path = r["args"][1]["value"]
    assert path == [
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "0xcccccccccccccccccccccccccccccccccccccccc",
    ]
    assert r["args"][0]["value"] == 100


def test_eip712_permit_from_demo():
    with open(os.path.join(DEMO, "permit.json")) as fh:
        payload = json.load(fh)
    r = decode_eip712(payload)
    assert r["primaryType"] == "Permit"
    # signing hash is 32 bytes, deterministic
    assert r["signingHash"].startswith("0x")
    assert len(r["signingHash"]) == 66
    assert r["domainSeparator"] != r["structHash"]
    assert any("Permit" in n or "spender" in n.lower() for n in r["risk"])


def test_eip712_deterministic():
    with open(os.path.join(DEMO, "permit.json")) as fh:
        payload = fh.read()
    a = decode_eip712(payload)
    b = decode_eip712(payload)
    assert a["signingHash"] == b["signingHash"]


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "sigsleuth"] + args,
        capture_output=True, text=True,
        cwd=os.path.join(os.path.dirname(__file__), ".."),
    )


def test_cli_version():
    p = _run_cli(["--version"])
    assert p.returncode == 0
    assert TOOL_VERSION in p.stdout


def test_cli_calldata_risk_exit_code():
    # Unlimited approve from demo -> risk findings -> exit code 2.
    p = _run_cli(["calldata", "--file", os.path.join(DEMO, "approve.hex"), "--format", "json"])
    assert p.returncode == 2
    out = json.loads(p.stdout)
    assert out["function"] == "approve(address,uint256)"
    assert out["risk"]


def test_cli_unknown_exit_code():
    p = _run_cli(["calldata", "0xdeadbeef"])
    assert p.returncode == 1


# ---------------------------------------------------------------------------
# Hardening tests: error paths, edge cases, input validation
# ---------------------------------------------------------------------------

def test_cli_missing_file_exit_and_stderr():
    """--file pointing to a nonexistent path must exit non-zero with a clear message."""
    p = _run_cli(["calldata", "--file", "/nonexistent/path/calldata.hex"])
    assert p.returncode != 0
    assert "error" in p.stderr.lower() or "not found" in p.stderr.lower() or "file" in p.stderr.lower()


def test_calldata_too_short():
    """Calldata shorter than 4 bytes must raise SigsleuthError."""
    with pytest.raises(SigsleuthError, match="too short"):
        decode_calldata("0xab")


def test_calldata_empty_string():
    """Completely empty (after strip) calldata must raise SigsleuthError."""
    with pytest.raises(SigsleuthError):
        decode_calldata("")


def test_calldata_non_hex():
    """Non-hex characters must raise SigsleuthError, not a raw ValueError."""
    with pytest.raises(SigsleuthError):
        decode_calldata("0xGGGGGGGG")


def test_eip712_malformed_json_raises():
    """A malformed JSON string must raise SigsleuthError, not json.JSONDecodeError."""
    with pytest.raises(SigsleuthError, match="invalid EIP-712 JSON"):
        decode_eip712("{not valid json")


def test_eip712_missing_message_field():
    """An EIP-712 payload that references a field not present in message must raise SigsleuthError."""
    payload = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "MyStruct": [
                {"name": "owner", "type": "address"},
                {"name": "value", "type": "uint256"},
            ],
        },
        "primaryType": "MyStruct",
        "domain": {"name": "TestApp", "chainId": 1},
        # message is deliberately missing the "value" field
        "message": {"owner": "0xab5801a7d398351b8be11c439e05c5b3259aec9b"},
    }
    with pytest.raises(SigsleuthError, match="missing required field"):
        decode_eip712(payload)


def test_eip712_missing_required_key():
    """EIP-712 payload missing a top-level required key must raise SigsleuthError."""
    with pytest.raises(SigsleuthError, match="missing"):
        decode_eip712({"types": {}, "primaryType": "Foo", "domain": {}})
        # "message" key missing


def test_selector_of_empty_raises():
    """selector_of with an empty string must raise SigsleuthError."""
    with pytest.raises(SigsleuthError):
        selector_of("")


def test_selector_of_no_parens_raises():
    """selector_of with a signature lacking parentheses must raise SigsleuthError."""
    with pytest.raises(SigsleuthError):
        selector_of("transferaddressuint256")


def test_decode_calldata_invalid_extra_sig():
    """An extra signature with no parentheses must raise SigsleuthError, not a traceback."""
    with pytest.raises(SigsleuthError):
        decode_calldata("0xa9059cbb" + "00" * 64, signatures=["notAnABISig"])
