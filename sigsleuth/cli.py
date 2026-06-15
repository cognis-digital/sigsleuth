"""SIGSLEUTH command-line interface.

Examples:
    # Decode raw calldata (an ERC-20 transfer)
    sigsleuth calldata 0xa9059cbb000000000000000000000000ab5801...000f4240

    # Decode from a file, JSON output for CI / piping
    sigsleuth calldata --file payload.hex --format json

    # Decode EIP-712 typed data and compute the signing hash
    sigsleuth eip712 --file demos/01-basic/permit.json

Exit codes:
    0  decoded and no risk findings
    2  decoded but RISK findings present (CI gate trips)
    1  could not decode / unrecognized
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import decode_calldata, decode_eip712, SigsleuthError


def _read_input(value: Optional[str], file: Optional[str], stream) -> str:
    if file:
        with open(file, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    if value:
        return value
    data = stream.read().strip()
    if not data:
        raise SigsleuthError("no input provided (pass a value, --file, or pipe via stdin)")
    return data


def _fmt_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, list):
        return "[" + ", ".join(_fmt_value(x) for x in v) + "]"
    return str(v)


def _render_table(result: Dict[str, Any]) -> str:
    lines: List[str] = []
    if result["kind"] == "calldata":
        lines.append(f"Selector : {result['selector']}")
        lines.append(f"Function : {result['function'] or '<unknown>'}")
        lines.append(f"Decoded  : {'yes' if result['recognized'] else 'NO'}")
        if result["args"]:
            lines.append("Arguments:")
            for a in result["args"]:
                lines.append(f"  [{a['index']}] {a['type']:<12} = {_fmt_value(a['value'])}")
    else:
        lines.append(f"Type          : EIP-712 / {result['primaryType']}")
        lines.append(f"Domain        : {json.dumps(result['domain'])}")
        lines.append(f"DomainSep     : {result['domainSeparator']}")
        lines.append(f"StructHash    : {result['structHash']}")
        lines.append(f"Signing Hash  : {result['signingHash']}")
        lines.append("Message:")
        for k, v in result["message"].items():
            lines.append(f"  {k:<16} = {_fmt_value(v)}")
    if result["risk"]:
        lines.append("Risk findings:")
        for r in result["risk"]:
            lines.append(f"  ! {r}")
    else:
        lines.append("Risk findings: none")
    return "\n".join(lines)


def _exit_code(result: Dict[str, Any]) -> int:
    if not result.get("recognized"):
        return 1
    if result.get("risk"):
        return 2
    return 0


def _emit(result: Dict[str, Any], fmt: str, out) -> None:
    if fmt == "json":
        out.write(json.dumps(result, indent=2) + "\n")
    else:
        out.write(_render_table(result) + "\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Decode raw EVM calldata and EIP-712 typed data into human-readable intent.",
        epilog="Exit: 0=clean, 2=risk findings, 1=undecodable. Use for wallet/CI signing gates.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table", help="output format (default: table)")

    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    pc = sub.add_parser("calldata", help="decode raw hex calldata")
    pc.add_argument("data", nargs="?", help="0x-prefixed hex calldata (or use --file / stdin)")
    pc.add_argument("--file", help="read calldata hex from a file")
    pc.add_argument("--sig", action="append", default=[],
                    help="extra ABI signature to recognize, e.g. 'foo(uint256)' (repeatable)")

    pe = sub.add_parser("eip712", help="decode EIP-712 typed data + compute signing hash")
    pe.add_argument("data", nargs="?", help="EIP-712 JSON string (or use --file / stdin)")
    pe.add_argument("--file", help="read EIP-712 JSON from a file")

    ps = sub.add_parser("selector", help="compute the 4-byte selector for an ABI signature")
    ps.add_argument("signature", help="e.g. 'transfer(address,uint256)'")

    # also accept --format after the subcommand (SUPPRESS so it doesn't clobber the global)
    for _sp in (pc, pe, ps):
        _sp.add_argument("--format", choices=["table", "json"], default=argparse.SUPPRESS,
                         help="output format (default: table)")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "selector":
            from .core import selector_of
            sel = selector_of(args.signature)
            if args.format == "json":
                sys.stdout.write(json.dumps({"signature": args.signature, "selector": sel}) + "\n")
            else:
                sys.stdout.write(f"{sel}  {args.signature}\n")
            return 0

        if args.command == "calldata":
            raw = _read_input(args.data, args.file, sys.stdin)
            result = decode_calldata(raw, signatures=args.sig or None)
        else:  # eip712
            raw = _read_input(args.data, args.file, sys.stdin)
            result = decode_eip712(raw)
    except SigsleuthError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    except FileNotFoundError as e:
        sys.stderr.write(f"error: file not found: {e.filename}\n")
        return 1

    _emit(result, args.format, sys.stdout)
    return _exit_code(result)
