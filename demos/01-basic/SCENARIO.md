# Demo 01 - Basic: "What am I actually signing?"

This demo shows SIGSLEUTH turning two opaque blobs a wallet might ask you to
sign into plain-English intent.

## Part A - Raw calldata (an ERC-20 `approve`)

The file `approve.hex` contains the calldata for:

```
approve(spender = 0x1111111254eeb25477b68fb85 ed929f73a960582,  // 1inch router
        amount  = 2**256 - 1)                                   // UNLIMITED
```

Run:

```bash
python -m sigsleuth calldata --file demos/01-basic/approve.hex
```

Expected:

- Selector resolves to `approve(address,uint256)` (selector `0x095ea7b3`).
- Argument `[1]` decodes to the uint256 maximum.
- A **risk finding**: "Grants UNLIMITED token spending allowance to the spender".
- Process exits with code **2** (risk present) — a CI signing gate would block it.

## Part B - EIP-712 typed data (a Permit)

The file `permit.json` is a standard EIP-712 `Permit` payload. Run:

```bash
python -m sigsleuth eip712 --file demos/01-basic/permit.json --format json
```

Expected:

- A deterministic `signingHash` is computed (pure-stdlib Keccak-256 + EIP-712).
- Risk findings flag it as a gasless approval and surface the `spender` + `deadline`.
- Exit code **2**.

## Why it matters

Unlimited approvals and blind `Permit` signatures are the #1 wallet-drain vector.
SIGSLEUTH makes the intent legible before you sign — with zero install.
