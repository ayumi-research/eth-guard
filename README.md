# eth-guard

A read-only Python 3.11+ CLI and library for Ethereum wallet hygiene. It inventories current ERC20 and Uniswap Permit2 allowances discovered in a bounded log range, and checks current EIP-7702 delegation. Supports mainnet (1), Base (8453), and Arbitrum (42161); supply an RPC endpoint for the selected chain.

Approvals can outlive the application session that created them. This report helps identify continuing access to tokens and account execution. **v0 is not a complete lifetime inventory:** discovery defaults to the last 50,000 blocks. An empty report does not establish that an account has no outstanding approvals.

## Read-only promise

No keys, signing, broadcasting, or chain write operations. `HttpTransport` permits only `eth_chainId`, `eth_getBlockByNumber`, `eth_getCode`, `eth_getLogs`, and `eth_call`. State reads use a numeric snapshot block; discovery queries are bounded by that block. Chain-ID and initial head queries establish the snapshot. No calls persist chain changes. Injected transports should honor this same contract. The CLI writes its report to stdout; the optional recorder writes a local JSON file.

## Run

From a source checkout, with Python 3.11 or newer:

```sh
python3.11 -m venv /tmp/eth-guard-venv
. /tmp/eth-guard-venv/bin/activate
python -m pip install .
eth-guard --help
python -m eth_guard --help
```

The following commands make real RPC requests. Set `RPC_URL` to your provider's
HTTP(S) endpoint for the selected chain and replace the example address with the
public wallet address you want to inspect. `RPC_URL` is a shell variable expanded
into `--rpc`; the library does not read it from the environment.

```sh
eth-guard inspect 0x1111111111111111111111111111111111111111 --rpc "$RPC_URL" --chain-id 1 --json
python -m eth_guard inspect 0x1111111111111111111111111111111111111111 --rpc "$RPC_URL" --chain-id 8453 --lookback 10000 --chunk-size 1000 --md
```

Markdown is the default; `--json` and `--md` are mutually exclusive. `--from-block N` explicitly sets the discovery start instead of `--lookback`. Provider log limits vary: reduce `--chunk-size` if needed. v0 does not automatically walk lifetime history, retry limited requests, or adapt range sizes. Expected discovery RPC failures abort with exit code 1; metadata/allowance RPC errors and invalid ABI values appear in report warnings. Such warnings mean the result is partial. Unexpected response types can still abort inspection; malformed-provider handling is incomplete.

```python
from eth_guard import HttpTransport, inspect

report = inspect("0x1111111111111111111111111111111111111111",
                 HttpTransport("https://rpc.example.org"),
                 chain_id=1, lookback=50_000)
print(report.to_markdown())
data = report.to_dict()
```

The Python example also needs a real provider endpoint. Providers must support historical block-tagged state reads, owner-topic log filters without a contract address, and OR topic filters for Permit2. Authentication can be supplied in the endpoint URL or, for library callers, through `HttpTransport.session.headers`; custom transports can handle other authentication schemes. Only the three listed chain presets are accepted. No live provider compatibility is claimed by the synthetic suite.

The transport interface is simply `call(method, params) -> result`; expected provider failures raise `RpcError`. Offline callers can inject fixture replay. Runtime dependencies are stdlib plus requests only.

## What is reported

JSON exposes all fields below; Markdown is a summary and omits some evidence, nonce, domain and metadata fields.

- Snapshot: normalized address, verified chain ID/name, block number/hash/timestamp and log range. State reads use that block number; a final hash check detects a snapshot reorg and aborts. This is not a finality guarantee or protection against a dishonest RPC.
- Entries: channel, token, spender, `amount_raw` (integer), exact `amount_human` (string), symbol, decimals, `unlimited`, `granted_at` (Unix timestamp or null), grant evidence/transaction hash, expiration, nonce, active status, spender reputation, risk rank and reason. JSON consumers must preserve arbitrary-precision integers.
- Tokens: balance raw/human and metadata. Failed metadata is null with a warning, never an assumed 18 decimals. Missing allowance reads produce warnings, not inferred zero values.
- Delegation: exact 23-byte `0xef0100 || address` designation, active flag, target and plain-language note. Other deployed code is distinguished from empty code. First/last account-emitted logs in range are **activity hints only**: they cannot identify when delegation was set, changed or cleared. EIP-7702 has no standard delegation-change event.
- Signatures: nonce/domain getter probes on discovered and selected major tokens (mainnet USDC/DAI, Base USDC, Arbitrum native USDC). Getter availability is only a permit-style capability hint, not proof of ERC-2612 conformance. Unsubmitted ERC-2612, DAI-style and Permit2 signatures are **not observable** via RPC. Executed permits affect the ordinary allowance channels.

ERC20 candidates come from owner-indexed `Approval` logs; four-topic ERC721 approvals are excluded. Current `allowance(owner, spender)` is authoritative, including revocations and transfers since the event. Zero allowances are omitted. Nonstandard tokens may evade discovery.

Permit2 candidates come from its owner-indexed `Approval` and `Permit` events. The public `allowance(owner, token, spender)` getter reads the nested AllowanceTransfer mapping through `eth_call`, returning uint160 amount, uint48 expiration and uint48 nonce. This avoids hard-coded storage layout assumptions. Nonzero expired entries remain visible with `active=false`; expiration is inclusive at the snapshot timestamp. These permissions still depend on the underlying token approval to Permit2 and available balance. Permit2 SignatureTransfer has no standing allowance inventory.

`granted_at` is the **latest matching event in range**, not necessarily the original grant date or proof of a permit's submission mechanism. Older approvals outside the range cannot be discovered in v0. Log order is normalized and report entries sort by HIGH/MED/LOW, token, spender and channel. Time-based logic uses the snapshot timestamp, never the local clock.

## Transparent risk rules

Implemented in `eth_guard/report.py`, evaluated in order:

1. Expired or zero allowance: LOW.
2. Unlimited allowance to an unknown spender: HIGH. Unlimited means exactly uint256 max for ERC20 or uint160 max for Permit2.
3. Capped allowance with an observed grant at least 180 days old: LOW.
4. Other active allowances, including unknown grant ages: MED.

All spender reputations are `unknown` in v0. These simple triage rules follow the v0 specification; age does not establish safety, and a capped allowance can still expose a large value. Delegation is reported separately rather than assigned an allowance risk rank.

## Offline tests and fixture provenance

```sh
python -m unittest test_eth_guard -q
python -m pip install pytest
python -m pytest -q
```

The regression tests make no network calls. `eth_guard/fixtures/snapshot.json` contains deterministic, synthetic ABI-shaped JSON-RPC responses; `expected.json` records the expected report. No live capture is claimed. `build_fixture.py` regenerates these fixtures without network access.

A human can capture real read-only responses with:

```sh
python -m eth_guard.fixtures.record 0x1111111111111111111111111111111111111111 \
  --rpc "$RPC_URL" --chain-id 1 --lookback 10000 --output /tmp/eth-guard-capture.json
```

`fixtures/record.py` is an equivalent source-checkout entry point. Captures store method/params/results or sanitized RPC errors, exclude the endpoint URL, and refuse to overwrite an existing file. Captures include the queried wallet's public activity; review before sharing. A failed scan may leave a capture with `complete=false`; successful scans set `complete=true`. Completion does not imply lifetime coverage or absence of report warnings. No manual live capture was performed for the bundled suite.

## Prior art and positioning

Approval inspection and revocation are established workflows, including in
[Revoke.cash](https://revoke.cash). EIP-7702 inspectors and revocation scripts are
adjacent tools. This offline review does not establish current feature coverage,
network counts or market leadership of external projects, and makes no claim
that eth-guard is unique or first.

**What eth-guard adds:** current EIP-7702 delegation state and discovered ERC20/Permit2 AllowanceTransfer permissions in one read-only Python report, with injectable transport and JSON/Markdown output. Allowances receive heuristic risk ranks; delegation is reported separately. The contribution is convenient integration for monitoring and automation — it complements inspection dashboards and revocation tools rather than replacing them.

## What this is — and is not

This is a partial snapshot, not a safety assessment. A clean report means "nothing was found in the scanned range with the current rules", not "this wallet is safe". Discovery defaults to 50,000 blocks and can miss older or nonstandard approvals; NFT permissions and unsubmitted signatures are excluded, and Permit2 SignatureTransfer has no standing-allowance inventory. RPC failures can produce warnings or abort inspection; provider dishonesty and state changes after the snapshot remain risks. All spender reputations are currently unknown, and LOW does not mean safe. The report neither audits delegated code nor establishes that wallet keys are uncompromised. Run it as a regular hygiene instrument, alongside — not instead of — revocation tooling and careful signing habits. No single tool is 100% protection.

## Public RPC notes

eth-guard runs against plain JSON-RPC endpoints, and free public providers differ a lot
in what they accept (verified October 2026; endpoints change without notice — always
probe before trusting):

- **`https://rpc.mevblocker.io`** — accepts `eth_getLogs` with topic filters and no
  `address`, and large ranges (50,000+ blocks tested). Worked for both Ethereum
  mainnet and Base in our scans.
- **publicnode family** (`*-rpc.publicnode.com`) — requires an `address` in every
  `eth_getLogs` (rejects topics-only queries) and caps results at 20,000 per call.
  High-traffic tokens (USDC on Base) exceed that cap within a few hundred blocks.
- **drpc free tier** — small effective log ranges; error messages can misstate the cap.
- **1rpc.io** — restricts `eth_getLogs` to a narrow recent-block window.
- **ankr** — requires an API key.

Practical rule: chunk log scans well below any provider's stated limit, sleep briefly
between calls (rate limits masquerade as range errors), and prefer topic-filtered
queries over address-less scans. From v0.1.2, provider rejection reasons are surfaced
in the error (with URLs and credentials stripped) so failures are self-diagnosing.

## Protocol references and next steps

- [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702): delegation designation and authorization processing.
- [ERC-2612](https://eips.ethereum.org/EIPS/eip-2612): permit, nonce, and Approval semantics.
- [Uniswap AllowanceTransfer](https://developers.uniswap.org/docs/protocols/permit2/concepts/allowance-transfer): mapping, amounts and expiration.
- [Permit2 overview](https://developers.uniswap.org/docs/protocols/permit2/overview): standing allowances versus signature transfers.

v1 should add resumable history discovery, spender labeling, richer delegation authorization evidence, user-supplied signature analysis, and an offline revocation transaction builder. Any future builder should produce unsigned transactions only to preserve the read-only promise.

MIT licensed; see [LICENSE](LICENSE). See [ROADMAP.md](ROADMAP.md) for completed and open work and [SECURITY.md](SECURITY.md) for security boundaries and the disclosure setup required before publication.
