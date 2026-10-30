# Roadmap

Version 0.1.0 is an experimental v0.x private beta. Interfaces and report schemas
may change. A bounded snapshot is not a lifetime inventory or a safety judgment.

| Area | Done | Open |
| --- | --- | --- |
| Robustness | Read-method allowlist, chain-ID check, numeric snapshot tags and final hash check, bounded log chunks, explicit allowance/metadata warnings, offline regression suite | Malformed-provider hardening, response-size limits, terminal-safe output, retries/backoff, adaptive ranges, live provider validation and stronger snapshot consistency |
| Features | ERC20 and Permit2 AllowanceTransfer inventory, EIP-7702 current designation, permit getter hints, exact amounts, JSON/Markdown and explicit heuristic ranks | Resumable history discovery, spender labels, additional chain presets, richer delegation evidence and optional user-supplied signature analysis |
| Packaging | MIT license, Python package and CLI metadata, requests minimum, synthetic fixture data, security policy, Python 3.11/3.13 CI definition and tracked-file secret scan | Owner-controlled disclosure address, online name availability check, hosted CI results, release automation and independently captured fixtures |

NFT permissions and unseen signatures are outside the current inventory. Any
future revocation builder must output unsigned transactions only; signing and
broadcasting remain outside the read-only promise. No release dates are promised.
