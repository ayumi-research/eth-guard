# Security policy

This is an experimental v0.x, read-only inventory tool. Only the latest 0.1.x
release is in scope for fixes; there is no maintenance or response-time guarantee.
Supported chain presets are Ethereum mainnet, Base and Arbitrum. Findings in the
RPC boundary, parsers, report generation, packaging and bundled fixtures are in
scope. A report is partial evidence, never a safety certificate or key audit.

## Private disclosure

Open a **private security advisory via GitHub** (Security → Report a
vulnerability) or contact the maintainers directly. Please include the affected
version, a minimal reproduction and impact, with credentials and personal
activity removed.

## Hardening and boundaries

- No private keys, seed phrases, signing, broadcasts or chain writes are needed
  or implemented. Never provide wallet secrets to this tool.
- `HttpTransport` allows only `eth_chainId`, `eth_getBlockByNumber`, `eth_getCode`,
  `eth_getLogs` and `eth_call`. Injected transports must preserve this contract.
  The allowlist controls RPC methods; it is not a sandbox for arbitrary Python.
- Use a trusted HTTPS provider. Plain HTTP is supported for local test nodes.
  Provider credentials in command arguments may appear in process listings or
  shell history. Requests can use ambient proxy settings and netrc credentials;
  the package defines no environment-variable configuration of its own.
- Reads use a numeric snapshot block and a final hash check. This does not
  guarantee finality, complete logs or honest provider responses. Use bounded
  ranges, a suitable timeout and provider-specific chunk sizes. There are no
  automatic retries, response-size limits or adaptive log queries yet.
- Metadata and RPC responses are untrusted. Review reports and captures before
  rendering or sharing them; they reveal public wallet activity. Built-in RPC
  errors omit endpoint URLs, but chained Python tracebacks can retain request
  context. Do not publish raw exception traces without review.
- The CLI writes reports to stdout. The optional recorder writes a local file
  with exclusive creation. These local writes do not modify blockchain state.
