# Changelog

## 0.2.0 (2026-10-03)

- Replace the Windows interface with Dear ImGui and DirectX 11, with Inter embedded
  in the portable executable.
- Keep the window borderless and 360 pixels wide. Options expands inline, with
  animated height changes and no scrollbars. Errors also adjust the window height.
- Add HTTP CONNECT to the Node client and preserve payload sent with the request.
- Bound native connection attempts, local proxy negotiation and idle sessions.
  Add traffic counters and safer worker shutdown.
- Reject malformed UTF-8 and non-object tunnel control messages.
- Add `etl doctor` for DNS, TCP and verified TLS checks without credentials.
- Rewrite setup, architecture, protocol and Windows documentation in plain English.

The wire protocol remains ETL v1. Existing server installations can serve the new
clients. The Node CLI requires Node.js 24 or later; the Windows executable does
not require Node.js or separate runtime DLLs.
