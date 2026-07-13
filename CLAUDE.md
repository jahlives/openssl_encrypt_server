# CLAUDE.md — openssl_encrypt_server

This project is the server component: API endpoints called by the client tool
via its plugins. It has a different security surface than the client — extend
the `security-reviewer` scope accordingly for changes in this project.

## Server security lens (in addition to the global crypto/general lenses)

Treat the plugin-facing API as an untrusted boundary: the server must not
assume a request came from a well-behaved client. A plugin can be buggy,
tampered with, or bypassed entirely by an attacker speaking to the API
directly. Review endpoint changes for:
- **Input validation at the boundary:** every field from a request validated
  for type, length, range, and format before use — no trusting client-side
  checks.
- **AuthN/AuthZ:** each endpoint verifies who is calling and that they may do
  this specific action; no endpoint implicitly trusts the caller because "it's
  our client".
- **Injection sinks:** request data reaching shell, filesystem paths, DB
  queries, or deserialization — parameterized/sanitized, path-traversal safe.
- **Resource & DoS:** request size limits, rate limiting, no unbounded
  allocation or work driven by attacker-controlled values.
- **Error/response hygiene:** errors don't leak stack traces, internal paths,
  key material, or crypto internals back to the caller.
- **Transport:** TLS termination, session/token handling, and any secrets in
  transit between client and server.
