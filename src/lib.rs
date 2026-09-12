#![forbid(unsafe_code)]
//! Identify by ntlm: reads the user and domain of an NTLM type 3 message; a transport-layer
//! identifier whose claim is passed.
//!
//! Declared and not yet written: `architecture.toml` carries the maturity. When it
//! is, it implements `TransportIdentifier` (ADR-0050).
