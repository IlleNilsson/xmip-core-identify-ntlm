# xmip-core-identify-ntlm

Identify by ntlm: reads the user and domain of an NTLM type 3 message; a transport-layer identifier whose claim is passed. A technology of
[xmip-core-identify](https://github.com/IlleNilsson/xmip-core-identify).

Declared and not yet written; `architecture.toml` carries the maturity. When
it is written it implements `TransportIdentifier`, one mechanism at one gate (ADR-0050), and
nothing goes sideways: it depends on its capability and on no sibling.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
