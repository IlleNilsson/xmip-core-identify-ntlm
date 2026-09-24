# xmip-core-identify-ntlm

Identify by ntlm: reads the user, domain and workstation of an NTLM AUTHENTICATE (type 3) message, unverified, with the message riding as proof for the second gate. A technology of [xmip-core-identify](https://github.com/IlleNilsson/xmip-core-identify).

The message is read through `xmip-core-library-ntlm`, the one NTLM layout
`authenticate/ntlm` and the SMB transport also use.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
