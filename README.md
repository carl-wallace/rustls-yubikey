# rustls-yubikey-demo

TLS 1.3 client authentication with a post-quantum key on a YubiKey. The program makes an HTTPS GET
with [rustls](https://github.com/rustls/rustls). The rustls client-authentication signature is made
on the card by the ML-DSA-65 key in the PIV authentication slot (9A). The private key never leaves
the device.

It targets the PQC Ready YubiKey beta and talks to the card through the ML-DSA and ML-KEM support
on the [`pqc-upstream` branch](https://github.com/carl-wallace/yubikey.rs/tree/pqc-upstream) of a
`yubikey.rs` fork. That support is not yet in upstream `yubikey.rs`.

The repository also contains a simulated derived PIV credential enrollment that provisions a device
and validates the results ([below](#simulated-derived-piv-credential-enrollment)). That flow can produce the key
and certificate the client needs.

## Usage

```sh
cargo run --release -- <host> <port> <path> <client-cert.der> <server-root.pem> [pin]
```

- `client-cert.der` is the certificate for the key in 9A, in DER. It is read from a file rather
  than from the card, because an ML-DSA certificate is too large for some tools to read back.
- `server-root.pem` contains the roots used to verify the server. It may hold more than one.
- `pin` defaults to `123456`, the PIV default. It is verified immediately before each signature,
  as a PIN-always slot requires.

The program prints the response's status line and, on stderr, the card's serial number and
signing activity.

## Requirements

- A PQC Ready YubiKey beta with an ML-DSA-65 key in slot 9A, and that key's certificate.
- A TLS 1.3 server that requests a client certificate, accepts ML-DSA-65 signatures for it, and
  trusts the certificate's issuer.

## Limitations

- Only ML-DSA-65 is offered. If the server does not list ML-DSA-65 among its acceptable signature
  schemes, no client certificate is sent.
- Only slot 9A is used.
- The first YubiKey found is opened. There is no option to pick a device by serial number.
- The server's own certificate is verified with rustls's `ring` provider, so the server
  authenticates with a classical algorithm.

## Simulated derived PIV credential enrollment

`scripts/run-pqc-flow.sh` runs a simulated derived PIV credential enrollment against the device
(`tests/enrollment.rs`) and then validates every certificate it produced, including the device's own
attestations.

> **Warning:** the flow resets the PIV applet before every variant. Every PIV key and certificate
> on the device is destroyed. Use a device dedicated to testing. The F9 attestation key survives a
> reset.

### Requirements

- `yubico-piv-tool` on `PATH`. It is used only to print device status between phases.
- `pittv3` 0.2.0-rc.2, the certificate path validator, from the
  [GitHub release](https://github.com/carl-wallace/rust-pki/releases/tag/pittv3-v0.2.0-rc.2)
  (macOS universal, Linux x86_64 and Windows x86_64 builds, with `SHA256SUMS`). Put it on `PATH`, or
  run as `PITTV3=/path/to/pittv3 ./scripts/run-pqc-flow.sh`.
- The YubiKey at factory defaults (`ykman piv reset`). Set `YUBIKEY_SERIAL` if more than one
  YubiKey is attached.

### Running it

From the root of this checkout:

```sh
./scripts/run-pqc-flow.sh
```

The flow runs six algorithm pairs, each starting from a reset:

| Variant | Signing | Decryption |
|---|---|---|
| `rsa2048`, `rsa3072`, `rsa4096` | RSA | RSA (same size) |
| `mldsa44` | ML-DSA-44 | ML-KEM-512 |
| `mldsa65` | ML-DSA-65 | ML-KEM-768 |
| `mldsa87` | ML-DSA-87 | ML-KEM-1024 |

The full matrix takes 10 to 15 minutes, and RSA key generation accounts for nearly all of that.
To run selected variants only, set `PQC_VARIANTS`, for example
`PQC_VARIANTS=mldsa44,mldsa65,mldsa87`.

Each variant follows the same sequence of steps:

1. Generate a self-signed pre-enrollment signing key and a decryption (KEM) key, and capture their
   attestations.
2. Have a software stand-in CA issue the device signing and decryption credentials, the user
   signature credential and the user PIV authentication credential. Each key is generated on the
   card and attested.
3. Import three escrowed decryption keys, delivered as PKCS #12, into 9D, 82 and 83.

Everything the flow produces goes to `target/pqc-artifacts/`. Afterwards the script validates 15
certificates per variant, so a full run reports 90 results. The attestations are validated against
the device's own F9 certificate, because no root has been published for the beta. A passing
attestation therefore shows that its signature verifies and that it names its slot. It does not
show that the device chains to Yubico.

The `RUST_LOG` setting controls logging. The default is `error`, which keeps the status word when a
slot write fails. Set `RUST_LOG=trace` to see the APDU exchange.

When the script finishes, the device is left as the last variant provisioned it: seven occupied
slots and a random, non-default management key. Set `YK_MGM_KEY` to 48 hex characters to install a
specific management key instead.

### Using the result with the client

The `mldsa65` variant leaves an ML-DSA-65 key in 9A, and its certificate is in
`target/pqc-artifacts/mldsa65_10_issued_piv.der`. Run that variant alone
(`PQC_VARIANTS=mldsa65 ./scripts/run-pqc-flow.sh`), because the full matrix ends with `mldsa87` and leaves an
ML-DSA-87 key in 9A. The server must trust `target/pqc-artifacts/mldsa65_00_ta_root.der`, with
`mldsa65_00_ca.der` as the intermediate.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
