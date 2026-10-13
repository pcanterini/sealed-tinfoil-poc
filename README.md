# sealed-tinfoil-poc

Throwaway test for sealed-agents (a private project): does a [Tinfoil Container](https://docs.tinfoil.sh/containers/overview)
let us hold the only keys? Nothing here is secret, and nothing here is meant for production.

- `tinfoil-config.yml`: the measured enclave config. Private secrets and the encrypted volume's key come from our
  own keyserver (`keyserver-url`) after attestation, never from Tinfoil's secret store.
- `app/`: a small Go server that reports, as JSON, the sha256 of its private secret, a counter on the encrypted
  volume, a fresh attestation from `/tinfoil/attestation.sock`, and outbound reachability.
- `.github/workflows/`: image build, plus Tinfoil's release workflows (measure-image-action), which sign each
  release's measurement into Sigstore.

Licensed under Apache-2.0.

## Releases used in the test (2026-10-13)

| Tag | Config | Keyserver policy |
|---|---|---|
| v0.0.1 | keyserver + private secret + encrypted volume (auto-unlock) | approved, but the enclave never launched with a volume attached |
| v0.0.2 | keyserver + private secret | deliberately not approved: refused |
| v0.0.3, v0.0.4 | keyserver + private secret | approved for one instance domain |
| v0.0.90 | no keyserver, no volume (sanity) | n/a |
| v0.0.91 | keyserver + private secret (diagnostic) | approved |
| v0.0.92 | volume with manual unlock (diagnostic) | n/a; never launched |

`main` holds the v0.0.4 config.
