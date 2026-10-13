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
