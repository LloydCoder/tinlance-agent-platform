# Release Security

Tagged releases are built in GitHub Actions, produce Python distributions and an SBOM, and sign those release artifacts with Sigstore keyless signing through the workflow's GitHub OIDC identity.

The release workflow is intentionally tag-triggered. Pull requests do not publish or sign release artifacts.

## Verification

Install Sigstore's Python client and verify a signed artifact using its bundle and the release workflow identity. Consumers should also verify that the certificate identity and OIDC issuer correspond to this repository's release workflow before trusting the artifact.

GitHub artifact attestations and SLSA provenance are additional supply-chain controls that can be layered onto future binary/container publication. The repository currently signs the Python release distributions and SBOM directly with Sigstore.
