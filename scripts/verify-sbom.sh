#!/usr/bin/env bash
# SR-20: verify a release's signed SBOM (needs cosign: https://docs.sigstore.dev/cosign/).
# Usage: scripts/verify-sbom.sh <owner/repo> <sbom.cdx.json> <sbom.cdx.json.sigstore.json>
# Succeeds only if the SBOM is byte-for-byte what the repository's Release SBOM
# workflow signed. Any change to the SBOM, or a signature from any other
# identity, makes this fail.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <owner/repo> <sbom.cdx.json> <sbom.cdx.json.sigstore.json>" >&2
  exit 2
fi
repo="$1"; sbom="$2"; bundle="$3"

cosign verify-blob "$sbom" --bundle "$bundle" \
  --certificate-identity-regexp "^https://github.com/${repo}/\.github/workflows/release-sbom\.yml@" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
echo "SBOM signature verified for ${repo}."
