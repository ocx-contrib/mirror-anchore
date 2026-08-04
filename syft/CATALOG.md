---
title: Syft
description: SBOM generator for container images and filesystems
keywords: syft,sbom,spdx,cyclonedx,supply-chain,anchore,packages,inventory,security
---

# Syft

Syft generates a Software Bill of Materials (SBOM) from container images and
filesystems. Point it at an image, a directory, an archive or a single file and
it catalogues the packages it finds — OS packages, and language ecosystems from
Python, Go, Java, JavaScript, Rust, Ruby, PHP, .NET and more — then emits the
inventory as SPDX, CycloneDX, its own syft-json, or any Go template you supply.

The result is the input other supply-chain tooling consumes: feed it to
[grype](https://index.ocx.sh/anchore/grype) to match those packages against
known vulnerabilities, or attach it to an image as an attestation.

## What's included

- **syft** — the single static binary (`syft scan <source>`, `-o
  spdx-json|cyclonedx-json|syft-json|template`, `syft attest`, `syft cataloger
  list`). No runtime dependencies.

## Links

- [Syft Documentation](https://github.com/anchore/syft#readme)
- [Syft on GitHub](https://github.com/anchore/syft)
- [Anchore](https://anchore.com/)
