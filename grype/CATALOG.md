---
title: Grype
description: Vulnerability scanner for container images, filesystems and SBOMs
keywords: grype,vulnerability,cve,scanner,sbom,security,sca,supply-chain,anchore
---

# Grype

Grype finds known vulnerabilities in container images, filesystems and SBOMs.
Point it at an image, a directory, or a [syft](https://index.ocx.sh/anchore/syft)
SBOM and it matches every discovered package — OS packages and language
ecosystems alike — against its vulnerability database, reporting the CVEs that
affect the exact versions you ship, with fix availability and severity.

It is designed to sit in CI: `--fail-on <severity>` turns the scan into a gate,
and output can be emitted as a table, JSON, SARIF, CycloneDX or a custom Go
template.

## What's included

- **grype** — the single static binary (`grype <image|dir|sbom|purl|cpe>`,
  `grype db update|status|search`, `grype explain`, `-o
  json|sarif|cyclonedx|template`, `--fail-on`). No runtime dependencies.

## Note on the vulnerability database

Grype downloads its vulnerability database on first use and refreshes it
automatically (`grype db update`). That download is a network operation and is
not part of this mirror — the package ships the scanner, not the data.

## Links

- [Grype Documentation](https://github.com/anchore/grype#readme)
- [Grype on GitHub](https://github.com/anchore/grype)
- [Anchore](https://anchore.com/)
