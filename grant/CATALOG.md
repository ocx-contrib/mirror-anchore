---
title: Grant
description: License compliance scanner for container images, SBOMs and filesystems
keywords: grant,license,compliance,spdx,sbom,legal,supply-chain,anchore,policy
---

# Grant

Grant answers what licenses are in a piece of software, and whether they are
allowed. Point it at a container image, a directory, an archive, a single
`LICENSE` file or an SBOM produced by
[syft](https://index.ocx.sh/anchore/syft), and it catalogues the license of
every package it finds, resolves each to its SPDX identifier, and evaluates the
result against a policy.

`grant list` reports the inventory without judging it. `grant check` applies the
policy and **exits non-zero when anything is denied**, which is what makes it a
CI gate rather than a report. The policy is deny-by-default: a package is
allowed only when its license matches an `allow` pattern, and a package with no
detectable license is denied unless you say otherwise.

## What's included

- **grant** — the single static binary (`grant check <image|dir|sbom|LICENSE>`,
  `grant list`, `grant config`, `-o table|json`, `-c <policy>`). No runtime
  dependencies.

## Policy

Grant reads its policy from `.grant.yaml` in the working directory, or from the
path given with `-c`. `grant config` prints a fully commented template:

```yaml
allow:
    - MIT
    - Apache-2.0
    - BSD-3-Clause
ignore-packages: []
require-license: true        # deny packages with no detected license
require-known-license: false # deny non-SPDX / unparsable licenses
```

Allow patterns support globs, so `BSD-*` covers the family.

## Links

- [Grant Documentation](https://github.com/anchore/grant#readme)
- [Grant on GitHub](https://github.com/anchore/grant)
- [Anchore](https://anchore.com/)
