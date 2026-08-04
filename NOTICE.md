# NOTICE

This repository packages and redistributes upstream software published by
[Anchore, Inc.](https://github.com/anchore). The Apache-2.0 license in
[`LICENSE`](LICENSE) covers the OCX pipeline files authored here. It does
**not** cover any upstream-derived asset — each package's redistributed bytes
carry their own license, recorded below.

| Package | GHCR path | Upstream SPDX |
|---|---|---|
| `syft` | `ghcr.io/ocx-contrib/anchore/syft` | `Apache-2.0` |

---

## `syft`

Upstream: <https://github.com/anchore/syft>
Published to `ghcr.io/ocx-contrib/anchore/syft`.

| Component | SPDX | Holder |
|---|---|---|
| Syft (`syft`) | **Apache-2.0** | Copyright Anchore, Inc. |

Permissive; redistribution of the compiled binary is granted under the terms of
<https://github.com/anchore/syft/blob/main/LICENSE>. Verified via
`gh api repos/anchore/syft/license` → `Apache-2.0`. Upstream ships the
`LICENSE` file **inside** every release archive, so the terms travel with the
redistributed bytes as well as being referenced here.

The binary is a pure-Go, cgo-free static build that links third-party Go
modules under permissive licenses, enumerated in upstream's `go.mod`.

[`syft/logo.svg`](syft/logo.svg) is the official
[Syft logo](https://anchore.com/wp-content/uploads/2024/11/syft-logo.svg) by
[Anchore](https://anchore.com/), used unmodified under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/);
[`syft/logo.png`](syft/logo.png) is a 512px raster of that same file, which
CC BY 4.0 permits as an adaptation under the same attribution. The Syft and
Anchore names remain marks of Anchore, Inc.; no endorsement is implied.

No modifications are made to any upstream artifact in this repository; they are
republished byte-for-byte inside an OCX bundle.
