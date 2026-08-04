# mirror-anchore

OCX mirrors for tools published by [Anchore, Inc.](https://github.com/anchore).
One repository, one spec directory per package.

| Package | Spec | Publishes to | Announced as | Upstream SPDX |
|---|---|---|---|---|
| [Syft](https://github.com/anchore/syft) | [`syft/mirror.yml`](syft/mirror.yml) | `ghcr.io/ocx-contrib/anchore/syft` | [`ocx.sh/anchore/syft`](https://index.ocx.sh/anchore/syft) | `Apache-2.0` |

Each upstream release is discovered, re-bundled, smoke-tested per
`(version, platform)` and only then pushed with cascade tags, after which the
result is announced into the OCX index.

## Layout

```
mirror-base.yml         repo-wide policy every spec inherits via `extends:`
syft/                   one directory per package — same five files each
├── mirror.yml          the spec — never at the repo root
├── metadata.json       bundle interface
├── CATALOG.md          → ocx package describe
├── logo.svg / logo.png describe assets, 512px PNG
└── tests/smoke.star    Starlark smoke test
```

`LICENSE` and `NOTICE.md` are shared at the root. Logos are **not** — each
package carries its own, because a repo-root `logo.*` sits in no workflow's
`paths:` filter, so replacing it would publish nothing until some unrelated
edit happened to fire.

⚠️ `extends:` is a **shallow** merge of top-level keys. A spec that restates
`platforms:` to change one runner drops every `containers:` entry with it, and
nothing reds — the legs simply stop existing, and every `os.features` claim
goes back to being asserted rather than verified. Restate a block in full or
not at all.

## Platforms

`mirror-base.yml` deliberately carries **no `platforms:` block**. Each spec
declares its own matrix in full, which sidesteps the shallow-merge trap by
construction and is forced anyway: the packages here do not share a matrix.

`syft` publishes six platform entries — both Linux arches, both macOS arches
and both Windows arches, everything upstream builds that OCX can express.
Upstream compiles it as a pure-Go binary without cgo, so there is one Linux
build per arch and it is **fully static**: no `PT_INTERP`, no `DT_NEEDED`, not
UPX-packed, measured on both arches of the newest *and* the oldest in-range
release. `os.features` states what an artifact requires *of the host*, so both
Linux keys are **bare** — tagging a static build `+libc.musl` would be a false
requirement that hid it from every glibc host. The `alpine:3.20` container leg
is what turns that claim into evidence; the measurement itself is recorded
above the `assets:` block in `syft/mirror.yml`.

Upstream also builds `linux/ppc64le`, `linux/riscv64` and `linux/s390x`. Those
are not carried, and that is not a policy call: OCX's architecture enum has
only `amd64` and `arm64`, so they cannot be expressed as platform keys at all.

Platforms roll out in three staged passes — linux, then darwin, then windows —
each its own commit and CI run. Staging only the `assets:` keys does **not**
save runner minutes: the generated test matrix is static, so a platform
declared with no matching asset still boots its `macos-14` / `windows-11-arm`
runner, skips every version and reports **success** having tested nothing. The
`platforms:` entry has to be commented out too, and uncommented in the same
edit as its assets.

## Asset selection

Every syft release ships three decoys per platform beside the archive this
mirror carries:

| Asset | Why it is not carried |
|---|---|
| `syft_<V>_<os>_<arch>.sbom` | syft's SBOM *of itself* — metadata, not an installable artifact |
| `syft_<V>_linux_<arch>.deb` / `.rpm` | distro package twins of the same binary |
| `syft_<V>_checksums.txt{,.pem,.sig}` | checksum sidecar plus its cosign cert and signature |

The `$` anchor on every pattern in `syft/mirror.yml` is what keeps them out. An
unanchored pattern reads the `.sbom` twin as a second format for that platform
and fails the version with an ambiguous `>1 match`.

Note also that **`v1.47.0` does not exist upstream** — the history runs
v1.46.0 → v1.48.0. Not a draft, not a prerelease, simply never published. A gap
in the discovered version sequence is upstream's, not an indexing bug.

## Editing

| File | Edit | Regenerate after |
|------|------|------------------|
| `mirror-base.yml`, `<pkg>/mirror.yml` | hand | yes — see below |
| `<pkg>/{metadata.json,CATALOG.md,logo.*}` | hand | — |
| `<pkg>/tests/smoke.star` | hand | — |
| `.github/workflows/*.yml` | **generated — never hand-edit** | re-run when a spec changes |

```bash
ocx-mirror package pipeline generate ci \
  --spec syft/mirror.yml
```

**Name every spec.** `--spec` *appends* rather than replaces, so a command
naming a subset silently stops rendering the rest while staying green — and the
drift guard reds on a generated workflow the current spec set no longer
produces.

`verify-generated.yml` exits 65 on drift. If a generated workflow is wrong, the
spec or the renderer template is wrong — fix it there and regenerate.

Run `direnv allow` once to put the pinned toolchain on `PATH`, and invoke
`ocx-mirror` directly — never `ocx run -- ocx-mirror`, which pins
`OCX_BINARY_PIN` to the bootstrap `ocx` and false-reds the nested push.

## The binaries claim

Both Anchore archives are **flat** — `CHANGELOG.md`, `LICENSE`, `README.md` and
the executable all sit at the archive root with no wrapper directory — so
`strip_components: 0` puts them at the content root and the bundle's only PATH
entry is a bare `${installPath}`. `bin_scan` only looks *below* an
`${installPath}/<dir>` entry, so `auto`/`verify` is rejected at spec load with
exit 65. `mirror-base.yml` therefore sets `bin_scan: off` and each
`metadata.json` hand-lists its one binary — the blessed shape for this layout.

## The smoke tests are hermetic

Anchore's tools are network-facing by default (syft can pull images; grype
downloads a vulnerability database), and container legs may have no egress. The
smoke tests therefore exercise only paths that touch nothing but the scratch
tree, with `*_CHECK_FOR_APP_UPDATE=false` to suppress the start-up version
ping. `syft/tests/smoke.star` writes a three-package `requirements.txt`, scans
it with the `template` encoder, and compares the rendered inventory byte for
byte — a real SBOM from an input the test wrote itself, plus a negative control
proving a red is reachable.

## Required secrets

| Secret | Use |
|--------|-----|
| `OCX_ANNOUNCE_TOKEN` | opens the index pull request from the `ocx-contrib/index` fork |
| `OCX_MIRROR_DISCORD_HOOK` | notify-stage Discord webhook URL |

(Inherited from the `ocx-contrib` org with visibility ALL. GHCR pushes use the
run's own `GITHUB_TOKEN` — no registry secret needed.)

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Upstream assets are out of scope; each
package's redistribution license is recorded in [`NOTICE.md`](NOTICE.md).
