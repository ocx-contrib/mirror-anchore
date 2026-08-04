# syft/tests/smoke.star — hermetic, offline, and asserting the CONTRACT.
#
# syft's whole job is "point me at a source, get back an SBOM". The check below
# does exactly that against an input this script writes itself, and compares the
# rendered result BYTE FOR BYTE. Nothing here asserts help text, banner prose or
# a vendor string — Anchore reshapes those freely; the catalogued package set is
# the contract.
#
# Offline by construction: a `dir:` source touches only the scratch tree, and
# SYFT_CHECK_FOR_APP_UPDATE=false stops the one thing syft would otherwise reach
# the network for on start-up (`check-for-app-update: true` is upstream's
# default). Container legs may have no egress at all.
#
# `env=` is an OVERLAY on the composed bundle env, not a replacement, so PATH
# still resolves the bundled binary.
SYFT = "syft.exe" if ocx.target_platform.os == ocx.os.Windows else "syft"
ENV = {"SYFT_CHECK_FOR_APP_UPDATE": "false"}

# ── Tier 1 + 2: liveness and version SHAPE ─────────────────────────────────
# Not the exact version and not the word "syft" — a rebrand or a version bump
# must not red the mirror. Digits in the documented shape are the contract.
r_version = ocx.run(SYFT, "--version", env=ENV)
expect.ok(r_version)
expect.matches(r_version.stdout, r"\d+\.\d+\.\d+")

# ── Tier 3: a real SBOM, from input this test wrote ────────────────────────
#
# Three pinned Python requirements go in; syft's python cataloger must find
# exactly those three, with those versions. The output goes through the
# `template` encoder against a template written here, so the comparison is a
# single exact token with no colour codes, no column padding and no prose:
#
#     3|flask@3.0.0;requests@2.31.0;urllib3@2.0.7;
#
# Measured identical on v1.48.0, v1.49.0 and v1.50.0 — the whole in-range set.
# NOTE the template fields are LOWERCASE (`.artifacts`, `.name`, `.version`):
# the encoder feeds the syft-json document model, and `{{ len .Artifacts }}`
# fails at render time with "reflect: call of reflect.Value.Type on zero Value".
#
# This reds against a truncated archive, a wrong-arch binary, a broken
# cataloger, a broken encoder, and a version that silently stops finding
# requirements.txt — all the ways this package can actually be wrong.
#
# Paths are RELATIVE (cwd defaults to the scratch root) so the Windows leg
# never feeds a `C:\…` drive letter into syft's `<scheme>:<path>` parser.
ocx.mkdir("proj")
ocx.write_file("proj/requirements.txt", "requests==2.31.0\nflask==3.0.0\nurllib3==2.0.7\n")
ocx.write_file("sbom.tmpl", "{{ len .artifacts }}|{{ range .artifacts }}{{ .name }}@{{ .version }};{{ end }}")

r_scan = ocx.run(SYFT, "scan", "dir:proj", "-o", "template", "-t", "sbom.tmpl", "-q", env=ENV)
expect.ok(r_scan)
expect.contains(r_scan.stdout, "3|flask@3.0.0;requests@2.31.0;urllib3@2.0.7;")

# ── Negative control ───────────────────────────────────────────────────────
# The assertion above would be worth nothing if syft could not fail. It can:
# a source path that does not exist exits 1 (measured on all three in-range
# versions). Without this, a build that greened on an empty SBOM would still
# have to fail the `contains` above — but proving red is REACHABLE is what
# makes the green mean something.
r_missing = ocx.run(SYFT, "scan", "dir:no-such-source-directory", "-o", "json", "-q", env=ENV)
expect.ne(r_missing.exit_code, 0)

# ── Tier 4 ─────────────────────────────────────────────────────────────────
# syft is a self-contained static binary; metadata.json declares PATH and
# nothing else, and Tier 1 already proves PATH resolves. No further wiring to
# check.
