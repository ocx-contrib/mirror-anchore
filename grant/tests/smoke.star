# grant/tests/smoke.star — hermetic, offline, and asserting the CONTRACT.
#
# Everything grant reads here is written by this script into the scratch tree,
# so nothing depends on the network, on a container image's package set, or on
# what any license database currently says. Verified end to end inside a
# network-less namespace on all seven in-range versions (0.6.0, 0.6.2, 0.6.3,
# 0.6.4, 0.6.6, 0.6.7, 0.6.8) — identical exit codes and identical decisions.
#
# No platform branch: upstream ships no Windows asset at all (see mirror.yml),
# so `grant` is never `grant.exe` here.
GRANT = "grant"

# A two-package SPDX document: one permissively licensed, one copyleft. The
# licenses are what the policies below discriminate on.
SBOM = """{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "ocx-smoke",
  "documentNamespace": "https://ocx.sh/smoke/grant",
  "creationInfo": { "created": "2026-01-01T00:00:00Z", "creators": ["Tool: ocx-smoke"] },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-alpha",
      "name": "alpha",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package-beta",
      "name": "beta",
      "versionInfo": "2.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "GPL-3.0-only",
      "licenseDeclared": "GPL-3.0-only",
      "copyrightText": "NOASSERTION"
    }
  ]
}
"""

ocx.write_file("sbom.spdx.json", SBOM)
ocx.write_file("allow-mit.yaml", "allow:\n    - MIT\n")
ocx.write_file("allow-both.yaml", "allow:\n    - MIT\n    - GPL-3.0-only\n")
ocx.write_file("garbage.json", "this is not an SBOM\n")

# ── Tier 1: liveness ───────────────────────────────────────────────────────
r_version = ocx.run(GRANT, "version")
expect.ok(r_version)

# ── Tier 2: version SHAPE, from the structured output ──────────────────────
#
# `grant version` prints a labelled banner, so the version is read from the
# machine-readable form instead: every `-o json` run carries the tool name and
# its own version at the document root. Asserting the SHAPE (`\d+\.\d+\.\d+`)
# and not a value keeps this true for every release.
r_list = ocx.run(GRANT, "list", "-o", "json", "sbom.spdx.json")
expect.ok(r_list)
expect.matches(r_list.stdout, r"\"tool\":\s*\"grant\"")
expect.matches(r_list.stdout, r"\"version\":\s*\"\d+\.\d+\.\d+\"")

# ── Tier 3a: it PARSES the document ────────────────────────────────────────
#
# Both packages are cataloged (`"total": 2`) and each license id is resolved
# against grant's embedded SPDX list — the asserted `detailsUrl` appears
# nowhere in the input, grant composes it from the id it resolved. That is a
# transformation, not an echo.
#
# This assertion is load-bearing for a specific reason: `grant list` on input
# it cannot parse exits **0** with an empty catalog (measured), so `expect.ok`
# above would be vacuous on its own.
expect.matches(r_list.stdout, r"\"total\":\s*2")
expect.contains(r_list.stdout, "https://spdx.org/licenses/MIT.json")
expect.contains(r_list.stdout, "https://spdx.org/licenses/GPL-3.0-only.json")

# ── Tier 3b: the POLICY decides, and the exit code carries the verdict ─────
#
# Same document, two policies. Allowing MIT alone denies `beta` and the run
# exits 1; allowing both licenses exits 0 and denies nothing. A tool that
# merely echoed its input could not produce both.
r_deny = ocx.run(GRANT, "check", "-c", "allow-mit.yaml", "-o", "json", "sbom.spdx.json")
expect.eq(r_deny.exit_code, 1)
expect.matches(r_deny.stdout, r"\"status\":\s*\"noncompliant\"")
expect.matches(r_deny.stdout, r"\"allowed\":\s*1")
expect.matches(r_deny.stdout, r"\"denied\":\s*1")

r_allow = ocx.run(GRANT, "check", "-c", "allow-both.yaml", "-o", "json", "sbom.spdx.json")
expect.ok(r_allow)
expect.matches(r_allow.stdout, r"\"status\":\s*\"compliant\"")
expect.matches(r_allow.stdout, r"\"allowed\":\s*2")

# ── Negative control: unparsable input is an ERROR, not a pass ─────────────
#
# Fed something that is not an SBOM, `check` reports `"status": "error"` with
# an empty catalog and exits non-zero (measured on all seven in-range
# versions). This is what makes the green results above evidence — a red is
# reachable from the same code path.
r_bad = ocx.run(GRANT, "check", "-c", "allow-both.yaml", "-o", "json", "garbage.json")
expect.ne(r_bad.exit_code, 0)
expect.matches(r_bad.stdout, r"\"status\":\s*\"error\"")

# ── Tier 4 ─────────────────────────────────────────────────────────────────
# grant is a self-contained static binary; metadata.json declares PATH and
# nothing else, and Tier 1 already proves PATH resolves. No further wiring to
# check.
