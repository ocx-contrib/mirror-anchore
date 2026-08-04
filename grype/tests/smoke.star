# grype/tests/smoke.star — hermetic, offline, and asserting the CONTRACT.
#
# ⚠️ WHY THERE IS NO SCAN HERE. grype's matching engine needs a vulnerability
# database, and every path to one is network: `grype db update` downloads it,
# `db auto-update: true` fetches it on first use, and a bare `grype <target>`
# on a runner with no database exits non-zero having matched nothing. Container
# legs may have no egress at all, so a scan would be a flake, not a test.
#
# What IS hermetic, DB-free, and stable across the whole in-range set is the
# `explain` path: grype reads a grype-JSON findings document on stdin, binds it
# to its own model, and renders an explanation for a requested vulnerability
# ID. That exercises real parsing and real transformation on input this script
# writes itself. Verified running under `alpine:3.20` with `--network none` on
# v0.115.0, v0.116.0 and v0.116.1 — identical output, exit 0, no DB touched.
#
# `env=` is an OVERLAY on the composed bundle env, not a replacement, so PATH
# still resolves the bundled binary.
GRYPE = "grype.exe" if ocx.target_platform.os == ocx.os.Windows else "grype"
ENV = {
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",  # upstream default is true
    "GRYPE_DB_AUTO_UPDATE": "false",        # upstream default is true
}

# ── Tier 1 + 2: liveness and version SHAPE, from the structured output ─────
#
# `version -o json` is the machine-readable form, so this asserts a schema
# rather than a banner: a semver-shaped `version` and an integer
# `supportedDbSchema` (the DB format this binary speaks — a real compatibility
# fact, and one whose VALUE must not be asserted since it legitimately moves
# 5→6→7 across releases). `\s*` absorbs any change to the JSON indentation.
r_version = ocx.run(GRYPE, "version", "-o", "json", env=ENV)
expect.ok(r_version)
expect.matches(r_version.stdout, r"\"version\":\s*\"\d+\.\d+\.\d+\"")
expect.matches(r_version.stdout, r"\"supportedDbSchema\":\s*\d+")

# ── Tier 3: parse a findings document and explain it ───────────────────────
#
# The document below is synthetic and self-contained — a fabricated CVE against
# a fabricated namespace — so nothing about it depends on the real world or on
# what any vulnerability database currently says.
#
# The asserted token is grype's COMPOSED vulnerability key,
# `<namespace>:<id>`, which appears nowhere in the input as a single string:
# grype joins the record's `namespace` and `id` while rendering the match
# explanation. That is a transformation, not an echo.
FINDINGS = """{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2026-99999",
        "dataSource": "https://example.invalid/CVE-2026-99999",
        "namespace": "example:distro:alpine:3.20",
        "severity": "High",
        "urls": [],
        "description": "synthetic finding used by an offline smoke test",
        "fix": { "versions": ["9.9.9"], "state": "fixed" },
        "advisories": []
      },
      "relatedVulnerabilities": [],
      "matchDetails": [
        {
          "type": "exact-direct-match",
          "matcher": "python-matcher",
          "searchedBy": { "language": "python" },
          "found": { "versionConstraint": "< 9.9.9 (python)", "vulnerabilityID": "CVE-2026-99999" }
        }
      ],
      "artifact": {
        "id": "aaaaaaaaaaaaaaaa",
        "name": "urllib3",
        "version": "2.0.7",
        "type": "python",
        "locations": [{ "path": "/requirements.txt" }],
        "language": "python",
        "licenses": [],
        "cpes": ["cpe:2.3:a:urllib3:urllib3:2.0.7:*:*:*:*:*:*:*"],
        "purl": "pkg:pypi/urllib3@2.0.7",
        "upstreams": []
      }
    }
  ],
  "source": { "type": "directory", "target": "/proj" },
  "distro": { "name": "", "version": "", "idLike": null },
  "descriptor": { "name": "grype", "version": "0.0.0" }
}
"""

r_explain = ocx.run(GRYPE, "explain", "--id", "CVE-2026-99999", stdin=FINDINGS, env=ENV)
expect.ok(r_explain)
expect.contains(r_explain.stdout, "example:distro:alpine:3.20:CVE-2026-99999")
expect.contains(r_explain.stdout, "pkg:pypi/urllib3@2.0.7")

# ── Negative control 1: it really parses, it does not cat ──────────────────
# An `explain` that merely echoed its input would pass everything above. Fed
# something that is not JSON, grype exits 1 with a parse error (measured on all
# three in-range versions). This is what makes the assertions above evidence.
r_garbage = ocx.run(GRYPE, "explain", "--id", "CVE-2026-99999", stdin="this is not json", env=ENV)
expect.ne(r_garbage.exit_code, 0)

# ── Negative control 2: the output is ID-driven, and exit 0 proves nothing ──
# Asking for an ID the document does not contain EXITS 0 with EMPTY stdout —
# measured. So `expect.ok` alone would be vacuous here, exactly the
# empty-result-exits-0 trap. This pins that the rendered content is selected by
# --id rather than dumped wholesale.
r_absent = ocx.run(GRYPE, "explain", "--id", "CVE-1999-00001", stdin=FINDINGS, env=ENV)
expect.false("CVE-2026-99999" in r_absent.stdout)

# ── Tier 4 ─────────────────────────────────────────────────────────────────
# grype is a self-contained static binary; metadata.json declares PATH and
# nothing else, and Tier 1 already proves PATH resolves. No further wiring to
# check.
