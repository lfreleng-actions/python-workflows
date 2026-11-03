<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🐍 Python Workflows

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
<!-- prettier-ignore-end -->

Reusable GitHub Actions workflows that encapsulate the canonical Linux
Foundation Python build / test / release pipeline. Adopt them from a thin
caller workflow instead of copying hundreds of lines of pipeline YAML into
every Python repository.

## Reusable workflows

<!-- markdownlint-disable MD013 -->

| Workflow                                              | Purpose                                                                                                                                 | Trigger style |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| `.github/workflows/build-test.yaml`                   | Single-arch build, test, audit, SBOM/Grype scan and CBOM                                                                                | Pull request  |
| `.github/workflows/build-test-release.yaml`           | Single-arch pipeline plus tag validation, release artefact attachment and draft-release promotion (the caller performs PyPI publishing) | Tag push      |
| `.github/workflows/build-test-multiarch.yaml`         | Multi-architecture (x64 + arm64) variant with native build hooks for C-extension projects                                               | Pull request  |
| `.github/workflows/build-test-release-multiarch.yaml` | Multi-architecture release variant                                                                                                      | Tag push      |

<!-- markdownlint-enable MD013 -->

Each pipeline runs a `repository-metadata` job in parallel (an
informational step that does not gate the build). After `python-build`,
the test, audit and SBOM/Grype branches run in parallel - none gates
another, so a pull request surfaces every failure at once (jobs in
`{ }` run concurrently; `->` denotes sequence):

```text
python-build -> { python-tests | python-audit | sbom -> grype | cbom }
```

The release variants wrap this with `tag-validate` up front and a
release-promotion chain at the end. They also **defer `python-tests`
until `python-audit` and `grype` have both passed**, so a failing audit
skips the expensive test matrix and never reaches release promotion:

```text
python-build -> { python-audit | sbom -> grype } -> python-tests
  -> attach-artefacts -> promote-release
python-build -> cbom
```

### PyPI publishing is the caller's responsibility

The release variants **do not** publish to PyPI. PyPI
trusted publishing matches the OIDC `job_workflow_ref` claim against the
*calling* repository, so a reusable workflow can never act as a
trusted publisher (see the [PyPI docs][trusted-publishers]). To keep
trusted publishing (and the PEP 740 attestations it enables), the caller
must run the publish jobs itself, stacked **after** the reusable call:

```text
caller: release (reusable) -> test-pypi -> pypi
```

The reusable workflow exposes a `tag` output and leaves the run-scoped
build artefact in place, so the caller's publish jobs have everything
they need. See
[`examples/build-test-release/`](examples/build-test-release/) for a
complete caller.

[trusted-publishers]: https://docs.pypi.org/trusted-publishers/

The multi-arch variants add a `python-metadata` job and fan the build,
test and audit jobs across an architecture matrix. The primary build
leg (the first `runners` entry with the first Python version) honours
`build_formats` and builds the single sdist; every other leg builds
wheels and drops any sdist before uploading, which covers `tox_build`
where the project's tox environment ignores `build_formats`. The
release variant fails `attach-artefacts` when the merged `dist/` holds
a duplicated or corrupt sdist, or none when `build_formats` asks for
one.

### CBOM (informational)

The `cbom` job runs `cbom-action` to produce a CycloneDX Cryptography
Bill of Materials: the algorithms, key sizes, modes, protocols and
certificates the code actually calls. An SBOM cannot express that, and
a CBOM is what post-quantum readiness assessments read. For Python the
scanner covers the `pyca/cryptography` library.

**It never fails the workflow run.** The job sets `continue-on-error`
and pins the action's `fail_on_error` to `false`, so a scanner error, a
rejected input, or the job timeout all leave the run green. That covers
the whole leg on purpose — there is no `cbom_permit_fail` input,
because the report is advisory by contract rather than by configuration.
Set `cbom_enabled: false` to drop the job entirely.

It runs in parallel with the test, audit and SBOM legs and gates
nothing, so it never delays another job. The run as a whole still waits
for it, as it does for every job, so a scan that outlasts every other
branch extends the total; `cbom_timeout_minutes` bounds that. In the
self-test it takes 46–55 seconds, well inside the build.
`needs: python-build` orders it after the build; it does its own
checkout and reads no build output. In the release variants it stays
outside the gating inversion: it neither gates `python-tests` nor joins
the release assets, because a job permitted to fail would attach its
output at random.

The multi-arch variants do **not** fan this job across the matrix. That
matrix exists because installed dependency trees differ by architecture
and Python version; a CBOM scan reads the source tree statically and
sees the same bytes on every cell. One run on `ubuntu-latest` produces
one `cbom-files` artefact, retained for 45 days like the SBOM.

<!-- markdownlint-disable MD013 -->

| Name                   | Type    | Default | Description                                                                              |
| ---------------------- | ------- | ------- | ---------------------------------------------------------------------------------------- |
| `cbom_enabled`         | boolean | `true`  | Generate a CBOM (set false to skip the job)                                              |
| `cbom_languages`       | string  | `''`    | Comma-separated languages to scan (`java`, `python`, `go`, `csharp`); empty auto-detects |
| `cbom_exclude`         | string  | `''`    | Comma-separated Java regex patterns to exclude; empty skips test sources                 |
| `cbom_module_cboms`    | boolean | `true`  | Emit a per-module CBOM alongside the consolidated one                                    |
| `cbom_empty_cboms`     | boolean | `true`  | Write CBOM files even when the scan finds no cryptographic assets                        |
| `cbom_timeout_minutes` | number  | `15`    | Timeout for the CBOM job; covers the container image pull as well as the scan            |

<!-- markdownlint-enable MD013 -->

The scanner image is a digest pinned inside `cbom-action`, so it moves
when the action pin moves rather than through a workflow input. The job
writes reports under `RUNNER_TEMP`, never the workspace, so a project
that tracks its own `cbom.json` keeps it.

**Known limitation.** The CBOM's metadata block (repository URL, branch,
commit) comes from the workflow run's own context, so it names the
*calling* repository and commit. Where `repository` or `ref` points at a
different tree, and on a Gerrit-sourced run where the checked-out change
is not the mirror commit, that metadata describes the caller rather than
the source scanned. This does not touch the cryptographic findings themselves.
Fixing it needs explicit metadata inputs on `cbom-action`.

### Artefact names

The SBOM, Grype and CBOM jobs upload `sbom-files`, `grype-scan-results`
and `cbom-files`; the multi-arch variants add `-<arch>` to the first
two. Artefact names are unique per workflow run, so a caller that
invokes one of these workflows more than once in a run (from a matrix,
for example) must give each call its own `artifact_suffix`. Without
one, every call uploads under the same names, and the Grype job can
download and scan another call's SBOM.

The workflow inserts the suffix verbatim and adds no separator, so pass
the leading hyphen yourself: `artifact_suffix: '-${{ matrix.name }}'`
yields `sbom-files-<name>`, `grype-scan-results-<name>` and
`cbom-files-<name>` (`sbom-files-<name>-<arch>` on multi-arch). The
default, empty, leaves the names unchanged.

<!-- markdownlint-disable MD013 -->

| Name              | Type   | Default | Description                                                                         |
| ----------------- | ------ | ------- | ----------------------------------------------------------------------------------- |
| `artifact_suffix` | string | `''`    | Suffix for the SBOM, Grype and CBOM artefact names, e.g. `-<leg>`; `[A-Za-z0-9._-]` |

<!-- markdownlint-enable MD013 -->

### Grype gating

The `grype` job (the in-leg Grype step, in the multi-arch variants)
scans the SBOM with [grype-scan-action][grype-scan-action] and fails
on a match at or above `grype_fail_on`. Six inputs shape which matches
count and when the verdict gates:

<!-- markdownlint-disable MD013 -->

| Name                             | Type    | Default    | Description                                                                                                                    |
| -------------------------------- | ------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `grype_gate_when`                | string  | `always`   | `always` gates every run; `dependencies-changed` gates a change that touches a dependency file (pull request flows; see below) |
| `grype_dependency_policy`        | string  | `declared` | `declared` applies `grype_fail_on` to direct dependencies and `grype_transitive_fail_on` to the rest; `all` treats both alike  |
| `grype_transitive_fail_on`       | string  | `critical` | Severity that fails on a transitive dependency under the `declared` policy (`negligible` … `critical`, or `none`)              |
| `grype_only_fixed`               | boolean | `true`     | Count matches with a fix available; a match no upgrade can clear appears in the report but never gates                         |
| `grype_remediation_window_days`  | string  | `''`       | On an unarmed `dependencies-changed` run, days after a match's fix date during which it warns instead of fails; empty disables |
| `grype_remediation_window_start` | string  | `''`       | Optional `YYYY-MM-DD` floor for the window clock: it starts at the later of this date and the fix date                         |

<!-- markdownlint-enable MD013 -->

`grype_only_fixed` defaults on because a match without a fix leaves the
author nothing to merge: it stays visible in the job summary and the
uploaded report, and the gate falls to the matches an upgrade can
clear. Set it `false` to gate on every match. Under
`dependency-policy: declared`, grype-scan-action classifies a match as
direct or transitive from the SBOM's dependency graph when the SBOM
names a root component; when it does not, every match counts as
declared and `grype_fail_on` applies to each. The gate then
relies on `grype_gate_when` for relief, not on the policy.

With `grype_gate_when: 'dependencies-changed'`, the `sbom` job runs
[dependency-change-action][dependency-change-action] before it
generates the SBOM and uploads the result as `dependency-change.json`
beside the SBOM files. The Grype step reads that manifest and gates
when it reports a change to a dependency file, or when the manifest
is absent or unresolved: the action fails closed, so a comparison it cannot make
(a `repository` or `ref` input naming another tree, a shallow checkout,
a symlinked dependency file) keeps the gate on. The action's README
documents the detection rules, the `python` ecosystem preset, the
base-commit rules and the fail-closed contract. A step named
`Grype gate active: <true|false>` in the Grype job's log shows the
outcome. The `gerrit-validate` job rejects a `grype_gate_when` value
outside `always` and `dependencies-changed`, a policy or severity
outside the action's vocabulary, and a window whose days value is not an
integer or whose start is not a real calendar date.

The remediation window bounds the leniency of an unarmed run in time.
It applies to one kind of run: `grype_gate_when` is
`dependencies-changed`, the manifest resolved, and the change left
every dependency file alone. Every other run, including an `always`
run and an unresolved one, ignores the window and gates. Within an
unarmed run the clock is per match: a match with a fix stays a warning
for `grype_remediation_window_days` days after that fix became
available, then gates as in an armed run. A match with no fix never
gates this way, and a fixed match with no recorded fix date gates at
once unless the caller gives `grype_remediation_window_start`. That
start is an optional floor, not a required opening date: the clock
starts at the later of the fix date and the start date, so a caller
adopting the window can name the adoption day and give an existing
backlog the full window instead of gating on it at once. It must not
be in the future; grype-scan-action enforces that.

The release variants take every input but `grype_gate_when`: a release
scans everything it ships, so the gate is always on. They accept the
remediation window for parity with the pull request flows so a caller
can set one block of `grype_*` inputs for both; it has no effect on a
release verdict, and grype-scan-action still reports the window.

[grype-scan-action]: https://github.com/lfreleng-actions/grype-scan-action
[dependency-change-action]: https://github.com/lfreleng-actions/dependency-change-action

### Repository metadata

The `repository-metadata` job needs the full commit history of every
branch to detect changed files, but not their contents. In a public
repository its checkout keeps `fetch-depth: 0` and adds
`filter: 'blob:none'`, a partial clone: git fetches commits and trees
for every ref and defers file contents until something reads them. A
repository with one heavy branch (a `gh-pages` branch of published
reports, say) no longer sets the clone time for every run.

The filter needs the event payload to mark the repository public
explicitly (`toJSON(github.event.repository.private) == 'false'`).
The checkout does not persist credentials, so a private repository
could not fetch a blob that rename detection later needs; private
repositories, and events whose payload carries no repository (such as
`schedule`), keep the full clone. The comparison goes through `toJSON`
because the expression `==` operator coerces both `null` and `false`
to `0`, so a plain `== false` would also match a missing value.

## Usage

Copy a template from [`examples/`](examples/) into your project's
`.github/workflows/` directory and replace the placeholder `uses:` SHA with
a pinned release of this repository. Each workflow ships in two forms:

- `github.yaml` — a plain GitHub-native caller (pull-request or tag-push
  triggered).
- `gerrit.yaml` — a Gerrit-wrapped caller for projects where Gerrit is the
  source of truth (SCM), integrating with `gerrit_to_platform` voting.

```text
examples/
  build-test/                    { github.yaml, gerrit.yaml }
  build-test-release/            { github.yaml, gerrit.yaml }
  build-test-multiarch/          { github.yaml, gerrit.yaml }
  build-test-release-multiarch/  { github.yaml, gerrit.yaml }
```

A minimal caller looks like this:

<!-- markdownlint-disable MD046 -->

```yaml
jobs:
  build-test:
    permissions:
      contents: read
      pull-requests: read
    uses: lfreleng-actions/python-workflows/.github/workflows/build-test.yaml@<release-sha>
```

<!-- markdownlint-enable MD046 -->

All inputs are optional and default to the canonical behaviour; see the
`inputs:` block at the top of each workflow file for the full, documented
list (project layout, matrix override, tox, pytest, audit allow-lists, SBOM
options, Grype severity gate, CBOM options, runner hardening, and
Gerrit-aware checkout). All four workflows share the runner hardening
inputs; [Egress allow-list](#egress-allow-list) describes them.

## Egress allow-list

Every job hardens its runner with `step-security/harden-runner`. In
`block` mode, `lfreleng-actions/harden-runner-block-action` first loads
the egress allow-list, and the runner then refuses any connection the
list does not name. All four workflows expose the same five inputs to
shape that list, and pass each one to every block-action step:

<!-- markdownlint-disable MD013 -->

| Name                                   | Type    | Default                   | Description                                                                                                     |
| -------------------------------------- | ------- | ------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `harden_runner_egress`                 | string  | `'block'`                 | Egress policy: `block` or `audit`; any other value falls back to `block`                                        |
| `harden_runner_allowlist`              | string  | organisation list, pinned | Baseline allow-list, passed to the action as `config`                                                           |
| `harden_runner_supplemental_allowlist` | string  | `''`                      | Extra list merged with the baseline, in the same coordinate grammar; passed as `supplemental_config`            |
| `harden_runner_supplemental_unpinned`  | boolean | `false`                   | Let the supplemental list omit `@ref` and follow its default branch; passed as `supplemental_unpinned`          |
| `harden_runner_extra_endpoints`        | string  | `''`                      | Inline `host[:port]` tokens, separated by spaces or newlines, merged into the list; passed as `extra_endpoints` |

<!-- markdownlint-enable MD013 -->

**An organisation's own list.** A project that needs hosts beyond the
baseline keeps them in its organisation's supplemental list. An ONAP
caller can follow ONAP's list on its default branch, so a host added
there reaches every ONAP project without a pin bump:

<!-- markdownlint-disable MD046 -->

```yaml
    with:
      harden_runner_supplemental_allowlist: 'onap//'
      harden_runner_supplemental_unpinned: true
```

<!-- markdownlint-enable MD046 -->

The action accepts an unpinned list from the caller's own organisation
alone. A list from another organisation must carry an `@ref` pin, and
`harden_runner_supplemental_unpinned` cannot lift that rule.

**A missing list fails the job.** When
`harden_runner_supplemental_allowlist` names a list, the workflows set
the action's `supplemental_required`, so a list the action cannot find
stops the job at the load step rather than at the first blocked
connection. An empty value adds nothing and requires nothing.

**Inline endpoints are a stopgap.** `harden_runner_extra_endpoints`
unblocks a caller at once, for example
`harden_runner_extra_endpoints: 'registry.example.org:443'`. Move the
host into the organisation's list as the lasting fix, then drop the
input.

**Audit trail.** The action records which list it loaded, and at which
commit, in its `supplemental_source` and `supplemental_sha` outputs.
For an unpinned list those outputs show what each run allowed.

## Gerrit support

The reusable workflows are Gerrit-aware: when a caller sets the
`gerrit_refspec` input they check out the unmerged change with
`checkout-gerrit-change-action` instead of `actions/checkout`. Vote casting
lives in the `gerrit.yaml` caller examples (clear vote → run → report vote),
gated by a `GERRIT_DISABLED` toggle on the build-test workflows so they can
also run manually from the GitHub UI. See the `gerrit.yaml` examples for the
full pattern.

## Verifying release artefacts

With the `attestations` and `sigstore_sign` inputs at their default of
`true`, the release workflows attest every wheel and sdist with SLSA
build provenance and sign each one with Sigstore. They attach the
artefacts to the GitHub release, each with its `<file>.sigstore.json`
bundle. Both steps run inside this reusable workflow, so the Sigstore
certificate behind each one names the reusable workflow as the signer.
The calling run's repository and tag appear in the GitHub extensions
of the certificate, not in its identity:

<!-- markdownlint-disable MD013 -->

| Certificate field                             | Binds                                       | Value                                                                                     |
| --------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Subject Alternative Name (identity)           | This workflow, at the ref the caller pinned | `https://github.com/lfreleng-actions/python-workflows/.github/workflows/<workflow>@<ref>` |
| GitHub Workflow Repository                    | The calling repository                      | `<owner>/<repo>`                                                                          |
| GitHub Workflow Ref and Source Repository Ref | The tag the caller ran on                   | `refs/tags/<tag>`                                                                         |
| GitHub Workflow Trigger                       | The triggering event                        | `push`                                                                                    |

<!-- markdownlint-enable MD013 -->

`<workflow>` is the release workflow the caller uses:
`build-test-release.yaml` or `build-test-release-multiarch.yaml`. Name
the right one in the commands below, because each rejects artefacts the
other signed. `<ref>` is whatever follows `@` in the caller's `uses:`
line, typically a python-workflows commit SHA. Check the identity and
the extensions together: the identity alone accepts an artefact that
any project released through this workflow, and the extensions alone
accept one from any workflow that ran on that tag.

The extensions describe the calling run, not the checkout. The
`repository`, `ref` and `gerrit_refspec` inputs can point the build at
other source, so the extensions identify the packaged source when the
caller leaves all three empty, as the examples do, and not otherwise.

Verify the build provenance attestation of each file with GitHub CLI
v2.102.0 or later; earlier releases matched `--signer-workflow` as a
prefix ([GHSA-wjmr-j3rp-mh2g]) and `--source-ref` without regard to
case ([GHSA-4mq3-hpgx-9cx8]). `--signer-workflow` is mandatory: without
it `gh` expects a signer in the project repository and rejects every
release:

<!-- markdownlint-disable MD013 -->

```shell
gh attestation verify <dist-file> \
  --repo <owner>/<repo> \
  --signer-workflow lfreleng-actions/python-workflows/.github/workflows/build-test-release.yaml \
  --source-ref refs/tags/<tag>
```

<!-- markdownlint-enable MD013 -->

Verify each Sigstore signature bundle with cosign v3 or later. The
workflows emit v0.3 Sigstore bundles, which cosign v2.2 cannot read:

<!-- markdownlint-disable MD013 -->

```shell
cosign verify-blob \
  --bundle <dist-file>.sigstore.json \
  --certificate-identity-regexp \
  '^https://github\.com/lfreleng-actions/python-workflows/\.github/workflows/build-test-release\.yaml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository <owner>/<repo> \
  --certificate-github-workflow-ref refs/tags/<tag> \
  --certificate-github-workflow-trigger push \
  <dist-file>
```

<!-- markdownlint-enable MD013 -->

For a multi-arch release, replace `build-test-release.yaml` with
`build-test-release-multiarch.yaml` in both commands, and in the regular
expression write it as `build-test-release-multiarch\.yaml@`.

Both commands accept any revision of the workflow. To pin the revision
as well, take the commit SHA from the project's caller at the release
tag, add `--signer-digest <sha>` to the `gh` command, and replace
cosign's `--certificate-identity-regexp` with `--certificate-identity`
and the full SAN ending in `@<sha>`.

These checks cover the files attached to the GitHub release. The PEP
740 attestations that PyPI serves come from the caller's own publish
job (see
[PyPI publishing is the caller's responsibility](#pypi-publishing-is-the-callers-responsibility)),
and name the caller's workflow, not this one.

[GHSA-wjmr-j3rp-mh2g]: https://github.com/cli/cli/security/advisories/GHSA-wjmr-j3rp-mh2g
[GHSA-4mq3-hpgx-9cx8]: https://github.com/cli/cli/security/advisories/GHSA-4mq3-hpgx-9cx8

## Testing

[`.github/workflows/testing.yaml`](.github/workflows/testing.yaml) exercises
the reusable workflows against three large downstream consumers
(`dependamerge`, `lftools-uv` and `python-nss-ng`) in parallel, validating
the workflows end-to-end on every pull request. The `dependamerge` and
`python-nss-ng` legs run with `grype_gate_when: 'dependencies-changed'`;
each builds another repository, so the action cannot resolve the
change and the gate must stay on. The `grype-gate-assert` job reads the
run's jobs and SBOM artefacts to prove that it did and that no leg
uploaded a sidecar. The
`grype-gate-wiring` job runs `tests/test-grype-gate-inputs.sh`, which
checks the Grype gate wiring in all four workflows and drives the shared
input validation step against the values it must reject; the same script
runs as a pre-commit hook.

## Design

See [`docs/BRIEF.md`](docs/BRIEF.md) for the full design rationale and the
decisions behind the input surface, Gerrit integration, harden-runner
strategy and multi-architecture structure.
