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
test and audit jobs across an architecture matrix.

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
Gerrit-aware checkout).

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
the workflows end-to-end on every pull request.

## Design

See [`docs/BRIEF.md`](docs/BRIEF.md) for the full design rationale and the
decisions behind the input surface, Gerrit integration, harden-runner
strategy and multi-architecture structure.
