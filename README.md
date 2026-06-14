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

| Workflow | Purpose | Trigger style |
| -------- | ------- | ------------- |
| `.github/workflows/build-test.yaml` | Single-arch build, test, audit, SBOM and Grype scan | Pull request |
| `.github/workflows/build-test-release.yaml` | Single-arch pipeline plus tag validation, Test PyPI / PyPI publishing and release promotion | Tag push |
| `.github/workflows/build-test-multiarch.yaml` | Multi-architecture (x64 + arm64) variant with native build hooks for C-extension projects | Pull request |
| `.github/workflows/build-test-release-multiarch.yaml` | Multi-architecture release variant | Tag push |

<!-- markdownlint-enable MD013 -->

Each pipeline runs a `repository-metadata` job in parallel (an
informational step that does not gate the build), alongside the build
chain:

```text
python-build -> {python-tests, python-audit, sbom} -> grype
```

The release variants add `tag-validate`, `test-pypi`, `pypi`,
`attach-artefacts` and `promote-release`. The multi-arch variants add a
`python-metadata` job and fan the build / test / audit jobs out across an
architecture matrix.

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
options, Grype severity gate, runner hardening, and Gerrit-aware checkout).

## Gerrit support

The reusable workflows are Gerrit-aware: when a caller sets the
`gerrit_refspec` input they check out the unmerged change with
`checkout-gerrit-change-action` instead of `actions/checkout`. Vote casting
lives in the `gerrit.yaml` caller examples (clear vote → run → report vote),
gated by a `GERRIT_DISABLED` toggle on the build-test workflows so they can
also run manually from the GitHub UI. See the `gerrit.yaml` examples for the
full pattern.

## Testing

[`.github/workflows/testing.yaml`](.github/workflows/testing.yaml) exercises
the reusable workflows against three large downstream consumers
(`dependamerge`, `lftools-uv` and `python-nss-ng`) in parallel, validating
the workflows end-to-end on every pull request.

## Design

See [`docs/BRIEF.md`](docs/BRIEF.md) for the full design rationale and the
decisions behind the input surface, Gerrit integration, harden-runner
strategy and multi-architecture structure.
