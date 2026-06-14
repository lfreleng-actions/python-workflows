<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

<!-- markdownlint-disable MD013 -->

# Design Brief: Reusable Python Workflows

This document records the full design conversation (a "grilling" session)
that produced the contract for the reusable workflows in this repository.
It captures the goal, every design question raised, the decision reached,
and the resulting implementation contract.

## Goal

Convert `python-workflows` (currently the bare `actions-template`
scaffold) into a repository of **reusable GitHub Actions workflows** that
encapsulate the canonical Linux Foundation Python build/test/release
pipeline. The workflows must serve three flagship consumers and any
future Python project:

- **dependamerge** — standard single-arch Python project (the canonical
  reference for the pipeline).
- **lftools-uv** — another large standard single-arch Python project.
- **python-nss-ng** — a multi-architecture (x64 + arm64) project that
  builds C code (NSS/NSPR) and therefore needs native build hooks.

Deliverables:

- Four reusable workflows (`workflow_call`).
- An `examples/` tree of copy-paste caller templates, in two forms each:
  a plain GitHub-native caller and a Gerrit-wrapped caller (for projects
  where Gerrit is the source of truth).
- A `.github/workflows/testing.yaml` that exercises the reusable
  workflows against the three consumers in parallel.
- This brief.

The work will be delivered as a pull request against
`lfreleng-actions/python-workflows` (`upstream/main`), raised from the
`modeseven-lfreleng-actions` fork.

## Source material consulted

- `dependamerge/.github/workflows/build-test.yaml` and
  `build-test-release.yaml` (canonical standard pipeline).
- `lftools-uv/.github/workflows/build-test.yaml` (standard + cache-clear,
  now out of scope).
- `python-nss-ng/.github/workflows/build-test.yaml` (multi-arch + native).
- Action input surfaces: `python-build-action`, `python-test-action`,
  `python-audit-action`, `python-sbom-action`, `repository-metadata-action`,
  `build-metadata-action`, `make-action`.
- `gerrit_to_platform/examples/workflows/*` and
  `docs/GITHUB_WORKFLOW_INPUT_LIMIT_SOLUTION.md`.
- ONAP canonical Gerrit workflow `onap/ccsdk-oran` `gerrit-merge-cbom.yaml`.

## Decisions (Q&A)

### Q1 — One parameterized workflow, or a family?

**Decision: two families (standard + multi-arch), not one mega-workflow.**
Cases 1 and 2 (dependamerge, lftools-uv) collapse onto one standard path.
nss-ng's per-arch fan-out and native pre-build differ structurally enough
to warrant a separate multi-arch workflow rather than drowning the common
case in conditionals.

### Q2 — File inventory and naming

**Decision: four reusable workflows** in `python-workflows/.github/workflows/`,
each `on: workflow_call`:

| File | Serves | Trigger semantics |
| --- | --- | --- |
| `build-test.yaml` | dependamerge, lftools-uv | PR / non-release |
| `build-test-release.yaml` | dependamerge, lftools-uv | tag-push release |
| `build-test-multiarch.yaml` | python-nss-ng | PR / non-release |
| `build-test-release-multiarch.yaml` | python-nss-ng | tag-push release |

`build-test` and release have materially different job graphs, so they
stay separate files (not one file gated by an input). The `-multiarch`
suffix is the agreed naming.

### Cache-clear — out of scope

Cache clearing is being removed from `python-build-action` and the
workflows. A dedicated, more powerful cache-clear workflow now exists
separately (simpler permissions model). Cache clearing is therefore
**entirely out of scope** for this work. This collapses lftools-uv onto
the dependamerge baseline.

### Q3 — Targeting foreign repositories

Reusable workflows run as separate jobs on fresh runners and check out
their own code, so `testing.yaml` cannot build foreign repos unless the
reusable workflows can target them.

**Decision: bake permanent optional inputs into all four workflows:**

- `repository` (static `default: ''`, with a `github.repository`
  fallback applied at each checkout step) → fed to checkout.
- `ref` (default `''`) → branch/tag/SHA to check out.

These are useful beyond testing (e.g. orchestration). `testing.yaml`
defaults each target to the consumer's default/HEAD branch.

### Q4 — Input passthrough surface (curated middle)

**`build-test.yaml` (standard) inputs:**

| Input | Feeds | Default |
| --- | --- | --- |
| `repository` | checkout | `''` (use-site `github.repository` fallback) |
| `ref` | checkout | `''` |
| `path_prefix` | build/test/audit/sbom/metadata | `.` |
| `python_version` | build (single-version override) | `''` |
| `python_versions` | matrix override (JSON) | `''` (use build-metadata discovery) |
| `build_formats` | build | `''` |
| `tox_build` | build | `false` |
| `tox_tests` | test | `false` |
| `tox_envs` | test | `''` |
| `tests_path` | test | `''` |
| `pytest_args` | test | `''` |
| `test_permit_fail` | test | `false` |
| `audit_permit_fail` | audit | `false` |
| `audit_ignore_vulns` | audit | `''` |
| `audit_allow_list_config` | audit (`config`) | `''` |
| `sbom_include_dev` | sbom | `false` |
| `sbom_format` | sbom | `both` |
| `grype_fail_on` | grype gate | `medium` |
| `grype_permit_fail` | grype (falls back to `vars.NO_BLOCK_AUDIT_FAIL`) | `false` |
| `harden_runner_egress` | harden-runner | `block` |
| `harden_runner_allowlist` | harden-runner allow-list ref | pinned lfreleng list |
| `gerrit_refspec` / `gerrit_project` / `gerrit_branch` / `gerrit_url` | Gerrit-aware checkout | `''` |

**`build-test-release.yaml`:** all of the above plus `attestations`
(`true`), `sigstore_sign` (`true`), `pypi_environment` (`production`),
`test_pypi_environment` (`development`), `tag` (`''`). Release workflows
do **not** carry `GERRIT_DISABLED` semantics.

**`build-test-multiarch.yaml`:** standard set plus `runners` (JSON),
`auditwheel` (`true`), `manylinux_version` (`manylinux_2_38`), `make`
(`false`), `make_args` (`''`), `setup_script` (`''`), `ld_library_path`
(`''`).

**Deliberately not exposed** (kept at action defaults, add later on
demand): `validate_output`, `strict_validation`, `export_env_vars`,
`debug`, `gerrit_include_comment`, `change_detection`, `git_fetch_depth`,
`sbom_spec_version`, `filename_prefix`, `purge_artefact_path`,
`skip_version_patch`, `editable`, `summary`, and the granular
`allow_list_path/url/org/disable` (superseded by the single `config`).

Rulings: `permit_fail` split into `test_permit_fail` / `audit_permit_fail`;
`python_versions` override added (defaulting to build-metadata discovery).

### Q5 — Native-setup script hook (multi-arch only)

**Decision:**

- Hook is a **file path** (`setup_script`) to a script committed in the
  consumer repo, **not** inline shell — mitigates shell-injection concerns.
- Validated with `lfreleng-actions/path-check-action`; if non-empty and
  missing, fail loudly; if empty, skip.
- Executed via `bash` from repo root; arch available via `uname -m`.
- **Scope: all four job types** (build, test, audit, sbom), relying on
  script idempotency (system-package installs are a prerequisite to the
  native compile).
- `setup_script` is **multi-arch only**; the standard workflow stays clean.
- python-nss-ng's currently-inline NSS/NSPR steps will be extracted to a
  committed script (e.g. `.github/scripts/setup-nss.sh`) via a separate
  draft PR (see Delivery).

### make-action

`python-build-action` already wraps `lfreleng-actions/make-action`
internally when `make: true`. The multi-arch **build** job therefore
leverages make-action transitively by passing `make` + `make_args` to
`python-build-action` — no separate make-action call. The
test/audit/sbom jobs use `setup_script` (which can itself call `make`),
because they additionally need `apt` system packages that make-action
cannot install.

### Q6 — `examples/` layout

**Decision: eight example files, per-workflow subfolders, each with a
`github.yaml` (plain caller) and `gerrit.yaml` (Gerrit-wrapped caller):**

```text
examples/
  build-test/                    { github.yaml, gerrit.yaml }   # + GERRIT_DISABLED
  build-test-release/            { github.yaml, gerrit.yaml }   # no GERRIT_DISABLED
  build-test-multiarch/          { github.yaml, gerrit.yaml }   # + GERRIT_DISABLED
  build-test-release-multiarch/  { github.yaml, gerrit.yaml }   # no GERRIT_DISABLED
```

Each file is heavily commented as a copy-paste template.

### Q7 — Gerrit-aware checkout in the reusable workflows

Because the unmerged Gerrit change ref lives only behind
`checkout-gerrit-change-action`, and reusable-workflow jobs own their own
checkout on fresh runners, **the reusable workflows must be Gerrit-aware**.

**Decision:**

- Add `gerrit_refspec`, `gerrit_project`, `gerrit_branch`, `gerrit_url`
  inputs (default `''`) to all four workflows.
- Every checkout-bearing job branches: if `gerrit_refspec != ''` use
  `checkout-gerrit-change-action`; else `actions/checkout` with
  `repository`/`ref`.
- **Voting stays entirely in the `gerrit.yaml` wrapper** (clear-vote →
  reusable call → vote, via `gerrit-review-action` +
  `im-open/workflow-conclusion`), gated on `GERRIT_DISABLED != true`. The
  reusable workflow needs no Gerrit SSH secret — only the wrapper's vote
  jobs do.
- We use **`GERRIT_DISABLED`** (per the explicit spec and the ONAP
  example), not g2p's `MANUAL_DISPATCH`. `GERRIT_DISABLED` appears on
  `build-test` wrappers only, not release wrappers.
- `gerrit_url`: explicit input, falling back at the point of use to
  `vars.GERRIT_URL` via `${{ inputs.gerrit_url != '' && inputs.gerrit_url || vars.GERRIT_URL }}`
  (input `default:` cannot reference `vars`).

The nine standard Gerrit inputs on the wrappers:
`GERRIT_BRANCH`, `GERRIT_CHANGE_ID`, `GERRIT_CHANGE_NUMBER`,
`GERRIT_CHANGE_URL`, `GERRIT_EVENT_TYPE`, `GERRIT_PATCHSET_NUMBER`,
`GERRIT_PATCHSET_REVISION`, `GERRIT_PROJECT`, `GERRIT_REFSPEC`
(+ `GERRIT_DISABLED` on build-test = 10, within the new 25-input limit).

### Q8 — Harden-runner egress strategy

**Decision: configurable with a secure default.**

| Input | Default |
| --- | --- |
| `harden_runner_egress` | `block` |
| `harden_runner_allowlist` | pinned `lfreleng-actions//.github/harden-runner/lfreleng-actions/allow_list.txt@18d9c444…` |

`block` runs `harden-runner-block-action` (out-of-band allow-list loader)
plus harden-runner block mode (dependamerge/nss-ng pattern). `audit` skips
the loader (lftools-uv pattern). Default is **block** (stronger posture).
Reuse the exact existing pins:

- `step-security/harden-runner@9af89fc71515a100421586dfdb3dc9c984fbf411` (v2.19.4)
- `lfreleng-actions/harden-runner-block-action@42663a22f7abe31521cbc6120901353a4b2849bc` (v0.2.0)
- allow_list `@18d9c4446bea555d0783e850f6d295f844fe8f67` (v0.1.1)

`testing.yaml` inherits block + lfreleng allow-list by default.

### Q9 — Release: environments, secrets, permissions

**Decision:**

- Environment names as inputs: `test_pypi_environment` (`development`),
  `pypi_environment` (`production`) — matches dependamerge.
- **Explicit `secrets:` contract** (not `secrets: inherit`):
  `pypi_credential` (required), `test_pypi_credential` (required).
- Release examples show callers mapping `secrets:` explicitly.
- `id-token: write` is declared by the reusable workflow's pypi jobs; the
  required `permissions:` are documented in the example header.

### Q10 — Referencing the reusable workflows / pinning

**Decision:**

- `testing.yaml` references the reusable workflows by **local path**
  (`uses: ./.github/workflows/build-test.yaml`) — already standard practice.
- `examples/` reference a **non-functional placeholder commit SHA** with a
  `# vX.Y.Z` comment and replace-me instructions (keeps GitHub Copilot's
  pin checks satisfied and teaches the SHA-pinning convention).
- Versioning of `python-workflows` itself is handled by the existing
  `tag-push.yaml` process; consumers pin to a release commit SHA. Out of
  scope here.

### Q11 — Job composition and SBOM/Grype configurability

**Decision:**

- Reproduce the **full** dependamerge graph faithfully:
  `python-build` → {`python-tests`, `python-audit`, `sbom`} → `grype`,
  with `repository-metadata` running in parallel as an informational
  job (no `needs`, so it does not gate the build). All jobs
  **always-on** (no enable/disable toggles).
- Expose `grype_fail_on` (default `medium`) and `grype_permit_fail`
  (default `false`, falling back to `vars.NO_BLOCK_AUDIT_FAIL` at the
  use-site).
- **`sbom_format` accepts `json` or `both`** (default `both`); the
  embedded Grype audit requires a JSON SBOM, so xml-only output is
  unsupported. An undocumented `xml` value is coerced to `both` at
  the use-site.
- **Context-driven `gerrit_summary`**: the `repository-metadata` job sets
  `gerrit_summary: ${{ inputs.gerrit_refspec != '' }}` so Gerrit runs get
  the Gerrit summary and GitHub runs do not.

### Q12 — Multi-arch internal structure

**Decision:**

- **Collapse per-arch duplication into matrixed jobs** (architecture ×
  python-version). `runners` input default:

  ```json
  [{"runner":"ubuntu-latest","arch":"x64"},{"runner":"ubuntu-24.04-arm","arch":"arm64"}]
  ```

  providing both `runs-on` and an `arch` token for artefact naming.
- A separate `python-metadata` job (using `build-metadata-action`) runs
  first to emit the version matrix (the per-arch builds need it up front).
- **SBOM + Grype run per-arch** (native dependency trees differ per arch).
- The structural asymmetry between standard (matrix from `python-build`
  output) and multi-arch (separate `python-metadata` job) is accepted.

### Q13 — Repo conversion and `testing.yaml` targets

**Decision:**

- **Delete** the template `action.yaml`; **rewrite** `README.md` to
  document the reusable workflows and point at `examples/`.
- `testing.yaml` targets `lfreleng-actions/{dependamerge, lftools-uv}` at
  each repo's default branch. The `python-nss-ng` leg temporarily targets
  the fork (`modeseven-lfreleng-actions/python-nss-ng@main`) because the
  multi-arch jobs need the committed `setup-nss.sh` (and the
  reusable-workflow migration), which lives only on the fork until the
  nss-ng migration lands upstream.
- `testing.yaml` triggers on **`pull_request` + `workflow_dispatch`** so
  the introducing PR is gated by the workflows actually working.
- Standard targets (dependamerge, lftools-uv) run through a parallel
  matrix calling `build-test.yaml`; python-nss-ng is a separate parallel
  job calling `build-test-multiarch.yaml`.

### Q14 — Commit/PR workflow

**Decision:**

- All work happens **locally** with signed, DCO-signed-off commits (no
  GitHub-API edits). Branch off the fork, push to `origin`, PR against
  `upstream` (`lfreleng-actions/python-workflows`) `main`.
- **Fine-grained atomic commits**, conventional + capitalized, ≤50-char
  subjects. Indicative sequence:
  1. `Chore: Remove action template scaffolding`
  2. `Feat: Add standard build-test reusable workflow`
  3. `Feat: Add standard release reusable workflow`
  4. `Feat: Add multiarch build-test reusable workflow`
  5. `Feat: Add multiarch release reusable workflow`
  6. `Docs: Add reusable workflow caller examples`
  7. `CI: Add testing workflow for downstream repos`
  8. `Docs: Rewrite README for reusable workflows`
  9. `Docs: Add design brief`
- **SPDX headers** on every new file: `Apache-2.0` +
  `2026 The Linux Foundation`.
- **Co-authorship trailer**: `Co-authored-by: Claude <noreply@anthropic.com>`,
  above the `Signed-off-by` DCO line (from the local git identity).
- After the PR is up: run **Copilot review cycles**, grouping fixes into a
  single dedicated copilot-feedback commit and resolving each thread
  against its item.

## Delivery: three coordinated PRs

1. **`lfreleng-actions/python-workflows` (main deliverable, non-draft)** —
   the four reusable workflows, `examples/`, `testing.yaml`, README, and
   this brief. Raised from the `modeseven-lfreleng-actions` fork branch
   against `upstream/main`.
2. **`lfreleng-actions/dependamerge` (DRAFT)** — replace its
   `build-test.yaml` + `build-test-release.yaml` with thin GitHub-native
   callers of the standard reusable workflows. dependamerge is a
   GitHub/PR project, so no Gerrit wrapping.
3. **`lfreleng-actions/python-nss-ng` (DRAFT)** — (a) extract the inline
   NSS/NSPR setup into a committed `setup-nss.sh` consumed via
   `setup_script`, and (b) migrate its workflows to thin callers of the
   `-multiarch` reusable workflows.

During the draft phase, the consumer PRs (#2, #3) reference the fork
workflows by **branch ref**
(`modeseven-lfreleng-actions/python-workflows/.github/workflows/<wf>.yaml@feat/reusable-python-workflows`)
with a loud comment that this is temporary. A branch ref (not a pinned
SHA) is used deliberately so the draft consumer PRs continuously validate
end-to-end against the latest fork push as the work iterates.

## Open follow-ups (post-merge)

- Once `python-workflows` merges upstream and `tag-push.yaml` cuts the
  first release: update `examples/` placeholder SHAs to the real pinned
  release SHA.
- Swap the dependamerge (#2) and python-nss-ng (#3) consumer PRs from the
  fork branch ref to the pinned `lfreleng-actions/python-workflows@<release-sha>`,
  take them out of draft, and send for human review.
- ✅ **Done** — `testing.yaml`'s nss-ng leg now targets
  `lfreleng-actions/python-nss-ng`, pinned to the v1.2.0 release commit
  (`e6e1975`), which ships `setup-nss.sh`.
