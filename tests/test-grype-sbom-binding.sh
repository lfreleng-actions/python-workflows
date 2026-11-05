#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Wiring check for the binding between the SBOM upload and the Grype
# scan that reads it.
#
# Artefact names are unique per run only until a second call of the
# same workflow uploads under the same name. A Grype job that
# downloads its SBOM by name can then read another call's SBOM. So the
# single-arch workflows export the upload step's artifact-id from the
# sbom job and the grype job downloads by that ID; the multi-arch
# workflows scan the SBOM in the leg that generated it and download
# nothing, because a matrix job cannot export one ID per leg.
#
# An empty ID is no binding either: download-artifact given neither a
# name nor an ID downloads every artefact in the run. So a step before
# the download fails the job when the sbom job's output is empty.
#
# This script reads the four workflows and fails when a Grype scan is
# fed by anything but one of those two bindings: a download by name or
# pattern anywhere, a download by an ID that is not the sbom job's
# upload, an output bound to another step, a download not guarded
# against an empty ID, or a scan in a job that neither uploads nor
# downloads the SBOM. It then mutates a copy of a single-arch and a
# multi-arch workflow in each way the check must catch and expects
# each mutant to fail.
#
# Usage: bash tests/test-grype-sbom-binding.sh [<workflows-dir>]
#
# Needs python3 with PyYAML.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
workflows="${1:-${repo_root}/.github/workflows}"

if [ ! -d "${workflows}" ]; then
  echo "ERROR: workflows directory not found: ${workflows}" >&2
  exit 1
fi

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "ERROR: python3 cannot import yaml; install PyYAML" >&2
  exit 1
fi

# '-I' keeps the working directory off sys.path.
python3 -I - "${workflows}" <<'PYEOF'
import copy
import pathlib
import sys

import yaml

GRYPE = "lfreleng-actions/grype-scan-action"
UPLOAD = "actions/upload-artifact"
DOWNLOAD = "actions/download-artifact"
ARTEFACT = "sbom-files"
OUTPUT = "sbom_artifact_id"
UPLOAD_ID = "upload-sbom"
DOWNLOAD_ID = "download-sbom"
GUARD_ID = "require-sbom-artifact-id"
GUARD_VAR = "ARTIFACT_ID"
# Split so a workflow running this script leaves the expressions
# unexpanded
OPEN = "$" + "{{ "
CLOSE = " }" + "}"
OUTPUT_EXPR = OPEN + f"steps.{UPLOAD_ID}.outputs.artifact-id" + CLOSE
BINDING_EXPR = OPEN + f"needs.sbom.outputs.{OUTPUT}" + CLOSE
EXPLAIN_IF = f"steps.{DOWNLOAD_ID}.outcome == 'failure'"
# The guard's run block tests the variable the ID is bound to and
# stops the job when it is empty
GUARD_TEST = '-n "${' + GUARD_VAR + '}"'
GUARD_EXIT = "exit 1"
# Any of these on the download step names an artefact or another run
# rather than this call's upload
BY_NAME = ("name", "pattern", "run-id", "repository")

WORKFLOWS = (
    "build-test.yaml",
    "build-test-multiarch.yaml",
    "build-test-release.yaml",
    "build-test-release-multiarch.yaml",
)


def uses_name(s):
    return str((s or {}).get("uses", "")).split("@", 1)[0]


def steps_using(job, action):
    return [s for s in (job or {}).get("steps") or [] if uses_name(s) == action]


def needs_of(job):
    needs = (job or {}).get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def scans(job):
    """The Grype steps in a job that scan. The validate-only call in
    gerrit-validate checks inputs and reads no SBOM, so it binds to
    no upload."""
    return [s for s in steps_using(job, GRYPE)
            if (s.get("with") or {}).get("validate-only") != "true"]


def find_scan(doc):
    """Return (job id, job) for the one job holding a Grype scan."""
    found = [(job_id, job) for job_id, job in (doc.get("jobs") or {}).items()
             if scans(job)]
    return found[0] if len(found) == 1 else (None, None)


def check_no_download_by_name(doc, problems):
    """No job may download an SBOM artefact by name or pattern."""
    for job_id, job in (doc.get("jobs") or {}).items():
        for s in steps_using(job, DOWNLOAD):
            given = s.get("with") or {}
            selector = str(given.get("name", "")) + str(given.get("pattern", ""))
            if ARTEFACT in selector:
                problems.append(f"jobs.{job_id} step {s.get('name')!r} "
                                f"downloads {ARTEFACT} by name or pattern")


def check_upload(doc, problems):
    """Return the sbom job's upload step, or None after a problem."""
    sbom = (doc.get("jobs") or {}).get("sbom")
    if sbom is None:
        problems.append("has no sbom job")
        return None
    uploads = [s for s in steps_using(sbom, UPLOAD)
               if str((s.get("with") or {}).get("name", "")).startswith(ARTEFACT)]
    if len(uploads) != 1:
        problems.append(f"jobs.sbom has {len(uploads)} {ARTEFACT} upload "
                        "steps, expected 1")
        return None
    return uploads[0]


def check_separate(job_id, job, doc, problems):
    """The grype job downloads the sbom job's upload by its ID."""
    where = f"jobs.{job_id}"
    if "sbom" not in needs_of(job):
        problems.append(f"{where} does not need sbom")
    outputs = (doc["jobs"]["sbom"].get("outputs") or {})
    if outputs.get(OUTPUT) != OUTPUT_EXPR:
        problems.append(f"jobs.sbom output {OUTPUT} is "
                        f"{outputs.get(OUTPUT)!r}, expected {OUTPUT_EXPR!r}")
    downloads = steps_using(job, DOWNLOAD)
    if len(downloads) != 1:
        problems.append(f"{where} has {len(downloads)} {DOWNLOAD} steps, "
                        "expected 1")
        return
    download = downloads[0]
    given = download.get("with") or {}
    if given.get("artifact-ids") != BINDING_EXPR:
        problems.append(f"{where} downloads artifact-ids "
                        f"{given.get('artifact-ids')!r}, expected "
                        f"{BINDING_EXPR!r}")
    for key in BY_NAME:
        if key in given:
            problems.append(f"{where} download sets {key}, which selects "
                            "an artefact by something other than this "
                            "call's upload")
    if download.get("id") != DOWNLOAD_ID:
        problems.append(f"{where} download step id is not {DOWNLOAD_ID}")
    check_guard(where, job, download, problems)
    explain = [s for s in job.get("steps") or []
               if EXPLAIN_IF in str(s.get("if", ""))]
    if len(explain) != 1:
        problems.append(f"{where} has no step explaining a failed "
                        f"{DOWNLOAD_ID}")


def check_guard(where, job, download, problems):
    """A step before the download fails the job on an empty ID."""
    steps = job.get("steps") or []
    guards = [s for s in steps if s.get("id") == GUARD_ID]
    if len(guards) != 1:
        problems.append(f"{where} has {len(guards)} steps with id "
                        f"{GUARD_ID}, expected 1")
        return
    guard = guards[0]
    if steps.index(guard) > steps.index(download):
        problems.append(f"{where} step {GUARD_ID} runs after the download")
    if guard.get("if") is not None:
        problems.append(f"{where} step {GUARD_ID} is conditional")
    if (guard.get("env") or {}).get(GUARD_VAR) != BINDING_EXPR:
        problems.append(f"{where} step {GUARD_ID} does not bind {GUARD_VAR} "
                        f"to {BINDING_EXPR!r}")
    run = str(guard.get("run", ""))
    if GUARD_TEST not in run or GUARD_EXIT not in run:
        problems.append(f"{where} step {GUARD_ID} does not fail on an "
                        f"empty {GUARD_VAR}")


def check_doc(doc):
    """Return the list of problems in one parsed workflow."""
    problems = []
    check_no_download_by_name(doc, problems)
    upload = check_upload(doc, problems)
    job_id, job = find_scan(doc)
    if job is None:
        problems.append(f"expected exactly one job with a {GRYPE} step")
        return problems
    if job_id == "sbom":
        if steps_using(job, DOWNLOAD):
            problems.append("jobs.sbom scans in-leg yet downloads an "
                            "artefact")
        return problems
    if upload is not None:
        if upload.get("id") != UPLOAD_ID:
            problems.append(f"jobs.sbom upload step id is not {UPLOAD_ID}")
        check_separate(job_id, job, doc, problems)
    return problems


def load(root, name):
    return yaml.safe_load((root / name).read_text(encoding="utf-8"))


def download_step(doc):
    _, job = find_scan(doc)
    return steps_using(job, DOWNLOAD)[0]


def upload_step(doc):
    return [s for s in steps_using(doc["jobs"]["sbom"], UPLOAD)
            if str((s.get("with") or {}).get("name", "")).startswith(ARTEFACT)][0]


def guard_step(doc):
    _, job = find_scan(doc)
    return [s for s in job["steps"] if s.get("id") == GUARD_ID][0]


def separate_mutants(doc):
    """Yield (label, mutated doc) for a workflow with a grype job."""
    d = copy.deepcopy(doc)
    # A validator that leaves validate-only mode is a second scan,
    # in a job that neither uploads nor downloads the SBOM
    validator = steps_using(d["jobs"]["gerrit-validate"], GRYPE)[0]
    del validator["with"]["validate-only"]
    yield "validator scans", d
    d = copy.deepcopy(doc)
    given = download_step(d)["with"]
    del given["artifact-ids"]
    given["name"] = ARTEFACT + OPEN + "inputs.artifact_suffix" + CLOSE
    yield "download by name", d
    d = copy.deepcopy(doc)
    given = download_step(d)["with"]
    del given["artifact-ids"]
    given["pattern"] = ARTEFACT + "*"
    yield "download by pattern", d
    d = copy.deepcopy(doc)
    download_step(d)["with"]["name"] = "other"
    yield "name beside artifact-ids", d
    d = copy.deepcopy(doc)
    download_step(d)["with"]["run-id"] = "1"
    yield "download from another run", d
    d = copy.deepcopy(doc)
    download_step(d)["with"]["artifact-ids"] = (
        OPEN + "needs.python-build.outputs.artifact_id" + CLOSE)
    yield "bound to another job's output", d
    d = copy.deepcopy(doc)
    download_step(d)["with"]["artifact-ids"] = "12345"
    yield "bound to a literal ID", d
    d = copy.deepcopy(doc)
    del d["jobs"]["sbom"]["outputs"][OUTPUT]
    yield "sbom output dropped", d
    d = copy.deepcopy(doc)
    d["jobs"]["sbom"]["outputs"][OUTPUT] = (
        OPEN + "steps.sbom.outputs.artifact-id" + CLOSE)
    yield "sbom output bound to another step", d
    d = copy.deepcopy(doc)
    upload_step(d)["id"] = "upload"
    yield "upload step renamed", d
    d = copy.deepcopy(doc)
    download_step(d)["id"] = "download"
    yield "download step renamed", d
    d = copy.deepcopy(doc)
    job_id, job = find_scan(d)
    job["steps"] = [s for s in job["steps"]
                    if EXPLAIN_IF not in str(s.get("if", ""))]
    yield "explanation step dropped", d
    d = copy.deepcopy(doc)
    job_id, job = find_scan(d)
    job["steps"].remove(download_step(d))
    yield "download step dropped", d
    d = copy.deepcopy(doc)
    job_id, job = find_scan(d)
    job["steps"].append(copy.deepcopy(download_step(d)))
    yield "second download step", d
    d = copy.deepcopy(doc)
    job_id, job = find_scan(d)
    job["needs"] = "python-build"
    yield "grype job needs another job", d
    d = copy.deepcopy(doc)
    job_id, job = find_scan(d)
    job["steps"].remove(guard_step(d))
    yield "empty-ID guard dropped", d
    d = copy.deepcopy(doc)
    job_id, job = find_scan(d)
    guard = guard_step(d)
    job["steps"].remove(guard)
    job["steps"].insert(job["steps"].index(download_step(d)) + 1, guard)
    yield "empty-ID guard after the download", d
    d = copy.deepcopy(doc)
    guard_step(d)["if"] = "false"
    yield "empty-ID guard made conditional", d
    d = copy.deepcopy(doc)
    guard_step(d)["env"][GUARD_VAR] = (
        OPEN + "needs.python-build.outputs.artifact_id" + CLOSE)
    yield "empty-ID guard bound to another job's output", d
    d = copy.deepcopy(doc)
    guard_step(d)["run"] = guard_step(d)["run"].replace(GUARD_EXIT, "exit 0")
    yield "empty-ID guard that does not fail", d
    d = copy.deepcopy(doc)
    guard_step(d)["run"] = guard_step(d)["run"].replace(
        GUARD_TEST, '-n "${ARTIFACT_NAME}"')
    yield "empty-ID guard testing another variable", d


def in_leg_mutants(doc):
    """Yield (label, mutated doc) for a workflow scanning in-leg."""
    d = copy.deepcopy(doc)
    d["jobs"]["sbom"]["steps"].append(
        {"name": "Download SBOM", "uses": DOWNLOAD + "@" + "0" * 40,
         "with": {"name": ARTEFACT + "-x64"}})
    yield "in-leg download by name", d
    d = copy.deepcopy(doc)
    d["jobs"]["sbom"]["steps"].append(
        {"name": "Download SBOM", "uses": DOWNLOAD + "@" + "0" * 40,
         "with": {"artifact-ids": "12345"}})
    yield "in-leg download by ID", d
    d = copy.deepcopy(doc)
    sbom = d["jobs"]["sbom"]
    scan = steps_using(sbom, GRYPE)[0]
    sbom["steps"].remove(scan)
    d["jobs"]["grype"] = {
        "needs": "sbom", "runs-on": "ubuntu-latest",
        "steps": [{"uses": DOWNLOAD + "@" + "0" * 40,
                   "with": {"pattern": ARTEFACT + "-*"}}, scan]}
    yield "scan moved to a job downloading by pattern", d


root = pathlib.Path(sys.argv[1])
failures = 0
docs = {}
for name in WORKFLOWS:
    if not (root / name).is_file():
        print(f"::error::{root / name} is missing")
        failures += 1
        continue
    docs[name] = load(root, name)
    problems = check_doc(docs[name])
    for problem in problems:
        print(f"::error file=.github/workflows/{name}::{problem}")
    failures += len(problems)

for name, mutate in (("build-test.yaml", separate_mutants),
                     ("build-test-multiarch.yaml", in_leg_mutants)):
    if name not in docs or check_doc(docs[name]):
        continue
    caught = total = 0
    for label, mutant in mutate(docs[name]):
        total += 1
        if check_doc(mutant):
            caught += 1
        else:
            print(f"::error::mutant of {name} not caught: {label}")
    print(f"Mutants of {name} caught: {caught}/{total}")
    failures += total - caught

if failures:
    print(f"{failures} problem(s) in the SBOM to Grype binding ❌")
    sys.exit(1)
print(f"{len(docs)} workflow(s) bind the Grype scan to the SBOM upload ✅")
PYEOF
