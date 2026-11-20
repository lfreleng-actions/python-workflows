#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Contract check for the Python version source of all four workflows.
#
# Each workflow resolves the Python versions a project supports in one
# python-metadata job, through one pinned build-metadata-action call,
# and every job that picks an interpreter takes it from that job: the
# matrixed jobs expand its matrix, python-build-action and the SBOM
# receive its build version (or, in the multi-arch build legs, the
# matrix's). Nothing reads a matrix or a build version from
# python-build, whose embedded copy of build-metadata-action can
# disagree with the pinned one. This script holds that: one
# python-metadata job, needing the job it should; the metadata step
# with the same pin, version comment, id and with: block in all four;
# the job's build_version output; the requires-python fallback warning,
# and in the standard workflows the matrix check; and every consumer
# wired to the job. It then mutates a copy of each workflow in each way
# the check must catch and expects each mutant to fail, so a check that
# silently passes everything fails here too.
#
# Usage: bash tests/test-python-metadata.sh [<workflows-dir>]
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
import re
import sys

import yaml

METADATA = "lfreleng-actions/build-metadata-action"
METADATA_PIN = "689e13653176908922b12f85cb93b061c467ba6f"
METADATA_TAG = "v0.13.2"
BUILD = "lfreleng-actions/python-build-action"
SBOM = "lfreleng-actions/sbom-action"
# Split so a workflow running this script leaves the expressions
# unexpanded
OPEN = "$" + "{{ "
CLOSE = " }" + "}"

JOB = "python-metadata"
STEP_ID = "metadata"
METADATA_WITH = {
    "path_prefix": OPEN + "inputs.path_prefix" + CLOSE,
    "output_format": "summary",
    "include_environment": True,
    "use_version_extract": True,
    "verbose": True,
}
BUILD_VERSION = OPEN + f"needs.{JOB}.outputs.build_version" + CLOSE
BUILD_VERSION_OUTPUT = (OPEN + f"steps.{STEP_ID}.outputs.python_build_version"
                        + CLOSE)
MATRIX_SOURCE = OPEN + f"steps.{STEP_ID}.outputs.python_matrix_json" + CLOSE
FALLBACK = OPEN + f"steps.{STEP_ID}.outputs.python_requires_python_fallback" + CLOSE
LEG_VERSION = OPEN + "matrix.python-version" + CLOSE
# Read from python-build, these would bypass the pinned metadata
RETIRED = re.compile(
    r"needs\s*\.\s*python-build\s*\.\s*outputs\s*\.\s*"
    r"(matrix_json|build_python_version)\b")

# name -> (the job python-metadata needs, its matrix output, the
# expression a matrixed job expands)
WORKFLOWS = {
    "build-test.yaml": (
        "gerrit-validate", "matrix_json",
        OPEN + f"fromJson(needs.{JOB}.outputs.matrix_json)" + CLOSE),
    "build-test-release.yaml": (
        "tag-validate", "matrix_json",
        OPEN + f"fromJson(needs.{JOB}.outputs.matrix_json)" + CLOSE),
    "build-test-multiarch.yaml": (
        "gerrit-validate", "versions_json",
        OPEN + f"fromJson(needs.{JOB}.outputs.versions_json)" + CLOSE),
    "build-test-release-multiarch.yaml": (
        "tag-validate", "versions_json",
        OPEN + f"fromJson(needs.{JOB}.outputs.versions_json)" + CLOSE),
}
STANDARD = ("build-test.yaml", "build-test-release.yaml")


def needs_of(job):
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def uses_name(step):
    return str((step or {}).get("uses", "")).split("@", 1)[0]


def steps_using(job, action):
    return [s for s in job.get("steps") or [] if uses_name(s) == action]


def strings(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from strings(key)
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)
    elif isinstance(node, str):
        yield node


def env_reads(step, expression):
    return expression in (step.get("env") or {}).values()


def check_text(text, problems):
    """The pin's version comment lives only in the raw text."""
    lines = [line.strip() for line in text.splitlines()
             if re.match(r"\s*(-\s+)?uses:\s*" + re.escape(METADATA) + "@",
                         line)]
    expected = f"uses: {METADATA}@{METADATA_PIN}  # {METADATA_TAG}"
    if len(lines) != 1:
        problems.append(f"{len(lines)} {METADATA} lines, expected 1")
    elif lines[0].removeprefix("- ") != expected:
        problems.append(f"{METADATA} line is {lines[0]!r}, "
                        f"expected {expected!r}")


def check_metadata_job(name, doc, problems):
    needed, matrix_output, _ = WORKFLOWS[name]
    jobs = doc.get("jobs") or {}
    callers = [j for j, job in jobs.items() if steps_using(job, METADATA)]
    if callers != [JOB]:
        problems.append(f"{METADATA} is called from {callers}, "
                        f"expected only from jobs.{JOB}")
    job = jobs.get(JOB)
    if job is None:
        problems.append(f"no jobs.{JOB}")
        return
    where = f"jobs.{JOB}"
    if needs_of(job) != [needed]:
        problems.append(f"{where} needs {needs_of(job)}, expected "
                        f"[{needed!r}]")
    steps = steps_using(job, METADATA)
    if len(steps) != 1:
        problems.append(f"{where} has {len(steps)} {METADATA} steps, "
                        "expected 1")
        return
    step = steps[0]
    if step.get("uses") != f"{METADATA}@{METADATA_PIN}":
        problems.append(f"{where} pins {step.get('uses')!r}, expected "
                        f"{METADATA}@{METADATA_PIN}")
    if step.get("id") != STEP_ID:
        problems.append(f"{where} metadata step id is {step.get('id')!r}, "
                        f"expected {STEP_ID!r}")
    if step.get("with") != METADATA_WITH:
        problems.append(f"{where} metadata step with: is "
                        f"{step.get('with')!r}, expected {METADATA_WITH!r}")
    outputs = job.get("outputs") or {}
    if outputs.get("build_version") != BUILD_VERSION_OUTPUT:
        problems.append(f"{where} output build_version is "
                        f"{outputs.get('build_version')!r}, expected "
                        f"{BUILD_VERSION_OUTPUT!r}")
    if matrix_output not in outputs:
        problems.append(f"{where} has no {matrix_output} output")
    later = job["steps"][job["steps"].index(step) + 1:]
    warns = [s for s in later if env_reads(s, FALLBACK)
             and "::warning::" in str(s.get("run", ""))]
    if len(warns) != 1:
        problems.append(f"{where} has no step warning on the "
                        "requires-python fallback")
    if name in STANDARD:
        if outputs.get(matrix_output) != MATRIX_SOURCE:
            problems.append(f"{where} output {matrix_output} is "
                            f"{outputs.get(matrix_output)!r}, expected "
                            f"{MATRIX_SOURCE!r}")
        checks = [s for s in later if env_reads(s, MATRIX_SOURCE)
                  and s.get("if") is None
                  and "::error::" in str(s.get("run", ""))
                  and "exit 1" in str(s.get("run", ""))]
        if len(checks) != 1:
            problems.append(f"{where} has no step failing on an unusable "
                            "matrix")


def matrix_source(job):
    """The expression giving the job's Python versions, or None."""
    matrix = (job.get("strategy") or {}).get("matrix")
    if isinstance(matrix, dict):
        return matrix.get("python-version")
    return matrix


def check_consumers(name, doc, problems):
    _, _, matrix_expr = WORKFLOWS[name]
    jobs = doc.get("jobs") or {}
    for text in strings(doc):
        if RETIRED.search(text):
            problems.append(f"an expression reads python-build's matrix "
                            f"or build version: {text!r}")
    for job_id, job in jobs.items():
        where = f"jobs.{job_id}"
        source = matrix_source(job)
        if source is not None and source != matrix_expr:
            problems.append(f"{where} Python matrix is {source!r}, "
                            f"expected {matrix_expr!r}")
        reads_metadata = any(f"needs.{JOB}." in text
                             for text in strings(job))
        if reads_metadata and JOB not in needs_of(job):
            problems.append(f"{where} reads {JOB} but does not need it")
        for action in (BUILD, SBOM):
            for step in steps_using(job, action):
                version = (step.get("with") or {}).get("python_version")
                allowed = {BUILD_VERSION}
                if source == matrix_expr:
                    allowed.add(LEG_VERSION)
                if version not in allowed:
                    problems.append(f"{where} passes {action} python_version "
                                    f"{version!r}, expected one of "
                                    f"{sorted(allowed)}")
    builds = [j for j, job in jobs.items() if steps_using(job, BUILD)]
    if not builds:
        problems.append(f"no job calls {BUILD}")


def check(name, text, doc):
    """Return the list of problems in one workflow."""
    problems = []
    check_text(text, problems)
    check_metadata_job(name, doc, problems)
    check_consumers(name, doc, problems)
    return problems


def metadata_step(doc):
    return steps_using(doc["jobs"][JOB], METADATA)[0]


def build_job(doc):
    return [job for job in doc["jobs"].values() if steps_using(job, BUILD)][0]


def build_step(doc):
    return steps_using(build_job(doc), BUILD)[0]


def sbom_step(doc):
    return steps_using(doc["jobs"]["sbom"], SBOM)[0]


def mutants(name, text, doc):
    """Yield (label, mutated text, mutated doc) for one workflow."""
    _, matrix_output, _ = WORKFLOWS[name]

    def doc_only(label, mutate):
        d = copy.deepcopy(doc)
        mutate(d)
        return label, text, d

    def drop_job(d):
        del d["jobs"][JOB]
    yield doc_only("python-metadata job dropped", drop_job)

    def rename_job(d):
        d["jobs"]["project-metadata"] = d["jobs"].pop(JOB)
    yield doc_only("python-metadata job renamed", rename_job)

    def wrong_needs(d):
        d["jobs"][JOB]["needs"] = "repository-metadata"
    yield doc_only("python-metadata needs another job", wrong_needs)

    yield ("version comment changed",
           text.replace(f"@{METADATA_PIN}  # {METADATA_TAG}",
                        f"@{METADATA_PIN}  # v0.11.1"), doc)

    def wrong_pin(d):
        metadata_step(d)["uses"] = f"{METADATA}@{'0' * 40}"
    yield doc_only("pin changed", wrong_pin)

    def rename_step(d):
        metadata_step(d)["id"] = "meta"
    yield doc_only("metadata step id changed", rename_step)

    def drop_input(d):
        del metadata_step(d)["with"]["use_version_extract"]
    yield doc_only("with: input dropped", drop_input)

    def change_input(d):
        metadata_step(d)["with"]["path_prefix"] = "."
    yield doc_only("with: input changed", change_input)

    def add_input(d):
        metadata_step(d)["with"]["python_version"] = "3.12"
    yield doc_only("with: input added", add_input)

    def second_call(d):
        d["jobs"]["python-build"]["steps"].insert(
            0, copy.deepcopy(metadata_step(d)))
    yield doc_only("second metadata call", second_call)

    def wrong_build_output(d):
        d["jobs"][JOB]["outputs"]["build_version"] = (
            OPEN + f"steps.{STEP_ID}.outputs.python_version" + CLOSE)
    yield doc_only("build_version output rebound", wrong_build_output)

    def drop_matrix_output(d):
        del d["jobs"][JOB]["outputs"][matrix_output]
    yield doc_only("matrix output dropped", drop_matrix_output)

    def drop_warning(d):
        steps = d["jobs"][JOB]["steps"]
        for s in steps:
            (s.get("env") or {}).pop("REQUIRES_PYTHON_FALLBACK", None)
    yield doc_only("fallback warning dropped", drop_warning)

    def build_version_dropped(d):
        del build_step(d)["with"]["python_version"]
    yield doc_only("python-build-action python_version dropped",
                   build_version_dropped)

    def build_version_literal(d):
        build_step(d)["with"]["python_version"] = "3.12"
    yield doc_only("python-build-action python_version literal",
                   build_version_literal)

    def sbom_from_build(d):
        sbom_step(d)["with"]["python_version"] = (
            OPEN + "needs.python-build.outputs.build_python_version" + CLOSE)
    yield doc_only("sbom reads python-build", sbom_from_build)

    def sbom_needs_dropped(d):
        d["jobs"]["sbom"]["needs"] = [
            n for n in needs_of(d["jobs"]["sbom"]) if n != JOB]
    yield doc_only("sbom does not need python-metadata", sbom_needs_dropped)

    def tests_from_build(d):
        d["jobs"]["python-tests"]["strategy"]["matrix"] = (
            OPEN + "fromJson(needs.python-build.outputs.matrix_json)" + CLOSE)
    yield doc_only("tests matrix reads python-build", tests_from_build)

    def audit_literal(d):
        d["jobs"]["python-audit"]["strategy"]["matrix"] = {
            "python-version": ["3.12"]}
    yield doc_only("audit matrix literal", audit_literal)

    def tests_needs_dropped(d):
        d["jobs"]["python-tests"]["needs"] = [
            n for n in needs_of(d["jobs"]["python-tests"]) if n != JOB]
    yield doc_only("tests do not need python-metadata", tests_needs_dropped)

    def stray_output(d):
        d["jobs"]["cbom"].setdefault("env", {})["PY"] = (
            OPEN + "needs.python-build.outputs.build_python_version" + CLOSE)
    yield doc_only("stray read of python-build's build version",
                   stray_output)

    if name in STANDARD:
        def drop_check(d):
            steps = d["jobs"][JOB]["steps"]
            d["jobs"][JOB]["steps"] = [
                s for s in steps if not env_reads(s, MATRIX_SOURCE)]
        yield doc_only("matrix check dropped", drop_check)

        def soften_check(d):
            for s in d["jobs"][JOB]["steps"]:
                if env_reads(s, MATRIX_SOURCE):
                    s["run"] = s["run"].replace("exit 1", "exit 0")
        yield doc_only("matrix check does not fail", soften_check)
    else:
        def build_leg_literal(d):
            build_job(d)["strategy"]["matrix"]["python-version"] = ["3.12"]
        yield doc_only("build legs use a literal matrix", build_leg_literal)


root = pathlib.Path(sys.argv[1])
failures = 0
loaded = {}
for name in WORKFLOWS:
    path = root / name
    if not path.is_file():
        print(f"::error::{path} is missing")
        failures += 1
        continue
    text = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    loaded[name] = (text, doc)
    problems = check(name, text, doc)
    for problem in problems:
        print(f"::error file=.github/workflows/{name}::{problem}")
    failures += len(problems)

for name, (text, doc) in loaded.items():
    if check(name, text, doc):
        continue
    caught = total = 0
    for label, mutant_text, mutant_doc in mutants(name, text, doc):
        total += 1
        if check(name, mutant_text, mutant_doc):
            caught += 1
        else:
            print(f"::error::mutant of {name} not caught: {label}")
    print(f"Mutants of {name} caught: {caught}/{total}")
    failures += total - caught

if failures:
    print(f"{failures} problem(s) in the Python metadata contract ❌")
    sys.exit(1)
print(f"{len(loaded)} workflow(s) take their Python versions from "
      f"{JOB} ✅")
PYEOF
