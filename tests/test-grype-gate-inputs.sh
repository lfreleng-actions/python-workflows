#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Wiring check for the Grype gate policy and the dependency-change
# verdict behind it.
#
# The verify workflows (build-test.yaml, build-test-multiarch.yaml)
# detect dependency changes in the repository-metadata job, through
# lfreleng-actions/repository-metadata-action, export the verdict as
# a job output and hand it to the grype-scan-action call, guarded so
# that a failed or skipped metadata job leaves it empty, which gates.
# They expose grype_gate_when and the detection inputs. The release
# workflows take the same policy inputs, pin the same metadata
# action, pass gate-when 'always' and never detect. Every workflow
# validates the policy inputs in gerrit-validate with one shared step,
# so a typo fails in seconds rather than after the build.
#
# repository-metadata-action's own suite proves what it detects; this
# script proves the wiring around it: the pin and the detection
# inputs, the checkout depth detection needs, the job output and its
# guarded hand-off, that the retired sbom-job detection and its
# sidecar are gone, that every policy input exists with the agreed
# default and reaches the scan, and that the shared validation steps
# reject every value they must. It then mutates a copy of each verify
# workflow in each way the check must catch and expects each mutant to
# fail, so a check that silently passes everything fails here too.
#
# Usage: bash tests/test-grype-gate-inputs.sh [<workflows-dir>]
#
# Needs python3 with PyYAML, and GNU date for the validation step.

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

scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

# Static checks over the four workflows. Writes the shared validation
# step bodies to the scratch directory for the second half.
# '-I' keeps the working directory off sys.path.
python3 -I - "${workflows}" "${scratch}" <<'PYEOF'
import copy
import pathlib
import sys

import yaml

METADATA = "lfreleng-actions/repository-metadata-action"
METADATA_PIN = "18e5b7c5b16423b0e734891d103513826b324858"  # v0.4.0
GRYPE = "lfreleng-actions/grype-scan-action"
GRYPE_PIN = "5c81b23afb2ea771b2d247807a12d90783328675"  # v0.5.0
# The detection wiring this replaced: none of it may come back
RETIRED = (
    "lfreleng-actions/dependency-change-action",
    "dependency-change.json",
    "dependency-change-manifest",
)
# Split so a workflow running this script leaves the expressions
# unexpanded
OPEN = "$" + "{{ "
CLOSE = " }" + "}"

VERIFY = ("build-test.yaml", "build-test-multiarch.yaml")
RELEASE = ("build-test-release.yaml", "build-test-release-multiarch.yaml")

# name -> (type, default, grype-scan-action input)
POLICY = {
    "grype_dependency_policy": ("string", "declared", "dependency-policy"),
    "grype_transitive_fail_on": ("string", "critical", "transitive-fail-on"),
    "grype_only_fixed": ("boolean", True, "only-fixed"),
    "grype_remediation_window_days": ("string", "", "remediation-window-days"),
    "grype_remediation_window_start": (
        "string", "", "remediation-window-start"),
}
GATE_WHEN = ("grype_gate_when", "string", "always", "gate-when")
# Verify-only inputs: name -> (type, default, repository-metadata input)
DETECTION = {
    "grype_dependency_ecosystems": ("string", "", "dependency_ecosystems"),
    "grype_dependency_patterns": ("string", "", "dependency_patterns"),
}
DETECT_IF = ("inputs.grype_enabled",
             "inputs.grype_gate_when == 'dependencies-changed'")
METADATA_JOB = "repository-metadata"
METADATA_STEP = "repo-metadata"
METADATA_WITH = {
    "dependency_change": OPEN + " && ".join(DETECT_IF) + CLOSE,
    "gerrit_refspec": OPEN + "inputs.gerrit_refspec" + CLOSE,
    "dependency_ecosystems": OPEN + "inputs.grype_dependency_ecosystems" + CLOSE,
    "dependency_patterns": OPEN + "inputs.grype_dependency_patterns" + CLOSE,
    "dependency_path_prefix": OPEN + "inputs.path_prefix" + CLOSE,
}
VERDICT = "dependencies_changed"
VERDICT_OUTPUT = OPEN + f"steps.{METADATA_STEP}.outputs.{VERDICT}" + CLOSE
# A failed metadata job can still expose an output an earlier step
# wrote, so the consumer forwards it only when the job succeeded
VERDICT_INPUT = (OPEN + f"needs.{METADATA_JOB}.result == 'success' && "
                 f"needs.{METADATA_JOB}.outputs.{VERDICT} || ''" + CLOSE)
GATE_STEP = "Grype gate active: " + OPEN + "steps.grype-audit.outputs.gate-active" + CLOSE
# Both metadata checkouts must hold HEAD's parent: actions/checkout
# defaults to 1, checkout-gerrit-change-action to 2
CHECKOUTS = {
    "actions/checkout": 1,
    "lfreleng-actions/checkout-gerrit-change-action": 2,
}


def expr(name):
    return OPEN + f"inputs.{name}" + CLOSE


def step(steps, key, value):
    found = [s for s in steps if (s or {}).get(key) == value]
    return found[0] if len(found) == 1 else None


def uses_name(s):
    return str((s or {}).get("uses", "")).split("@", 1)[0]


def needs_of(job):
    needs = (job or {}).get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def find_scan(doc):
    """Return (job id, step) for the one grype-scan-action step."""
    found = []
    for job_id, job in (doc.get("jobs") or {}).items():
        for s in (job or {}).get("steps") or []:
            if uses_name(s) == GRYPE:
                found.append((job_id, s))
    return found[0] if len(found) == 1 else (None, None)


def check_typed(inputs, name, kind, default, problems):
    spec = inputs.get(name)
    if not isinstance(spec, dict):
        problems.append(f"input {name} is missing")
        return
    value = spec.get("default")
    if (spec.get("type") != kind or value != default
            or type(value) is not type(default)):
        problems.append(f"input {name} is not a {kind} defaulting to "
                        f"{default!r}")


def check_inputs(name, doc, problems):
    inputs = doc[True]["workflow_call"]["inputs"]
    verify_only = {GATE_WHEN[0]: GATE_WHEN[1:3]}
    verify_only.update({k: v[:2] for k, v in DETECTION.items()})
    for input_name, (kind, default) in verify_only.items():
        if name in VERIFY:
            check_typed(inputs, input_name, kind, default, problems)
        elif input_name in inputs:
            problems.append(f"input {input_name} exists; a release always "
                            "gates")
    for input_name, (kind, default, _) in POLICY.items():
        check_typed(inputs, input_name, kind, default, problems)


def check_scan(name, doc, problems):
    job_id, scan = find_scan(doc)
    if scan is None:
        problems.append(f"expected exactly one {GRYPE} step")
        return
    where = f"jobs.{job_id}"
    if str(scan.get("uses", "")).partition("@")[2] != GRYPE_PIN:
        problems.append(f"{where} does not pin {GRYPE}@{GRYPE_PIN}")
    if scan.get("id") != "grype-audit":
        problems.append(f"{where} {GRYPE} step id is not grype-audit")
    given = scan.get("with") or {}
    if given.get("sbom") != "sbom-cyclonedx.json":
        problems.append(f"{where} grype-audit does not scan "
                        "sbom-cyclonedx.json")
    for input_name, (_, _, passed) in POLICY.items():
        if given.get(passed) != expr(input_name):
            problems.append(f"{where} grype-audit passes {passed} as "
                            f"{given.get(passed)!r}")
    if name in VERIFY:
        if given.get(GATE_WHEN[3]) != expr(GATE_WHEN[0]):
            problems.append(f"{where} grype-audit passes {GATE_WHEN[3]} as "
                            f"{given.get(GATE_WHEN[3])!r}")
        if given.get("dependencies-changed") != VERDICT_INPUT:
            problems.append(f"{where} grype-audit passes "
                            "dependencies-changed as "
                            f"{given.get('dependencies-changed')!r}, "
                            f"expected {VERDICT_INPUT!r}")
        # testing.yaml reads the verdict from this step's name
        steps = doc["jobs"][job_id]["steps"]
        gate = step(steps, "name", GATE_STEP)
        if gate is None:
            problems.append(f"{where} has no {GATE_STEP!r} step")
        elif DETECT_IF[1] not in str(gate.get("if", "")):
            problems.append(f"{where} gate step does not run only for the "
                            "dependencies-changed gate")
    else:
        if given.get(GATE_WHEN[3]) != "always":
            problems.append(f"{where} grype-audit passes {GATE_WHEN[3]} as "
                            f"{given.get(GATE_WHEN[3])!r}, expected 'always'")
        if "dependencies-changed" in given:
            problems.append(f"{where} grype-audit reads a verdict; a "
                            "release always gates")


def check_consumer(doc, problems):
    """The job holding the scan reads the metadata job's verdict."""
    job_id, _ = find_scan(doc)
    if job_id is None:
        return
    where = f"jobs.{job_id}"
    job = doc["jobs"][job_id]
    if METADATA_JOB not in needs_of(job):
        problems.append(f"{where} does not need {METADATA_JOB}")
    cond = str(job.get("if", ""))
    # Without !cancelled() a failed or skipped metadata job would skip
    # the scan; requiring its success would do the same
    if "!cancelled()" not in cond:
        problems.append(f"{where} if: lacks !cancelled(), so a failed or "
                        f"skipped {METADATA_JOB} job skips the scan")
    if f"needs.{METADATA_JOB}" in cond:
        problems.append(f"{where} if: depends on {METADATA_JOB}, so its "
                        "failure skips the scan")


def check_metadata(name, doc, problems):
    """Every workflow pins the metadata action; verify lanes detect."""
    job = (doc.get("jobs") or {}).get(METADATA_JOB)
    if job is None:
        problems.append(f"has no {METADATA_JOB} job")
        return
    steps = job.get("steps") or []
    meta = step(steps, "id", METADATA_STEP)
    if meta is None or uses_name(meta) != METADATA:
        problems.append(f"jobs.{METADATA_JOB} has no {METADATA_STEP} step "
                        f"using {METADATA}")
        return
    if str(meta.get("uses", "")).partition("@")[2] != METADATA_PIN:
        problems.append(f"jobs.{METADATA_JOB} does not pin "
                        f"{METADATA}@{METADATA_PIN}")
    given = meta.get("with") or {}
    output = (job.get("outputs") or {}).get(VERDICT)
    if name in RELEASE:
        if any(key in given for key in METADATA_WITH):
            problems.append(f"jobs.{METADATA_JOB} detects dependency "
                            "changes; a release always gates")
        return
    for key, value in METADATA_WITH.items():
        if given.get(key) != value:
            problems.append(f"{METADATA_STEP} input {key} is "
                            f"{given.get(key)!r}, expected {value!r}")
    if output != VERDICT_OUTPUT:
        problems.append(f"jobs.{METADATA_JOB} output {VERDICT} is "
                        f"{output!r}, expected {VERDICT_OUTPUT!r}")
    for action, default in CHECKOUTS.items():
        found = [s for s in steps if uses_name(s) == action]
        if len(found) != 1:
            problems.append(f"jobs.{METADATA_JOB} has {len(found)} {action} "
                            "steps, expected 1")
            continue
        depth = (found[0].get("with") or {}).get("fetch-depth", default)
        # 0 fetches all history, which also holds the parent
        if not isinstance(depth, int) or 0 < depth < 2:
            problems.append(f"jobs.{METADATA_JOB} {action} fetch-depth is "
                            f"{depth!r}; the dependency change base needs "
                            "2 or more")
    # Detection left the sbom job, and so did the depth it needed there
    sbom = (doc.get("jobs") or {}).get("sbom") or {}
    for s in sbom.get("steps") or []:
        if uses_name(s) == "actions/checkout" and "fetch-depth" in (
                s.get("with") or {}):
            problems.append("jobs.sbom checkout sets a fetch-depth only "
                            "detection needed")


def check_retired(doc, problems):
    # Comments drop out in the round trip, so only live wiring counts
    text = yaml.safe_dump(doc)
    for term in RETIRED:
        if term in text:
            problems.append(f"still names {term}; detection runs in "
                            f"{METADATA_JOB}")


def check_validation(name, doc, reference, problems):
    """Return the shared validation steps, keyed as in reference."""
    steps = doc["jobs"]["gerrit-validate"]["steps"]
    found = {}
    for key, step_id, verify_only in VALIDATION:
        s = step(steps, "id", step_id)
        found[key] = s
        if verify_only and name not in VERIFY:
            if s is not None:
                problems.append(f"gerrit-validate has {step_id}, which "
                                "validates an input a release does not "
                                "take")
            continue
        if s is None:
            problems.append(f"gerrit-validate has no {step_id} step")
        elif reference is not None and s != reference[key]:
            problems.append(f"{step_id} diverged from build-test.yaml")
    return found


# key, step id, verify only
VALIDATION = (
    ("policy", "validate-grype-policy", False),
    ("gate", "validate-grype-gate-when", True),
    ("ecosystems", "validate-grype-dependency-ecosystems", True),
)


def check_doc(name, doc, reference=None):
    """Return the list of problems in one parsed workflow."""
    problems = []
    check_inputs(name, doc, problems)
    check_scan(name, doc, problems)
    check_metadata(name, doc, problems)
    check_retired(doc, problems)
    if name in VERIFY:
        check_consumer(doc, problems)
    check_validation(name, doc, reference, problems)
    return problems


def load(root, name):
    return yaml.safe_load((root / name).read_text(encoding="utf-8"))


def mutants(doc):
    """Yield (label, mutated doc) for each drift the check must catch."""

    def inputs(d):
        return d[True]["workflow_call"]["inputs"]

    def meta_job(d):
        return d["jobs"][METADATA_JOB]

    def meta(d):
        return step(meta_job(d)["steps"], "id", METADATA_STEP)

    def scan(d):
        return find_scan(d)[1]

    def consumer(d):
        return d["jobs"][find_scan(d)[0]]

    def sbom_step(d, key, value):
        return step(d["jobs"]["sbom"]["steps"], key, value)

    for input_name in list(POLICY) + [GATE_WHEN[0]] + list(DETECTION):
        d = copy.deepcopy(doc)
        del inputs(d)[input_name]
        yield f"drop input {input_name}", d
    d = copy.deepcopy(doc)
    inputs(d)["grype_only_fixed"]["default"] = "true"
    yield "only_fixed default typed string", d
    d = copy.deepcopy(doc)
    inputs(d)[GATE_WHEN[0]]["default"] = "dependencies-changed"
    yield "gate_when default flipped", d
    d = copy.deepcopy(doc)
    inputs(d)["grype_remediation_window_days"]["default"] = "30"
    yield "remediation window on by default", d
    d = copy.deepcopy(doc)
    inputs(d)["grype_dependency_ecosystems"]["default"] = "python"
    yield "ecosystems narrowed by default", d
    for _, (_, _, passed) in POLICY.items():
        d = copy.deepcopy(doc)
        del scan(d)["with"][passed]
        yield f"drop pass-through {passed}", d
    for key in (GATE_WHEN[3], "dependencies-changed"):
        d = copy.deepcopy(doc)
        del scan(d)["with"][key]
        yield f"drop pass-through {key}", d
    d = copy.deepcopy(doc)
    scan(d)["with"]["dependencies-changed"] = (
        OPEN + f"needs.{METADATA_JOB}.outputs.{VERDICT}" + CLOSE)
    yield "verdict forwarded from a failed metadata job", d
    d = copy.deepcopy(doc)
    scan(d)["with"]["dependency-change-manifest"] = "dependency-change.json"
    yield "sidecar manifest read again", d
    d = copy.deepcopy(doc)
    scan(d)["uses"] = f"{GRYPE}@{'0' * 40}"
    yield "grype-scan-action pinned elsewhere", d
    d = copy.deepcopy(doc)
    meta(d)["uses"] = f"{METADATA}@2206d754f65f1a90f57b49be546712c5f594def2"
    yield "repository-metadata-action on v0.3.3", d
    for key in METADATA_WITH:
        d = copy.deepcopy(doc)
        del meta(d)["with"][key]
        yield f"drop metadata input {key}", d
    d = copy.deepcopy(doc)
    meta(d)["with"]["dependency_change"] = "true"
    yield "detection runs on every gate", d
    d = copy.deepcopy(doc)
    meta(d)["with"]["dependency_ecosystems"] = "python"
    yield "ecosystems fixed to one preset", d
    d = copy.deepcopy(doc)
    del meta_job(d)["outputs"][VERDICT]
    yield "drop the verdict job output", d
    d = copy.deepcopy(doc)
    meta_job(d)["outputs"][VERDICT] = (
        OPEN + f"steps.{METADATA_STEP}.outputs.dependency_change_reason"
        + CLOSE)
    yield "verdict output bound elsewhere", d
    d = copy.deepcopy(doc)
    step(meta_job(d)["steps"], "name",
         "Checkout repository")["with"]["fetch-depth"] = 1
    yield "metadata checkout depth 1", d
    d = copy.deepcopy(doc)
    step(meta_job(d)["steps"], "name",
         "Checkout Gerrit change")["with"]["fetch-depth"] = 1
    yield "metadata Gerrit checkout depth 1", d
    d = copy.deepcopy(doc)
    job = consumer(d)
    job["needs"] = [n for n in needs_of(job) if n != METADATA_JOB]
    yield "consumer does not need repository-metadata", d
    d = copy.deepcopy(doc)
    job = consumer(d)
    job["if"] = str(job["if"]).replace("!cancelled() && ", "")
    yield "consumer drops !cancelled()", d
    d = copy.deepcopy(doc)
    job = consumer(d)
    job["if"] = str(job["if"]).replace(
        "!cancelled()",
        f"!cancelled() && needs.{METADATA_JOB}.result == 'success'")
    yield "consumer requires a successful metadata job", d
    d = copy.deepcopy(doc)
    sbom_step(d, "name", "Checkout repository")["with"]["fetch-depth"] = 2
    yield "sbom checkout depth 2 again", d
    d = copy.deepcopy(doc)
    d["jobs"]["sbom"]["steps"].insert(0, {
        "name": "Detect dependency changes", "id": "dependency-change",
        "uses": f"{RETIRED[0]}@{'0' * 40}"})
    yield "dependency-change-action called again", d
    d = copy.deepcopy(doc)
    sbom_step(d, "id", "upload-sbom")["with"]["path"] = (
        "sbom-cyclonedx.*\ndependency-change.json\n")
    yield "sidecar uploaded again", d
    d = copy.deepcopy(doc)
    job_id, _ = find_scan(d)
    gate = step(d["jobs"][job_id]["steps"], "name", GATE_STEP)
    gate["name"] = "Grype gate summary"
    yield "gate step renamed", d
    d = copy.deepcopy(doc)
    job_id, _ = find_scan(d)
    gate = step(d["jobs"][job_id]["steps"], "name", GATE_STEP)
    gate["if"] = "always()"
    yield "gate step on every gate", d
    for _, step_id, _ in VALIDATION:
        d = copy.deepcopy(doc)
        steps = d["jobs"]["gerrit-validate"]["steps"]
        steps.remove(step(steps, "id", step_id))
        yield f"drop {step_id}", d
        d = copy.deepcopy(doc)
        steps = d["jobs"]["gerrit-validate"]["steps"]
        step(steps, "id", step_id)["run"] = "exit 0"
        yield f"{step_id} diverged", d


root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
failures = 0
reference = None
for name in VERIFY + RELEASE:
    if not (root / name).is_file():
        print(f"::error::{root / name} is missing")
        failures += 1
        continue
    doc = load(root, name)
    problems = check_doc(name, doc, reference)
    if name == VERIFY[0]:
        found = check_validation(name, doc, None, [])
        if None in found.values():
            failures += 1
            print(f"::error file={root / name}::cannot extract the "
                  "validation steps")
        else:
            reference = found
            for key, step_id, _ in VALIDATION:
                (out / f"{step_id}.sh").write_text(reference[key]["run"])
    for problem in problems:
        failures += 1
        print(f"::error file={root / name}::{problem}")
if failures:
    print(f"{failures} problem(s) across {len(VERIFY + RELEASE)} "
          "workflow(s) ❌")
    sys.exit(1)
print(f"{len(VERIFY + RELEASE)} workflow(s) wire the Grype gate ✅")

# Self-test: every mutant of each verify workflow must fail. The
# single-arch one scans in a grype job, the multi-arch one in its sbom
# legs, so each consumer shape is mutated. A mutant is checked against
# the pristine reference, so a change to a validation step counts as
# divergence.
escaped = 0
for name in VERIFY:
    doc = load(root, name)
    caught = total = 0
    for label, mutant in mutants(doc):
        total += 1
        # Round-trip through YAML as the real check does
        mutant = yaml.safe_load(yaml.safe_dump(mutant))
        if check_doc(name, mutant, reference):
            caught += 1
        else:
            print(f"::error::mutant of {name} not caught: {label}")
    print(f"Mutants of {name} caught: {caught}/{total}")
    escaped += total - caught
if escaped:
    sys.exit(1)
PYEOF

# Drive the extracted validation steps against the values each must
# accept and reject. Fail loudly rather than silently testing nothing
# if a step loses an input.
policy="${scratch}/validate-grype-policy.sh"
gate="${scratch}/validate-grype-gate-when.sh"
for var in GRYPE_DEPENDENCY_POLICY GRYPE_TRANSITIVE_FAIL_ON \
  GRYPE_ONLY_FIXED GRYPE_REMEDIATION_WINDOW_DAYS \
  GRYPE_REMEDIATION_WINDOW_START; do
  if ! grep -q "${var}" "${policy}"; then
    echo "::error::validate-grype-policy does not read ${var}"
    exit 1
  fi
done
if ! grep -q GRYPE_GATE_WHEN "${gate}"; then
  echo "::error::validate-grype-gate-when does not read GRYPE_GATE_WHEN"
  exit 1
fi
ecosystems="${scratch}/validate-grype-dependency-ecosystems.sh"
if ! grep -q GRYPE_DEPENDENCY_ECOSYSTEMS "${ecosystems}"; then
  echo "::error::validate-grype-dependency-ecosystems does not read" \
    "GRYPE_DEPENDENCY_ECOSYSTEMS"
  exit 1
fi

errors=0
# $1 script, $2 input the error must name, $3 accept|reject, then the
# environment for the run
drive() {
  local script="$1" name="$2" verdict="$3" out rc
  shift 3
  set +e
  out="$(env -i PATH="${PATH}" "$@" bash -eo pipefail "${script}" 2>&1)"
  rc=$?
  set -e
  if [ "${verdict}" = 'accept' ] && [ "${rc}" != '0' ]; then
    echo "${name}: rejected, expected accepted ❌"
    printf '%s\n' "${out}"
    errors=1
  elif [ "${verdict}" = 'reject' ] && { [ "${rc}" = '0' ] \
    || ! printf '%s' "${out}" | grep -q "^::error::Invalid ${name} input"; }
  then
    echo "${name}: accepted, or rejected without naming it ❌"
    printf '%s\n' "${out}"
    errors=1
  fi
  # A rejected value reaches the log; a newline in it must not start
  # a second workflow command
  if printf '%s\n' "${out}" | grep -q '^::warning::forged'; then
    echo "${name}: a newline in a rejected value forged a command ❌"
    errors=1
  fi
}

# $1 accept|reject, $2 input the error must name, then any overrides
# of the defaults
policy_case() {
  local verdict="$1" name="$2"
  shift 2
  drive "${policy}" "${name}" "${verdict}" \
    GRYPE_DEPENDENCY_POLICY=declared GRYPE_TRANSITIVE_FAIL_ON=critical \
    GRYPE_ONLY_FIXED=true GRYPE_REMEDIATION_WINDOW_DAYS= \
    GRYPE_REMEDIATION_WINDOW_START= "$@"
}

policy_case accept defaults
for value in all declared; do
  policy_case accept "policy ${value}" GRYPE_DEPENDENCY_POLICY="${value}"
done
for value in none negligible low medium high critical; do
  policy_case accept "transitive ${value}" GRYPE_TRANSITIVE_FAIL_ON="${value}"
done
policy_case accept 'only-fixed false' GRYPE_ONLY_FIXED=false
for value in 0 1 30 365; do
  policy_case accept "window ${value} days" \
    GRYPE_REMEDIATION_WINDOW_DAYS="${value}"
done
for value in 2026-01-01 2024-02-29 2026-12-31; do
  policy_case accept "window start ${value}" \
    GRYPE_REMEDIATION_WINDOW_START="${value}"
done
policy_case accept 'window with start' GRYPE_REMEDIATION_WINDOW_DAYS=30 \
  GRYPE_REMEDIATION_WINDOW_START=2026-01-01
# Bad values per input, each named in the error
for value in declare 'all declared' '' Declared; do
  policy_case reject grype_dependency_policy \
    GRYPE_DEPENDENCY_POLICY="${value}"
done
for value in Critical '' 'low medium' moderate; do
  policy_case reject grype_transitive_fail_on \
    GRYPE_TRANSITIVE_FAIL_ON="${value}"
done
for value in yes '' 1 True; do
  policy_case reject grype_only_fixed GRYPE_ONLY_FIXED="${value}"
done
for value in -1 1.5 30d ' 30' 'thirty' '1 2'; do
  policy_case reject grype_remediation_window_days \
    GRYPE_REMEDIATION_WINDOW_DAYS="${value}"
done
for value in 2026-1-1 01-01-2026 20260101 2026-13-01 2026-02-30 \
  2025-02-29 2026-01-01T00:00:00Z today ' 2026-01-01'; do
  policy_case reject grype_remediation_window_start \
    GRYPE_REMEDIATION_WINDOW_START="${value}"
done
policy_case reject grype_dependency_policy \
  GRYPE_DEPENDENCY_POLICY="$(printf 'x\n::warning::forged')"
policy_case reject grype_remediation_window_start \
  GRYPE_REMEDIATION_WINDOW_START="$(printf 'x\n::warning::forged')"

for value in always dependencies-changed; do
  drive "${gate}" "gate-when ${value}" accept GRYPE_GATE_WHEN="${value}"
done
for value in '' Always never dependencies_changed 'always x'; do
  drive "${gate}" grype_gate_when reject GRYPE_GATE_WHEN="${value}"
done
drive "${gate}" grype_gate_when reject \
  GRYPE_GATE_WHEN="$(printf 'x\n::warning::forged')"

# Empty watches every preset; otherwise each name, trimmed, is one of
# the seven presets of the pinned dependency-change-action
for value in '' node python go maven gradle rust docker 'node,python' \
  ' python , go ' 'node,python,go,maven,gradle,rust,docker'; do
  drive "${ecosystems}" "ecosystems '${value}'" accept \
    GRYPE_DEPENDENCY_ECOSYSTEMS="${value}"
done
for value in Python pip npm 'python,' ',python' 'python,,go' ' ' \
  'python go' 'python;go' all; do
  drive "${ecosystems}" grype_dependency_ecosystems reject \
    GRYPE_DEPENDENCY_ECOSYSTEMS="${value}"
done
drive "${ecosystems}" grype_dependency_ecosystems reject \
  GRYPE_DEPENDENCY_ECOSYSTEMS="$(printf 'python\n::warning::forged')"
drive "${ecosystems}" grype_dependency_ecosystems reject \
  GRYPE_DEPENDENCY_ECOSYSTEMS="$(printf 'python\ngo')"

if [ "${errors}" != '0' ]; then
  echo "Grype policy validation incorrect ❌"
  exit 1
fi
echo "Grype policy validation accepts and rejects as documented ✅"
