#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Wiring check for the Grype gate policy and the dependency-change
# signal behind it.
#
# The verify workflows (build-test.yaml, build-test-multiarch.yaml)
# call lfreleng-actions/dependency-change-action in the job that
# generates the SBOM, carry the dependency-change.json sidecar it
# writes to the grype-scan-action call, and expose grype_gate_when.
# The release workflows take the same policy inputs, pass
# gate-when 'always' and never call the action. Every workflow
# validates the policy inputs in gerrit-validate with one shared step,
# so a typo fails in seconds rather than after the build.
#
# The action's own suite proves what it writes; this script proves
# the wiring around it: the pinned call and its condition, the
# checkout depth it needs, the sidecar's path through the artefact,
# that every policy input exists with the agreed default and reaches
# the scan, and that the shared validation step rejects every value
# it must. It then mutates a copy of a verify workflow in each way the
# check must catch and expects each mutant to fail, so a check that
# silently passes everything fails here too.
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

ACTION = "lfreleng-actions/dependency-change-action"
PIN = "257928b15e4e6a5cc5a888435be59b058055c4e1"  # v0.0.1
GRYPE = "lfreleng-actions/grype-scan-action"
GRYPE_PIN = "5c81b23afb2ea771b2d247807a12d90783328675"  # v0.5.0
SIDECAR = "dependency-change.json"
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
DETECT_WITH = {
    "ecosystems": "python",
    "path-prefix": OPEN + "inputs.path_prefix" + CLOSE,
    "gerrit-refspec": OPEN + "inputs.gerrit_refspec" + CLOSE,
    "output": SIDECAR,
}
DETECT_IF = ("inputs.grype_enabled",
             "inputs.grype_gate_when == 'dependencies-changed'")
GATE_STEP = "Grype gate active: " + OPEN + "steps.grype-audit.outputs.gate-active" + CLOSE
# Both checkouts must hold HEAD's parent: actions/checkout defaults to
# 1, checkout-gerrit-change-action to 2
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


def find_scan(doc):
    """Return (job id, step) for the one grype-scan-action step."""
    found = []
    for job_id, job in (doc.get("jobs") or {}).items():
        for s in (job or {}).get("steps") or []:
            if uses_name(s) == GRYPE:
                found.append((job_id, s))
    return found[0] if len(found) == 1 else (None, None)


def check_inputs(name, doc, problems):
    inputs = doc[True]["workflow_call"]["inputs"]
    spec = inputs.get(GATE_WHEN[0])
    if name in VERIFY:
        if not isinstance(spec, dict):
            problems.append(f"input {GATE_WHEN[0]} is missing")
        elif (spec.get("type") != GATE_WHEN[1]
              or spec.get("default") != GATE_WHEN[2]):
            problems.append(f"input {GATE_WHEN[0]} is not a {GATE_WHEN[1]} "
                            f"defaulting to {GATE_WHEN[2]!r}")
    elif spec is not None:
        problems.append(f"input {GATE_WHEN[0]} exists; a release always "
                        "gates")
    for input_name, (kind, default, _) in POLICY.items():
        spec = inputs.get(input_name)
        if not isinstance(spec, dict):
            problems.append(f"input {input_name} is missing")
            continue
        value = spec.get("default")
        if (spec.get("type") != kind or value != default
                or type(value) is not type(default)):
            problems.append(f"input {input_name} is not a {kind} "
                            f"defaulting to {default!r}")


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
    if "dependencies-changed" in given:
        problems.append(f"{where} grype-audit sets dependencies-changed, "
                        "which overrides the sidecar")
    if name in VERIFY:
        if given.get(GATE_WHEN[3]) != expr(GATE_WHEN[0]):
            problems.append(f"{where} grype-audit passes {GATE_WHEN[3]} as "
                            f"{given.get(GATE_WHEN[3])!r}")
        if given.get("dependency-change-manifest") != SIDECAR:
            problems.append(f"{where} grype-audit reads "
                            f"{given.get('dependency-change-manifest')!r}, "
                            f"expected {SIDECAR!r}")
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
        if "dependency-change-manifest" in given:
            problems.append(f"{where} grype-audit reads a manifest nothing "
                            "writes")


def check_detection(name, doc, problems):
    text = yaml.safe_dump(doc)
    if name in RELEASE:
        if ACTION in text or SIDECAR in text:
            problems.append(f"calls {ACTION} or names {SIDECAR}; a release "
                            "always gates")
        return
    sbom = doc["jobs"].get("sbom")
    if sbom is None:
        problems.append("has no sbom job")
        return
    steps = sbom["steps"]
    names = [s.get("name") for s in steps]
    # The signal comes from the pinned action alone: no run step may
    # detect or write it, where a second implementation would drift
    for s in steps:
        run = s.get("run") or ""
        if "changed=" in run or SIDECAR in run:
            problems.append(f"jobs.sbom step {s.get('name')!r} carries "
                            "inline dependency change handling")
    detect = step(steps, "id", "dependency-change")
    if detect is None:
        problems.append("jobs.sbom has no dependency-change step")
    else:
        uses = str(detect.get("uses", ""))
        if uses != f"{ACTION}@{PIN}":
            problems.append(f"dependency-change step uses {uses!r}, "
                            f"expected {ACTION}@{PIN}")
        given = detect.get("with") or {}
        for key, value in DETECT_WITH.items():
            if given.get(key) != value:
                problems.append(f"dependency-change input {key} is "
                                f"{given.get(key)!r}, expected {value!r}")
        cond = str(detect.get("if", ""))
        if any(term not in cond for term in DETECT_IF):
            problems.append("dependency-change step does not run only "
                            "for the dependencies-changed gate")
        # After every checkout and the consumer's setup script, so the
        # tree is complete, and before the SBOM upload that carries it
        at = steps.index(detect)
        later = [n for n in names[at:]
                 if n in ("Checkout repository", "Checkout Gerrit change",
                          "Run setup script")]
        if later:
            problems.append(f"dependency-change step runs before {later}")
        sbom_step = step(steps, "id", "sbom")
        if sbom_step is None or steps.index(sbom_step) < at:
            problems.append("dependency-change step does not run before "
                            "the SBOM generation")
    for action, default in CHECKOUTS.items():
        found = [s for s in steps if uses_name(s) == action]
        if len(found) != 1:
            problems.append(f"jobs.sbom has {len(found)} {action} steps, "
                            "expected 1")
            continue
        depth = (found[0].get("with") or {}).get("fetch-depth", default)
        # 0 fetches all history, which also holds the parent
        if not isinstance(depth, int) or 0 < depth < 2:
            problems.append(f"jobs.sbom {action} fetch-depth is {depth!r}; "
                            "the dependency change base needs 2 or more")
    upload = step(steps, "id", "upload-sbom")
    if upload is None:
        problems.append("jobs.sbom has no upload-sbom step")
    else:
        given = upload.get("with") or {}
        paths = str(given.get("path", "")).split()
        if paths[:1] != ["sbom-cyclonedx.*"] or SIDECAR not in paths:
            problems.append(f"upload-sbom uploads {paths!r}, expected "
                            f"['sbom-cyclonedx.*', {SIDECAR!r}]")
        if given.get("if-no-files-found") == "error":
            problems.append("upload-sbom would fail on a missing sidecar")
        if detect is not None and steps.index(upload) < steps.index(detect):
            problems.append("dependency-change step runs after upload-sbom")


def check_validation(name, doc, reference, problems):
    steps = doc["jobs"]["gerrit-validate"]["steps"]
    policy = step(steps, "id", "validate-grype-policy")
    if policy is None:
        problems.append("gerrit-validate has no validate-grype-policy step")
    elif reference is not None and policy != reference["policy"]:
        problems.append("validate-grype-policy diverged from build-test.yaml")
    gate = step(steps, "id", "validate-grype-gate-when")
    if name in VERIFY:
        if gate is None:
            problems.append("gerrit-validate has no validate-grype-gate-when "
                            "step")
        elif reference is not None and gate != reference["gate"]:
            problems.append("validate-grype-gate-when diverged from "
                            "build-test.yaml")
    elif gate is not None:
        problems.append("gerrit-validate validates grype_gate_when, which "
                        "a release does not take")
    return policy, gate


def check_doc(name, doc, reference=None):
    """Return the list of problems in one parsed workflow."""
    problems = []
    check_inputs(name, doc, problems)
    check_scan(name, doc, problems)
    check_detection(name, doc, problems)
    check_validation(name, doc, reference, problems)
    return problems


def load(root, name):
    return yaml.safe_load((root / name).read_text(encoding="utf-8"))


def mutants(doc):
    """Yield (label, mutated doc) for each drift the check must catch."""

    def inputs(d):
        return d[True]["workflow_call"]["inputs"]

    def sbom_step(d, key, value):
        return step(d["jobs"]["sbom"]["steps"], key, value)

    def scan(d):
        return find_scan(d)[1]

    for input_name in list(POLICY) + [GATE_WHEN[0]]:
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
    for _, (_, _, passed) in POLICY.items():
        d = copy.deepcopy(doc)
        del scan(d)["with"][passed]
        yield f"drop pass-through {passed}", d
    for key in (GATE_WHEN[3], "dependency-change-manifest"):
        d = copy.deepcopy(doc)
        del scan(d)["with"][key]
        yield f"drop pass-through {key}", d
    d = copy.deepcopy(doc)
    scan(d)["with"]["dependencies-changed"] = "false"
    yield "dependencies-changed overrides the sidecar", d
    d = copy.deepcopy(doc)
    scan(d)["uses"] = f"{GRYPE}@{'0' * 40}"
    yield "grype-scan-action pinned elsewhere", d
    d = copy.deepcopy(doc)
    sbom_step(d, "id", "dependency-change")["uses"] = f"{ACTION}@{'0' * 40}"
    yield "dependency-change-action pinned elsewhere", d
    d = copy.deepcopy(doc)
    sbom_step(d, "id", "dependency-change")["if"] = "inputs.grype_enabled"
    yield "detection runs on every gate", d
    d = copy.deepcopy(doc)
    sbom_step(d, "id", "dependency-change")["with"]["ecosystems"] = "node"
    yield "wrong ecosystem preset", d
    d = copy.deepcopy(doc)
    steps = d["jobs"]["sbom"]["steps"]
    steps.remove(sbom_step(d, "id", "dependency-change"))
    yield "drop the detection step", d
    d = copy.deepcopy(doc)
    steps = d["jobs"]["sbom"]["steps"]
    detect = sbom_step(d, "id", "dependency-change")
    steps.remove(detect)
    steps.append(detect)
    yield "detection after the upload", d
    d = copy.deepcopy(doc)
    steps = d["jobs"]["sbom"]["steps"]
    detect = sbom_step(d, "id", "dependency-change")
    steps.remove(detect)
    steps.insert(steps.index(step(steps, "name", "Checkout repository")),
                 detect)
    yield "detection before the checkout", d
    d = copy.deepcopy(doc)
    sbom_step(d, "name", "Checkout repository")["with"]["fetch-depth"] = 1
    yield "actions/checkout depth 1", d
    d = copy.deepcopy(doc)
    del sbom_step(d, "name", "Checkout repository")["with"]["fetch-depth"]
    yield "actions/checkout depth unset", d
    d = copy.deepcopy(doc)
    sbom_step(d, "name", "Checkout Gerrit change")["with"]["fetch-depth"] = 1
    yield "Gerrit checkout depth 1", d
    d = copy.deepcopy(doc)
    sbom_step(d, "id", "upload-sbom")["with"]["path"] = "sbom-cyclonedx.*"
    yield "sidecar not uploaded", d
    d = copy.deepcopy(doc)
    sbom_step(d, "id", "upload-sbom")["with"]["if-no-files-found"] = "error"
    yield "upload fails without a sidecar", d
    d = copy.deepcopy(doc)
    d["jobs"]["sbom"]["steps"].append(
        {"name": "Write sidecar", "shell": "bash",
         "run": f'echo \'{{"changed": false}}\' > {SIDECAR}'})
    yield "inline sidecar writer", d
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
    for step_id in ("validate-grype-policy", "validate-grype-gate-when"):
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
        policy, gate = check_validation(name, doc, None, [])
        if policy is None or gate is None:
            print(f"::error file={root / name}::cannot extract the "
                  "validation steps")
            sys.exit(1)
        reference = {"policy": policy, "gate": gate}
        (out / "validate-grype-policy.sh").write_text(policy["run"])
        (out / "validate-grype-gate-when.sh").write_text(gate["run"])
    for problem in problems:
        failures += 1
        print(f"::error file={root / name}::{problem}")
if failures:
    print(f"{failures} problem(s) across {len(VERIFY + RELEASE)} "
          "workflow(s) ❌")
    sys.exit(1)
print(f"{len(VERIFY + RELEASE)} workflow(s) wire the Grype gate ✅")

# Self-test: every mutant of the first verify workflow must fail. A
# mutant is checked against the pristine reference, so a change to a
# validation step counts as divergence.
doc = load(root, VERIFY[0])
escaped = 0
total = 0
for label, mutant in mutants(doc):
    total += 1
    # Round-trip through YAML as the real check does
    mutant = yaml.safe_load(yaml.safe_dump(mutant))
    if not check_doc(VERIFY[0], mutant, reference):
        escaped += 1
        print(f"::error::mutant not caught: {label}")
print(f"Mutants of {VERIFY[0]} caught: {total - escaped}/{total}")
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

if [ "${errors}" != '0' ]; then
  echo "Grype policy validation incorrect ❌"
  exit 1
fi
echo "Grype policy validation accepts and rejects as documented ✅"
