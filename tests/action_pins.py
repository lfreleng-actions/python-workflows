# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Check shared GitHub Action pins, including YAML version comments."""

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Protocol

SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"# v([0-9]+)\.([0-9]+)\.([0-9]+)")
EXPECTED_PIN = "expected a full lowercase commit SHA and # vX.Y.Z"


class Mark(Protocol):
    line: int
    column: int
    index: int


class Node(Protocol):
    """The source positions and values provided by PyYAML's compose."""

    start_mark: Mark
    end_mark: Mark
    value: str | list["Node"] | list[tuple["Node", "Node"]]


Compose = Callable[[str], Node | None]


@dataclass(frozen=True)
class Call:
    workflow: str
    line: int
    column: int
    uses: str
    comment: str

    @property
    def sha(self) -> str:
        return self.uses.partition("@")[2]


def _mapping(node: Node | None) -> Iterator[tuple[Node, Node]]:
    if node is not None and isinstance(node.value, list):
        for item in node.value:
            if isinstance(item, tuple):
                yield item


def _field(node: Node | None, key: str) -> Node | None:
    return next((value for field, value in _mapping(node) if field.value == key), None)


def _steps(doc: Node | None) -> Iterator[Node]:
    for _, job in _mapping(_field(doc, "jobs")):
        steps = _field(job, "steps")
        if steps is not None and isinstance(steps.value, list):
            for step in steps.value:
                if not isinstance(step, tuple):
                    yield step


def _calls(workflow: str, text: str, action: str, compose: Compose) -> Iterator[Call]:
    # YAML locates the actual steps; the source preserves their comments.
    for step in _steps(compose(text)):
        for key, uses in _mapping(step):
            value = uses.value
            if (
                key.value != "uses"
                or not isinstance(value, str)
                or value.partition("@")[0] != action
            ):
                continue
            start, end = uses.start_mark, uses.end_mark
            comment = ""
            if key.end_mark.line == start.line == end.line:
                comment = text[end.index :].partition("\n")[0].strip()
            yield Call(workflow, key.start_mark.line, start.column, value, comment)


def _problems(calls: list[Call], action: str, floor: tuple[int, int, int]) -> list[str]:
    if not calls:
        return [f"{action}: no calls found"]
    minimum = "v{}.{}.{}".format(*floor)
    reasons: dict[Call, str] = {}
    pins: set[tuple[str, str]] = set()
    for call in calls:
        version = VERSION.fullmatch(call.comment)
        if not SHA.fullmatch(call.sha) or version is None:
            reasons[call] = EXPECTED_PIN
            continue
        pins.add((call.sha, call.comment))
        if tuple(map(int, version.groups())) < floor:
            reasons[call] = f"version below {minimum}"
    if not reasons and len(pins) <= 1:
        return []
    summary = f"{action}: invalid pin"
    if len(pins) > 1:
        summary = f"{action}: calls do not share one pin and version comment"
    problems = [summary]
    for call in calls:
        location = f"{call.workflow}:{call.line + 1}"
        pin = f"{call.uses} {call.comment}".rstrip()
        reason = f": {reasons[call]}" if call in reasons else ""
        problems.append(f"{location}: {pin}{reason}")
    return problems


def check_pins(
    sources: dict[str, str], action: str, floor: tuple[int, int, int], compose: Compose
) -> list[str]:
    """Return pin problems and every affected action call site."""
    calls = [
        call
        for name, text in sources.items()
        for call in _calls(name, text, action, compose)
    ]
    return _problems(calls, action, floor)


def pin_self_tests(
    sources: dict[str, str], action: str, floor: tuple[int, int, int], compose: Compose
) -> list[str]:
    """Rewrite actual workflow calls and verify the pin check's verdicts."""
    by_workflow = {
        name: list(_calls(name, text, action, compose))
        for name, text in sources.items()
    }
    calls = [call for pins in by_workflow.values() for call in pins]
    original = calls[0]
    # Synthetic SHAs distinct from the validated pin, even after future bumps.
    fresh, other = [digit * 40 for digit in "012" if digit * 40 != original.sha][:2]
    major = int(original.comment.removeprefix("# v").partition(".")[0])
    newer = f"# v{major + 1}.0.0"
    older = f"# v{floor[0]}.{floor[1] - 1}.0"

    def rewrite(targets: list[Call], pin: str) -> list[str]:
        rewritten = sources.copy()
        for name in {call.workflow for call in targets}:
            lines = sources[name].splitlines(keepends=True)
            for call in targets:
                if call.workflow == name:
                    lines[call.line] = (
                        f"{lines[call.line][: call.column]}{action}@{pin}\n"
                    )
            rewritten[name] = "".join(lines)
        return check_pins(rewritten, action, floor, compose)

    problems: list[str] = []
    if rejected := rewrite(calls, f"{fresh}  {newer}"):
        problems.append(f"uniform pin bump rejected: {rejected}")
    mismatched_pin = f"{other}  {original.comment}"
    mutants = [
        ("tag", [original], f"v1.0.0  {original.comment}", EXPECTED_PIN),
        ("branch", [original], f"main  {original.comment}", EXPECTED_PIN),
        ("short SHA", [original], f"{fresh[:7]}  {original.comment}", EXPECTED_PIN),
        ("missing comment", [original], original.sha, EXPECTED_PIN),
        ("old version", calls, f"{original.sha}  {older}", "version below"),
    ]
    for call in calls:
        site = f"{call.workflow}:{call.line + 1}"
        mutants.append(
            (f"one different SHA at {site}", [call], mismatched_pin, "do not share")
        )
        mutants.append(
            (
                f"old version at {site}",
                [call],
                f"{original.sha}  {older}",
                "version below",
            )
        )
    for name, targets in by_workflow.items():
        if len(targets) > 1:
            mutants.append(
                (f"all calls drift in {name}", targets, mismatched_pin, "do not share")
            )
    for label, targets, pin, expected in mutants:
        found = rewrite(targets, pin)
        if not any(expected in problem for problem in found):
            problems.append(f"{label} mutant did not report {expected!r}: {found}")
    return problems
