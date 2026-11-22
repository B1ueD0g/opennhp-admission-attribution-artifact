"""Independent local state-aware baseline for the frozen method-v3 contract.

B1 uses visible compatibility, native hard parents, capacity singleton propagation,
and one ordinary maximum-matching feasibility check.  It does not project all
feasible assignments or force/forbid query edges.  Residual candidate domains are
safe over-approximations: an unresolved edge need not belong to a global matching.
The resulting abstention is part of this operational baseline, not an oracle.

Only stdlib is used.  Run ``python3 baseline.py --self-test`` for seven independent,
handwritten controls; no generator, hidden owner, or sealed input is imported.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from typing import Any


_PROCESSING = {"CONSUMED", "REJECTED", "UNKNOWN"}
_PRE = ("rule_empty", "tcp_failed", "health_ok", "order_ok")
_POST = ("new_tcp", "http_ok", "order_ok")
_COVERAGE = ("owners_complete", "actions_complete", "single_action_per_request")
Owner = tuple[str, str]


def _is_bool(value: Any) -> bool:
    return type(value) is bool


def _nullable_bool(value: Any) -> bool:
    return value is None or _is_bool(value)


def _error(message: str) -> None:
    raise ValueError(message)


def _validate(case: Any) -> None:
    if not isinstance(case, dict):
        _error("case must be an object")
    if not isinstance(case.get("query"), str) or not case["query"]:
        _error("query must be a nonempty request-instance id")
    if not isinstance(case.get("requests"), list) or not isinstance(case.get("actions"), list):
        _error("requests and actions must be arrays")
    contract = case.get("contract")
    if not isinstance(contract, dict) or any(not _is_bool(contract.get(k)) for k in _COVERAGE):
        _error("all three contract coverage/cardinality fields must be strict booleans")
    if contract.get("basis") not in {"fixture_verified", "record_unverified"}:
        _error("contract basis must be fixture_verified or record_unverified")
    request_ids: set[str] = set()
    for request in case["requests"]:
        if not isinstance(request, dict):
            _error("each request must be an object")
        rid = request.get("id")
        if not isinstance(rid, str) or not rid or rid in request_ids or rid == "__external_owner__":
            _error("request ids must be unique nonempty strings")
        if request.get("processing") not in _PROCESSING:
            _error("request processing must be CONSUMED, REJECTED, or UNKNOWN")
        if not isinstance(request.get("resource"), str) or not request["resource"]:
            _error("request resource must be a nonempty string")
        # Identity metadata is optional evidence, not a global invocation key.
        # Sparse real observations retain null rather than fabricated values.
        for key in ("content_hash", "connection"):
            value = request.get(key)
            if value is not None and not isinstance(value, str):
                _error(f"request {key} must be a string or null when present")
        wire_tx = request.get("wire_tx")
        if wire_tx is not None and not (
            isinstance(wire_tx, str) or type(wire_tx) is int
        ):
            _error("request wire_tx must be a string, integer, or null when present")
        request_ids.add(rid)
    request_resources = {r["id"]: r.get("resource") for r in case["requests"]}
    target_resource = request_resources.get(case["query"])
    action_ids: set[str] = set()
    for action in case["actions"]:
        if not isinstance(action, dict):
            _error("each action must be an object")
        aid = action.get("id")
        if not isinstance(aid, str) or not aid or aid in action_ids:
            _error("action ids must be unique nonempty strings")
        action_ids.add(aid)
        if not _nullable_bool(action.get("success")):
            _error("action success must be a strict boolean or null")
        candidates = action.get("candidates")
        if not isinstance(candidates, list) or any(not isinstance(x, str) for x in candidates):
            _error("action candidates must be an array of request ids")
        if len(candidates) != len(set(candidates)) or any(x not in request_ids for x in candidates):
            _error("candidates must be distinct observed request ids")
        if not _is_bool(action.get("hard_parent")):
            _error("action hard_parent must be a strict boolean")
        if action["hard_parent"] and len(candidates) != 1:
            _error("a hard_parent action requires exactly one candidate")
        # One-resource request model: every proposed owner must protect the
        # same state as the logical action.  An independent other-resource
        # component remains valid when its own request/action edges agree.
        if "resource" in action and (not isinstance(action["resource"], str) or not action["resource"]):
            _error("action resource must be nonempty when supplied")
        action_resource = action.get("resource", target_resource)
        coarse_candidates = action.get("coarse_candidates")
        if not isinstance(coarse_candidates, list) or any(
            not isinstance(x, str) for x in coarse_candidates
        ):
            _error("action coarse_candidates must be an array of request ids")
        if len(coarse_candidates) != len(set(coarse_candidates)) or any(
            x not in request_ids for x in coarse_candidates
        ):
            _error("coarse_candidates must be distinct observed request ids")
        for field, owners in (("candidates", candidates), ("coarse_candidates", coarse_candidates)):
            if any(request_resources[rid] != action_resource for rid in owners):
                _error(f"action {field} contains a cross-resource owner edge")
    for name, keys in (("pre", _PRE), ("post", _POST)):
        state = case.get(name)
        if not isinstance(state, dict) or any(not _nullable_bool(state.get(k)) for k in keys):
            _error(f"{name} evidence must contain nullable strict booleans")
    requirement = case.get("requirement")
    if not isinstance(requirement, dict):
        _error("requirement must be an object")
    if requirement.get("kind") not in {"fixture", "native", "unknown"}:
        _error("requirement kind must be fixture, native, or unknown")
    if not _is_bool(requirement.get("applicable")):
        _error("requirement applicable must be a strict boolean")
    if not _nullable_bool(requirement.get("allows_target")):
        _error("requirement allows_target must be a strict boolean or null")
    if not isinstance(requirement.get("source"), str):
        _error("requirement source must be a string when present")


def _processing(case: dict[str, Any]) -> str:
    target = next((r for r in case["requests"] if r["id"] == case["query"]), None)
    if target is not None:
        return target["processing"]
    return "NO_TARGET_RECORD" if case["contract"]["owners_complete"] else "UNKNOWN"


def _authorize(effect: str, case: dict[str, Any], blockers: list[str]) -> str:
    req = case.get("requirement", {})
    if (
        req.get("kind", "unknown") not in {"fixture", "native"}
        or req.get("applicable", False) is not True
        or not _is_bool(req.get("allows_target"))
    ):
        blockers.append("requirement_unknown_or_inapplicable")
        return "UNKNOWN"
    source = req.get("source")
    # The shared pre-evaluation clarification fixes canonical source to string.
    # Presence still does not independently certify truth or applicability.
    source_present = isinstance(source, str) and bool(source.strip())
    if not source_present:
        blockers.append("requirement_source_missing")
        return "UNKNOWN"
    if effect in {"ACTION_ONLY", "REOPENED"}:
        return "CONFORMS" if req["allows_target"] else "DEVIATES"
    if effect == "NO_TARGET_ACTION":
        return "CONFORMS"
    return "UNKNOWN"


def _owner_label(owner: Owner) -> str:
    return owner[1] if owner[0] == "request" else f"EXTERNAL_FOR_ACTION:{owner[1]}"


def _result_error(status: str, message: str, method: str, started: int) -> dict[str, Any]:
    return {
        "method": method,
        "status": status,
        "processing": status,
        "effect": status,
        "authorization": status,
        "blockers": [message],
        "witness": {},
        "coverage": {},
        "cost": {"elapsed_ns": time.perf_counter_ns() - started},
    }


def _maximum_matching(
    domains: dict[str, set[Owner]], cost: dict[str, Any]
) -> tuple[bool, dict[str, Owner]]:
    """Ordinary augmenting-path feasibility, once per whole input instance."""
    owner_to_action: dict[Owner, str] = {}

    def augment(aid: str, visited: set[Owner]) -> bool:
        for owner in sorted(domains[aid]):
            cost["matching_edge_visits"] += 1
            if owner in visited:
                continue
            visited.add(owner)
            previous = owner_to_action.get(owner)
            if previous is None or augment(previous, visited):
                owner_to_action[owner] = aid
                return True
        return False

    for aid in sorted(domains, key=lambda x: (len(domains[x]), x)):
        cost["matching_augmentations"] += 1
        if not augment(aid, set()):
            return False, {}
    return True, {aid: owner for owner, aid in owner_to_action.items()}


def solve(case: dict[str, Any]) -> dict[str, Any]:
    """Return conservative B1 verdicts from the published visible input only."""
    started = time.perf_counter_ns()
    try:
        _validate(case)
    except (ValueError, TypeError) as exc:
        return _result_error("INVALID_INPUT", str(exc), "B1", started)

    query = case["query"]
    target_owner: Owner = ("request", query)
    contract = case["contract"]
    requests = {r["id"]: r for r in case["requests"]}
    actions = {a["id"]: a for a in case["actions"]}
    target_resource = requests.get(query, {}).get("resource")
    processing = _processing(case)
    capacity = contract["single_action_per_request"]
    domains: dict[str, set[Owner]] = {}
    cost: dict[str, Any] = {
        "requests": len(requests),
        "actions": len(actions),
        "visible_candidate_edges": sum(len(a["candidates"]) for a in actions.values()),
        "propagation_rounds": 0,
        "capacity_edges_removed": 0,
        "matching_checks": 0,
        "matching_augmentations": 0,
        "matching_edge_visits": 0,
        "query_projection_checks": 0,
    }
    steps: list[dict[str, str]] = []
    for aid, action in actions.items():
        domains[aid] = {
            ("request", rid)
            for rid in action["candidates"]
            if requests[rid]["processing"] != "REJECTED"
        }
        if not contract["owners_complete"] and not action["hard_parent"]:
            # The token is action-specific and has unrestricted external capacity.
            domains[aid].add(("external", aid))

    def conflict(reason: str) -> dict[str, Any]:
        result = _result_error("CONFLICT", reason, "B1", started)
        result["coverage"] = {k: contract[k] for k in _COVERAGE}
        result["witness"] = {
            "residual_candidates": {
                aid: [_owner_label(x) for x in sorted(domain)] for aid, domain in sorted(domains.items())
            },
            "propagation_steps": steps,
        }
        cost["elapsed_ns"] = time.perf_counter_ns() - started
        result["cost"] = cost
        return result

    # Propagation uses only singleton domains and the declared request capacity.
    # It never treats one arbitrary matching as a uniquely established trace.
    propagated: set[str] = set()
    while True:
        if any(not domain for domain in domains.values()):
            return conflict("an_observed_action_has_no_compatible_owner")
        newly_single = [aid for aid in sorted(domains) if len(domains[aid]) == 1 and aid not in propagated]
        if not newly_single:
            break
        cost["propagation_rounds"] += 1
        for aid in newly_single:
            if not domains[aid]:
                return conflict("capacity_singleton_contradiction")
            propagated.add(aid)
            owner = next(iter(domains[aid]))
            steps.append({"action": aid, "singleton_owner": _owner_label(owner)})
            if capacity and owner[0] == "request":
                for other in sorted(domains):
                    if other != aid and owner in domains[other]:
                        domains[other].remove(owner)
                        cost["capacity_edges_removed"] += 1
                        steps.append({"action": other, "removed_owner": owner[1], "because_action": aid})

    if capacity:
        cost["matching_checks"] = 1
        feasible, assignment = _maximum_matching(domains, cost)
        if not feasible:
            return conflict("no_capacity_feasible_matching_for_all_observed_actions")
    else:
        assignment = {aid: sorted(domain)[0] for aid, domain in domains.items()}

    fixed = {aid: next(iter(domain)) for aid, domain in domains.items() if len(domain) == 1}
    fixed_target = [aid for aid, owner in fixed.items() if owner == target_owner]
    success_witnesses = [aid for aid in fixed_target if actions[aid]["success"] is True]
    local_possible = [
        aid for aid, domain in domains.items()
        if target_owner in domain and actions[aid]["success"] is not False
    ]
    # With one bundle already forced to target, the capacity also excludes an
    # additional unobserved successful bundle, including after a failed bundle.
    hidden_possible = (
        query in requests
        and processing != "REJECTED"
        and not contract["actions_complete"]
        and (not capacity or not fixed_target)
    )
    must_success = bool(success_witnesses)
    may_success_upper = bool(local_possible) or hidden_possible
    blockers: list[str] = []
    lifecycle_missing = [
        f"{group}.{key}"
        for group, keys in (("pre", _PRE), ("post", _POST))
        for key in keys
        if case.get(group, {}).get(key) is not True
    ]
    all_possible_success_exclusive = all(
        domain == {target_owner}
        for aid, domain in domains.items()
        if actions[aid]["success"] is not False
        and actions[aid].get("resource", target_resource) == target_resource
    )
    reopen = (
        must_success
        and not lifecycle_missing
        and contract["owners_complete"]
        and contract["actions_complete"]
        and all_possible_success_exclusive
    )
    if processing == "UNKNOWN":
        effect = "UNKNOWN"
        blockers.append("target_processing_not_observed")
    elif processing == "NO_TARGET_RECORD":
        effect = "NO_TARGET_ACTION"
    elif must_success:
        effect = "REOPENED" if reopen else "ACTION_ONLY"
        if lifecycle_missing:
            blockers.append("reopen_state_missing:" + ",".join(lifecycle_missing))
        if not contract["owners_complete"]:
            blockers.append("reopen_owners_coverage_incomplete")
        if not contract["actions_complete"]:
            blockers.append("reopen_actions_coverage_incomplete")
        if not all_possible_success_exclusive:
            blockers.append("other_possible_successful_window_action")
    elif not may_success_upper:
        effect = "NO_TARGET_ACTION"
    else:
        effect = "UNKNOWN"
        if hidden_possible:
            blockers.append("unobserved_target_success_permitted")
        if any(len(domains[aid]) > 1 for aid in local_possible):
            blockers.append("success_ownership_not_locally_unique")
        if any(actions[aid]["success"] is None for aid in local_possible):
            blockers.append("target_candidate_action_success_unknown")
    authorization = _authorize(effect, case, blockers)
    cost["forced_action_owners"] = len(fixed)
    cost["elapsed_ns"] = time.perf_counter_ns() - started
    return {
        "method": "B1",
        "status": "OK",
        "processing": processing,
        "effect": effect,
        "authorization": authorization,
        "blockers": blockers,
        "coverage": {k: contract[k] for k in _COVERAGE},
        "witness": {
            "feasible_assignment": {aid: _owner_label(owner) for aid, owner in sorted(assignment.items())},
            "singleton_owners": {aid: _owner_label(owner) for aid, owner in sorted(fixed.items())},
            "propagation_steps": steps,
            "residual_candidates": {
                aid: [_owner_label(owner) for owner in sorted(domain)] for aid, domain in sorted(domains.items())
            },
            "certain_success_actions": sorted(success_witnesses),
            "local_possible_success_actions": sorted(local_possible),
            "unobserved_target_success_permitted": hidden_possible,
            "may_is_local_upper_bound": True,
            "requirement": copy.deepcopy(case.get("requirement", {})),
        },
        "cost": cost,
    }


def solve_http(case: dict[str, Any]) -> dict[str, Any]:
    """HTTP-only informational ablation, explicitly not the strong B1 baseline.

    The common direct-processing channel and requirement are retained.  The
    effect channel sees only HTTP availability: HTTP success is naively credited
    as ACTION_ONLY, and HTTP failure/absence cannot establish no target action.
    It never certifies reopening.  This deliberate information loss can produce
    wrong target attribution and must not be used as a normative contract oracle.
    """
    started = time.perf_counter_ns()
    try:
        _validate(case)
    except (ValueError, TypeError) as exc:
        return _result_error("INVALID_INPUT", str(exc), "HTTP_ONLY_INFORMATIONAL_ABLATION", started)
    processing = _processing(case)
    blockers = ["http_success_does_not_identify_the_operation_owner"]
    if processing == "UNKNOWN":
        effect = "UNKNOWN"
        blockers.append("target_processing_not_observed")
    elif processing == "NO_TARGET_RECORD":
        effect = "NO_TARGET_ACTION"
    elif case.get("post", {}).get("http_ok") is True:
        effect = "ACTION_ONLY"
    else:
        effect = "UNKNOWN"
        blockers.append("http_failure_or_absence_does_not_exclude_target_action")
    authorization = _authorize(effect, case, blockers)
    return {
        "method": "HTTP_ONLY_INFORMATIONAL_ABLATION",
        "status": "OK",
        "processing": processing,
        "effect": effect,
        "authorization": authorization,
        "blockers": blockers,
        "coverage": {k: case["contract"][k] for k in _COVERAGE},
        "witness": {"http_ok": case.get("post", {}).get("http_ok"), "strong_baseline": False},
        "cost": {
            "requests": len(case["requests"]),
            "shared_validation_actions": len(case["actions"]),
            "effect_channel_actions_inspected": 0,
            "elapsed_ns": time.perf_counter_ns() - started,
        },
    }


def run_self_tests() -> list[dict[str, Any]]:
    """Seven small controls specified from contract semantics, not generated data."""
    def base() -> dict[str, Any]:
        return {
            "id": "handwritten", "query": "q",
            "requests": [{"id": "q", "processing": "CONSUMED", "provenance": "handwritten control"}],
            "actions": [{"id": "a", "success": True, "candidates": ["q"], "hard_parent": True}],
            "contract": {"owners_complete": True, "actions_complete": True, "single_action_per_request": True},
            "pre": dict.fromkeys(_PRE, True), "post": dict.fromkeys(_POST, True),
            "requirement": {"kind": "fixture", "applicable": True, "allows_target": True, "source": "handwritten fixture rule"},
        }
    controls: list[tuple[str, dict[str, Any], tuple[str, str, str, str]]] = []
    c = base()
    controls.append(("complete_identity_reopen", c, ("OK", "CONSUMED", "REOPENED", "CONFORMS")))
    c = base()
    c["requests"].extend([{"id": "prefix", "processing": "CONSUMED"}])
    c["requests"][0]["processing"] = "REJECTED"
    c["actions"][0]["candidates"] = ["prefix"]
    c["requirement"]["allows_target"] = False
    controls.append(("rejected_target_with_inherited_http", c, ("OK", "REJECTED", "NO_TARGET_ACTION", "CONFORMS")))
    c = base()
    c["contract"]["owners_complete"] = False
    c["actions"][0]["hard_parent"] = False
    controls.append(("unobserved_competing_owner", c, ("OK", "CONSUMED", "UNKNOWN", "UNKNOWN")))
    c = base()
    c["actions"] = []
    c["contract"]["actions_complete"] = False
    controls.append(("missing_action_is_not_absence", c, ("OK", "CONSUMED", "UNKNOWN", "UNKNOWN")))
    c = base()
    c["requests"].append({"id": "other", "processing": "CONSUMED"})
    c["actions"] = [
        {"id": "a", "success": True, "candidates": ["q", "other"], "hard_parent": False},
        {"id": "b", "success": False, "candidates": ["other"], "hard_parent": False},
    ]
    controls.append(("capacity_singleton_cascade", c, ("OK", "CONSUMED", "REOPENED", "CONFORMS")))
    c = base()
    c["requests"].append({"id": "other", "processing": "CONSUMED"})
    c["actions"] = [
        {"id": aid, "success": True, "candidates": ["q", "other"], "hard_parent": False}
        for aid in ("a", "b", "c")
    ]
    controls.append(("hall_conflict_without_singletons", c, ("CONFLICT", "CONFLICT", "CONFLICT", "CONFLICT")))
    c = base()
    c["requests"][0]["resource"] = "target-resource"
    c["requests"].append({"id": "unrelated", "processing": "CONSUMED", "resource": "other-resource"})
    c["actions"].append({
        "id": "unrelated-action", "success": True, "candidates": ["unrelated"],
        "hard_parent": True, "resource": "other-resource",
    })
    controls.append(("unrelated_resource_invariance", c, ("OK", "CONSUMED", "REOPENED", "CONFORMS")))
    results = []
    for name, case, expected in controls:
        case['contract']['basis']='fixture_verified'
        for r in case['requests']:r.setdefault('resource','target-resource')
        for a in case['actions']:a.setdefault('coarse_candidates',list(a['candidates']))
        original = copy.deepcopy(case)
        out = solve(case)
        actual = tuple(out[k] for k in ("status", "processing", "effect", "authorization"))
        assert actual == expected, (name, expected, actual, out)
        assert case == original, (name, "input mutated")
        if name == "unrelated_resource_invariance":
            reduced = copy.deepcopy(case)
            reduced["requests"] = reduced["requests"][:1]
            reduced["actions"] = reduced["actions"][:1]
            reference = solve(reduced)
            reference_verdict = tuple(reference[k] for k in ("status", "processing", "effect", "authorization"))
            assert actual == reference_verdict, (name, "unrelated resource changed verdict")
        results.append({"name": name, "passed": True, "expected": expected, "actual": actual})
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--http-only", action="store_true")
    parser.add_argument("input", nargs="?", help="one public visible case JSON; stdin if omitted")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps({"handwritten_controls": run_self_tests(), "count": 7}, ensure_ascii=False, indent=2))
        return
    if args.input:
        with open(args.input, encoding="utf-8") as source:
            case = json.load(source)
    else:
        case = json.load(sys.stdin)
    print(json.dumps((solve_http if args.http_only else solve)(case), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
