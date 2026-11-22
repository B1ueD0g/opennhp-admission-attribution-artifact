"""Independent finite-fixture generator and exact observational reference.

The reference reads only the public MODEL_CONTRACT fields.  It does not inspect
family, split, provenance text, latent execution, names, or candidate-method code.
Synthetic scopes are an explicit observation interface: candidate edges are
projected from resource and observable scope membership, never from an answer.

Run with ``python fixture_reference.py --out PATH --self-check``.  Sealed labels
and latent executions are stored only under oracle_private; the printed receipt
contains counts and hashes, not sealed contents or labels.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import time
from typing import Any


VERSION = "independent-reference-v1"
EXTERNAL = "__external_owner__"
MAX_SECONDS = 10.0
FAMILIES = (
    "rejected_old_admission", "consumed_existing_admission", "expired_reopen",
    "background_without_target", "critical_evidence_missing", "equal_candidates",
)
PRE_KEYS = ("rule_empty", "tcp_failed", "health_ok", "order_ok")
POST_KEYS = ("new_tcp", "http_ok", "order_ok")


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _invalid(message: str) -> dict[str, Any]:
    return {"status": "INVALID_INPUT", "processing": "INVALID_INPUT",
            "effect": "INVALID_INPUT", "authorization": "INVALID_INPUT",
            "error": message, "cost": {"models_examined": 0, "owner_assignments": 0}}


def _validate(case: Any) -> str | None:
    if not isinstance(case, dict):
        return "case must be an object"
    if not isinstance(case.get("query"), str) or not case["query"]:
        return "query must be a nonempty request-instance string"
    if not isinstance(case.get("requests"), list) or not isinstance(case.get("actions"), list):
        return "requests/actions must be arrays"
    reqs = case["requests"]
    acts = case["actions"]
    ids: list[str] = []
    for request in reqs:
        if not isinstance(request, dict):
            return "request must be an object"
        ident = request.get("id")
        if not isinstance(ident, str) or not ident or ident == EXTERNAL:
            return "invalid/reserved request id"
        ids.append(ident)
        if request.get("processing") not in ("CONSUMED", "REJECTED", "UNKNOWN"):
            return "invalid processing observation"
        if not isinstance(request.get("resource"), str) or not request["resource"]:
            return "request resource must be a nonempty string"
        for key in ("content_hash", "connection"):
            value = request.get(key)
            if value is not None and not isinstance(value, str):
                return f"request {key} must be a string or null"
        wire_tx = request.get("wire_tx")
        if wire_tx is not None and (not isinstance(wire_tx, (str, int)) or isinstance(wire_tx, bool)):
            return "wire_tx must be a string/integer or null, not invocation identity"
    if len(ids) != len(set(ids)):
        return "duplicate request-instance id"
    request_resources = {request["id"]: request["resource"] for request in reqs}
    query_resource = request_resources.get(case["query"])
    action_ids: list[str] = []
    for action in acts:
        if not isinstance(action, dict):
            return "action must be an object"
        ident = action.get("id")
        if not isinstance(ident, str) or not ident:
            return "invalid action id"
        action_ids.append(ident)
        if action.get("success") is not None and type(action.get("success")) is not bool:
            return "success must be bool or null"
        if type(action.get("hard_parent")) is not bool:
            return "hard_parent must be bool"
        for key in ("candidates", "coarse_candidates"):
            candidates = action.get(key)
            if (not isinstance(candidates, list) or
                    any(not isinstance(x, str) or x not in ids for x in candidates) or
                    len(candidates) != len(set(candidates))):
                return f"{key} must contain unique observed request ids"
        if action["hard_parent"] and len(action["candidates"]) != 1:
            return "hard_parent requires exactly one candidate"
        if "resource" in action and (not isinstance(action["resource"], str) or not action["resource"]):
            return "action resource must be nonempty when supplied"
        effective_resource = action.get("resource", query_resource)
        for key in ("candidates", "coarse_candidates"):
            if any(request_resources[owner] != effective_resource for owner in action[key]):
                return f"{key} contains an owner outside the action resource"
    if len(action_ids) != len(set(action_ids)):
        return "duplicate logical action id"
    contract = case.get("contract")
    if not isinstance(contract, dict):
        return "contract missing"
    for key in ("owners_complete", "actions_complete", "single_action_per_request"):
        if type(contract.get(key)) is not bool:
            return f"contract.{key} must be bool"
    if contract.get("basis") not in ("fixture_verified", "record_unverified"):
        return "invalid contract basis"
    for section, keys in (("pre", PRE_KEYS), ("post", POST_KEYS)):
        if not isinstance(case.get(section), dict):
            return f"{section} missing"
        for key in keys:
            value = case[section].get(key)
            if value is not None and type(value) is not bool:
                return f"{section}.{key} must be bool or null"
    requirement = case.get("requirement")
    if not isinstance(requirement, dict):
        return "requirement missing"
    if requirement.get("kind") not in ("fixture", "native", "unknown"):
        return "invalid requirement kind"
    if type(requirement.get("applicable")) is not bool:
        return "requirement.applicable must be bool"
    if requirement.get("allows_target") is not None and type(requirement.get("allows_target")) is not bool:
        return "requirement.allows_target must be bool or null"
    if not isinstance(requirement.get("source"), str):
        return "requirement.source must be a string"
    return None


def reference(case: dict[str, Any], max_assignments: int = 100000) -> dict[str, Any]:
    """Enumerate every feasible owner/success/optional-hidden completion.

    max_assignments bounds complete concrete executions, including independent
    success-null choices and the optional hidden target operation.  A result is
    withheld if the next feasible completion would exceed that bound.  External
    owners are capacity-free; naming one external equivalence class preserves
    all query-specific outputs and avoids an artificial infinite domain.
    """
    if type(max_assignments) is not int or max_assignments < 1:
        return _invalid("max_assignments must be a positive integer")
    error = _validate(case)
    if error:
        return _invalid(error)
    started = time.monotonic()
    query = case["query"]
    requests = {r["id"]: r for r in case["requests"]}
    actions = case["actions"]
    contract = case["contract"]
    target = requests.get(query)
    processing = (target["processing"] if target is not None else
                  "NO_TARGET_RECORD" if contract["owners_complete"] else "UNKNOWN")
    query_resource = target["resource"] if target else None
    projection_applicable = target is not None and processing != "UNKNOWN"
    domains: list[list[str]] = []
    for action in actions:
        domain = [r for r in action["candidates"] if requests[r]["processing"] != "REJECTED"]
        if not action["hard_parent"] and not contract["owners_complete"]:
            domain.append(EXTERNAL)
        domains.append(domain)
    # Choosing the smallest domain first is a traversal optimization only.
    order = sorted(range(len(actions)), key=lambda i: (len(domains[i]), i))
    unknown_successes = [i for i, a in enumerate(actions) if a["success"] is None]
    models = 0
    owners_count = 0
    search_nodes = 0
    any_success = False
    all_success = True
    exclusive = True
    first_success: dict[str, Any] | None = None
    first_failure: dict[str, Any] | None = None
    owner_vector: list[str | None] = [None] * len(actions)
    occupied: set[str] = set()
    exceeded: str | None = None

    def checkpoint() -> bool:
        nonlocal exceeded
        if time.monotonic() - started > MAX_SECONDS:
            exceeded = "time_limit"
            return False
        return True

    def visit(depth: int) -> None:
        nonlocal models, owners_count, search_nodes, exceeded, any_success, all_success
        nonlocal exclusive, first_success, first_failure
        if exceeded or not checkpoint():
            return
        search_nodes += 1
        if depth < len(order):
            i = order[depth]
            for owner in domains[i]:
                if (contract["single_action_per_request"] and owner != EXTERNAL and owner in occupied):
                    continue
                owner_vector[i] = owner
                if owner != EXTERNAL:
                    occupied.add(owner)
                visit(depth + 1)
                if owner != EXTERNAL:
                    # With unlimited capacity, another earlier bundle may still
                    # occupy this owner.  Recompute instead of removing blindly.
                    occupied.clear()
                    occupied.update(x for j, x in enumerate(owner_vector)
                                    if j != i and x is not None and x != EXTERNAL)
                owner_vector[i] = None
                if exceeded:
                    return
            return
        owners_count += 1
        has_target_owner = query in owner_vector
        hidden_allowed = (not contract["actions_complete"] and target is not None and
                          target["processing"] != "REJECTED" and
                          (not contract["single_action_per_request"] or not has_target_owner))
        for bits in itertools.product((False, True), repeat=len(unknown_successes)):
            values = [a["success"] for a in actions]
            for i, bit in zip(unknown_successes, bits):
                values[i] = bit
            for hidden in ((False, True) if hidden_allowed else (False,)):
                if not checkpoint():
                    return
                if models == max_assignments:
                    exceeded = "assignment_limit"
                    return
                models += 1
                success = hidden or any(owner == query and value is True
                                        for owner, value in zip(owner_vector, values))
                any_success |= success
                all_success &= success
                for action, owner, value in zip(actions, owner_vector, values):
                    relevant = (query_resource is not None and
                                action.get("resource", query_resource) == query_resource)
                    if relevant and value is True and owner != query:
                        exclusive = False
                if (success and first_success is None) or (not success and first_failure is None):
                    witness = {
                        "owners": {a["id"]: owner for a, owner in zip(actions, owner_vector)},
                        "success": {a["id"]: value for a, value in zip(actions, values)},
                        "hidden_target_success": hidden,
                        "target_success": success,
                    }
                    if success:
                        first_success = witness
                    else:
                        first_failure = witness

    visit(0)
    cost = {"models_examined": models, "owner_assignments": owners_count,
            "search_nodes": search_nodes, "seconds": time.monotonic() - started,
            "max_assignments": max_assignments, "max_seconds": MAX_SECONDS}
    if exceeded:
        return {"status": "BOUND_EXCEEDED", "processing": "BOUND_EXCEEDED",
                "effect": "BOUND_EXCEEDED", "authorization": "BOUND_EXCEEDED",
                "reason": exceeded, "cost": cost}
    if not models:
        return {"status": "CONFLICT", "processing": "CONFLICT", "effect": "CONFLICT",
                "authorization": "CONFLICT", "feasible_assignments": 0,
                "blockers": ["no_feasible_owner_assignment"], "cost": cost}
    lifecycle = all(case["pre"].get(k) is True for k in PRE_KEYS) and all(
        case["post"].get(k) is True for k in POST_KEYS)
    if processing == "UNKNOWN":
        effect = "UNKNOWN"
    elif processing == "NO_TARGET_RECORD":
        effect = "NO_TARGET_ACTION"
    elif all_success:
        effect = ("REOPENED" if lifecycle and contract["owners_complete"] and
                  contract["actions_complete"] and exclusive else "ACTION_ONLY")
    elif not any_success:
        effect = "NO_TARGET_ACTION"
    else:
        effect = "UNKNOWN"
    requirement = case["requirement"]
    applicable = (requirement["kind"] in ("fixture", "native") and
                  requirement["applicable"] and type(requirement["allows_target"]) is bool and
                  bool(requirement["source"].strip()))
    if not applicable or effect == "UNKNOWN":
        authorization = "UNKNOWN"
    elif effect == "NO_TARGET_ACTION":
        authorization = "CONFORMS"
    else:
        authorization = "CONFORMS" if requirement["allows_target"] else "DEVIATES"
    blockers: list[str] = []
    if target is None:
        blockers.append("target_not_located")
    if processing == "UNKNOWN":
        blockers.append("target_processing_unobserved")
    if not contract["owners_complete"]:
        blockers.append("owners_coverage_incomplete")
    if not contract["actions_complete"]:
        blockers.append("actions_coverage_incomplete")
    blockers += [f"pre.{k}_not_true" for k in PRE_KEYS if case["pre"].get(k) is not True]
    blockers += [f"post.{k}_not_true" for k in POST_KEYS if case["post"].get(k) is not True]
    if not exclusive:
        blockers.append("possible_other_owner_success_on_target_resource")
    if any_success and not all_success:
        blockers.append("opposite_feasible_target_success_completions")
    if not applicable:
        blockers.append("applicable_requirement_unavailable")
    output = {"status": "OK", "processing": processing, "effect": effect,
              "authorization": authorization, "projection_applicable": projection_applicable,
              "must_success": all_success if projection_applicable else None,
              "may_success": any_success if projection_applicable else None,
              "exclusive_successful_related_actions": exclusive if projection_applicable else None,
              "feasible_assignments": models, "feasible_owner_assignments": owners_count,
              "witness": first_success or first_failure, "counterexample": first_failure if any_success else None,
              "blockers": blockers, "cost": cost,
              "coverage": {k: contract[k] for k in ("owners_complete", "actions_complete")}}
    if first_success is not None and first_failure is not None:
        output["opposite_witnesses"] = [first_success, first_failure]
    if all_success:
        output["must_certificate"] = {"kind": "exhaustive_no_target_failure_completion",
                                      "complete_models": models, "search_exhausted": True}
    if not projection_applicable:
        # The anonymous external class is not a located query instance.  Keep
        # bounded-model diagnostics explicitly separate from the public query
        # projection, including when the direct consumer witness is UNKNOWN.
        output["internal_projection"] = {
            "must_success": all_success, "may_success": any_success,
            "exclusive_successful_related_actions": exclusive,
            "interpretation": "enumerated observed-id model only; public query projection inapplicable",
        }
        for key in ("witness", "counterexample", "opposite_witnesses", "must_certificate"):
            if key in output:
                output["internal_projection"][key] = output.pop(key)
    return output


def _request(name: str, processing: str = "CONSUMED", *, observed: str | None = None,
             resource: str = "svc-main", same_bytes: bool = True) -> dict[str, Any]:
    return {"id": name, "actual_processing": processing,
            "observed_processing": observed or processing, "resource": resource,
            "content_hash": "sha256:captured-bytes-A" if same_bytes else f"sha256:bytes-{name}",
            "wire_tx": "reused-wire-tx-17", "connection": f"connection-{name}",
            "visible_scopes": []}


def _action(name: str, owner: str, domain: list[str], success: bool = True, *,
            mode: str = "scope", observed_success: Any = "actual", resource: str = "svc-main") -> dict[str, Any]:
    return {"id": name, "actual_owner": owner, "scope_domain": domain,
            "actual_success": success, "observed_success": success if observed_success == "actual" else observed_success,
            "projection": mode, "resource": resource, "join_scope": f"scope-{name}"}


def _spec(requests: list[dict[str, Any]], actions: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
    result = {"requests": requests, "actions": actions, "query": "q",
              "owners_complete": True, "actions_complete": True,
              "single_action_per_request": True, "pre": {k: True for k in PRE_KEYS},
              "post": {k: True for k in POST_KEYS}, "allows_target": False,
              "requirement_kind": "fixture", "requirement_applicable": True,
              "intentional_conflict": False}
    result.update(kwargs)
    return result


def _templates(split: str) -> list[tuple[str, str, dict[str, Any]]]:
    """48 frozen semantic cases: structurally distinct dev/sealed prefix families.

    Domain membership is a declared observable scope relation.  Actual owners
    are chosen independently within those scopes, then hidden by projection.
    """
    R, A, S = _request, _action, _spec
    out: list[tuple[str, str, dict[str, Any]]] = []

    def add(family: int, name: str, spec: dict[str, Any]) -> None:
        out.append((FAMILIES[family], name, spec))

    if split == "dev":
        add(0, "single_prior_rule", S([R("q", "REJECTED"), R("p")],
            [A("a", "p", ["p"], mode="hard")], pre={**{k: True for k in PRE_KEYS}, "rule_empty": False}))
        add(0, "two_prior_outcomes", S([R("q", "REJECTED"), R("p"), R("b")],
            [A("a", "p", ["p"], False, mode="hard"), A("b", "b", ["b"], mode="hard")],
            pre={**{k: True for k in PRE_KEYS}, "tcp_failed": False}))
        add(0, "rejection_parent_contradiction", S([R("q", "CONSUMED", observed="REJECTED")],
            [A("a", "q", ["q"], mode="hard")], intentional_conflict=True))
        add(0, "rejected_hidden_operation_excluded", S([R("q", "REJECTED"), R("p")],
            [A("a", "p", ["p"], mode="hard")], actions_complete=False))

        add(1, "direct_consume_active_rule", S([R("q")], [A("a", "q", ["q"], mode="hard")],
            pre={**{k: True for k in PRE_KEYS}, "rule_empty": False}, allows_target=True))
        add(1, "one_bundle_two_receives", S([R("q"), R("p")], [A("a", "q", ["q", "p"])],
            pre={**{k: True for k in PRE_KEYS}, "tcp_failed": False}))
        add(1, "failed_bundle_exhausts_target", S([R("q")], [A("a", "q", ["q"], False, mode="hard")],
            actions_complete=False, pre={**{k: True for k in PRE_KEYS}, "rule_empty": False}))
        add(1, "unknown_success_active_rule", S([R("q")], [A("a", "q", ["q"], mode="hard", observed_success=None)],
            pre={**{k: True for k in PRE_KEYS}, "rule_empty": False}))

        add(2, "closed_then_unique_native_parent", S([R("q")], [A("a", "q", ["q"], mode="hard")]))
        add(2, "reused_hash_and_transaction", S([R("q"), R("p")],
            [A("a", "q", ["q"], mode="hard"), A("b", "p", ["p"], False, mode="hard")], allows_target=True))
        add(2, "health_unobserved", S([R("q")], [A("a", "q", ["q"], mode="hard")],
            pre={**{k: True for k in PRE_KEYS}, "health_ok": None}))
        add(2, "old_tcp_is_not_new_tcp", S([R("q")], [A("a", "q", ["q"], mode="hard")],
            post={**{k: True for k in POST_KEYS}, "new_tcp": False}))

        add(3, "background_only_complete_window", S([R("b")], [A("a", "b", ["b"], mode="hard")]))
        add(3, "background_window_owners_uncovered", S([R("b")], [A("a", "b", ["b"])], owners_complete=False))
        add(3, "absent_target_actions_uncovered", S([R("b")], [A("a", "b", ["b"], mode="hard")], actions_complete=False))
        add(3, "background_cardinality_contradiction", S([R("b")],
            [A("a", "b", ["b"], mode="hard"), A("b", "b", ["b"], mode="hard")], intentional_conflict=True))

        add(4, "target_action_stream_missing", S([R("q")], [], actions_complete=False))
        add(4, "external_owner_competes", S([R("q")], [A("a", "q", ["q"])], owners_complete=False))
        add(4, "consumer_processing_log_missing", S([R("q", observed="UNKNOWN")],
            [A("a", "q", ["q"], mode="hard")]))
        add(4, "optional_hidden_with_unlimited_capacity", S([R("q"), R("p")],
            [A("a", "q", ["q"], False, mode="hard"), A("b", "p", ["p"], mode="hard")],
            actions_complete=False, single_action_per_request=False))

        add(5, "equal_one_bundle_exchange", S([R("q"), R("p")], [A("a", "q", ["q", "p"])]))
        add(5, "two_bundle_exchange_must_success", S([R("q"), R("p")],
            [A("a", "q", ["q", "p"]), A("b", "p", ["q", "p"])], allows_target=True))
        add(5, "unlimited_owner_capacity", S([R("q"), R("p")],
            [A("a", "q", ["q", "p"]), A("b", "q", ["q", "p"])], single_action_per_request=False))
        add(5, "ambiguous_but_all_operations_failed", S([R("q"), R("p")],
            [A("a", "p", ["q", "p"], False)]))
    else:
        add(0, "two_stage_ambiguous_old_rules", S([R("q", "REJECTED"), R("p"), R("r"), R("s")],
            [A("a", "p", ["p", "r"]), A("b", "r", ["p", "r"]), A("c", "s", ["s"], False, mode="hard")],
            pre={**{k: True for k in PRE_KEYS}, "rule_empty": False}))
        add(0, "old_success_null_mix", S([R("q", "REJECTED"), R("p"), R("r")],
            [A("a", "p", ["p", "r"], observed_success=None), A("b", "r", ["p", "r"], False)],
            pre={**{k: True for k in PRE_KEYS}, "order_ok": None}))
        add(0, "hard_rejected_parent_with_background", S([R("q", "CONSUMED", observed="REJECTED"), R("p")],
            [A("a", "q", ["q"], mode="hard"), A("b", "p", ["p"], mode="hard")], intentional_conflict=True))
        add(0, "unobserved_prior_authorizer", S([R("q", "REJECTED")],
            [A("a", "external:earlier", ["q"])], owners_complete=False,
            pre={**{k: True for k in PRE_KEYS}, "tcp_failed": False}))

        add(1, "active_rule_hall_forces_query", S([R("q"), R("p"), R("r")],
            [A("a", "p", ["p", "r"], False), A("b", "r", ["p", "r"], False), A("c", "q", ["q", "p", "r"])],
            pre={**{k: True for k in PRE_KEYS}, "rule_empty": False}))
        add(1, "active_rule_cycle_all_success", S([R("q"), R("p"), R("r")],
            [A("a", "q", ["q", "p"]), A("b", "p", ["p", "r"]), A("c", "r", ["q", "r"])],
            pre={**{k: True for k in PRE_KEYS}, "tcp_failed": False}, allows_target=True))
        add(1, "active_rule_missing_query_processing", S([R("q", observed="UNKNOWN"), R("p")],
            [A("a", "q", ["q"], mode="hard"), A("b", "p", ["p"], False, mode="hard")],
            pre={**{k: True for k in PRE_KEYS}, "health_ok": None}))
        add(1, "multiple_bundles_same_consumer", S([R("q"), R("p")],
            [A("a", "q", ["q"], False, mode="hard"), A("b", "q", ["q"], mode="hard"), A("c", "p", ["p"], False, mode="hard")],
            single_action_per_request=False, pre={**{k: True for k in PRE_KEYS}, "rule_empty": False}))

        add(2, "closed_hall_positive_control", S([R("q"), R("p"), R("r")],
            [A("a", "p", ["p", "r"], False), A("b", "r", ["p", "r"], False), A("c", "q", ["q", "p", "r"])], allows_target=True))
        add(2, "closed_exchange_nonexclusive_success", S([R("q"), R("p")],
            [A("a", "q", ["q", "p"]), A("b", "p", ["q", "p"])]))
        add(2, "concurrent_unrelated_resource", S([R("q"), R("p", resource="svc-other")],
            [A("a", "q", ["q"], mode="hard"), A("b", "p", ["p"], mode="hard", resource="svc-other")]))
        add(2, "closed_order_gap_with_two_actions", S([R("q"), R("p")],
            [A("a", "q", ["q"], mode="hard"), A("b", "p", ["p"], False, mode="hard")],
            pre={**{k: True for k in PRE_KEYS}, "order_ok": None}))

        add(3, "background_exchange_prefix", S([R("p"), R("r")],
            [A("a", "p", ["p", "r"]), A("b", "r", ["p", "r"])]))
        add(3, "background_hall_prefix", S([R("p"), R("r"), R("s")],
            [A("a", "p", ["p", "r"]), A("b", "r", ["p", "r"]), A("c", "s", ["p", "r", "s"])]))
        add(3, "external_background_prefix", S([R("p"), R("r")],
            [A("a", "external:background", ["p", "r"])], owners_complete=False))
        add(3, "background_null_results_prefix", S([R("p"), R("r")],
            [A("a", "p", ["p"], mode="hard", observed_success=None), A("b", "r", ["r"], mode="hard", observed_success=None)]))

        add(4, "hidden_blocked_by_hall_occupancy", S([R("q"), R("p"), R("r")],
            [A("a", "p", ["p", "r"], False), A("b", "r", ["p", "r"], False), A("c", "q", ["q", "p", "r"])], actions_complete=False))
        add(4, "native_parent_but_owner_coverage_gap", S([R("q"), R("p")],
            [A("a", "q", ["q"], mode="hard"), A("b", "p", ["p"], False, mode="hard")], owners_complete=False))
        add(4, "complete_empty_action_window", S([R("q"), R("p"), R("r")], [],
            requirement_kind="unknown", requirement_applicable=False))
        add(4, "all_parent_scope_edges_lost", S([R("q"), R("p")],
            [A("a", "q", [], mode="scope")], intentional_conflict=True))

        add(5, "nested_hall_positive_control", S([R("q"), R("p"), R("r"), R("s")],
            [A("a", "p", ["p", "r"], False), A("b", "r", ["p", "r"], False),
             A("c", "s", ["p", "r", "s"], False), A("d", "q", ["q", "p", "r", "s"])]))
        add(5, "three_way_exchange_all_success", S([R("q"), R("p"), R("r")],
            [A("a", "q", ["q", "p"]), A("b", "p", ["p", "r"]), A("c", "r", ["q", "r"])], allows_target=True))
        add(5, "slack_capacity_four_receives", S([R("q"), R("p"), R("r"), R("s")],
            [A("a", "q", ["q", "p", "r", "s"]), A("b", "p", ["q", "p", "r", "s"])]))
        add(5, "hall_deficit_observation_conflict", S([R("q"), R("p")],
            [A("a", "q", ["q", "p"]), A("b", "p", ["q", "p"]), A("c", "q", ["q", "p"])], intentional_conflict=True))
    assert len(out) == 24
    return out


def _project(split: str, family: str, template: str, spec: dict[str, Any], ordinal: int) -> tuple[dict[str, Any], dict[str, Any]]:
    latent = copy.deepcopy(spec)
    ident = f"{split}-{ordinal:02d}"
    # Nullable observations are projected from a concrete underlying lifecycle;
    # the missing sensor field must not erase the latent state itself.
    latent["actual_pre"] = {key: True if value is None else value for key, value in spec["pre"].items()}
    latent["actual_post"] = {key: True if value is None else value for key, value in spec["post"].items()}
    # Scope membership is observed on receive records, not recovered from owner.
    by_id = {r["id"]: r for r in latent["requests"]}
    for action in latent["actions"]:
        for request_id in action["scope_domain"]:
            by_id[request_id]["visible_scopes"].append(action["join_scope"])
    requests = []
    for i, request in enumerate(latent["requests"]):
        requests.append({"id": request["id"], "processing": request["observed_processing"],
            **{key: request[key] for key in ("content_hash", "wire_tx", "connection", "resource")},
            "provenance": {"source": f"fixture://{ident}/receive/{i}", "source_sequence": i,
                           "visible_scopes": request["visible_scopes"],
                           "identity_basis": "unique_receive_instance_and_connection"}})
    actions = []
    for i, action in enumerate(latent["actions"]):
        if action["projection"] == "hard":
            native_parent = action["actual_owner"]
            candidates = [r["id"] for r in requests if r["id"] == native_parent]
            match = {"rule": "independent_unique_native_parent", "native_parent": native_parent}
        else:
            candidates = [r["id"] for r in requests if r["resource"] == action["resource"] and
                          action["join_scope"] in r["provenance"]["visible_scopes"]]
            match = {"rule": "same_resource_and_scope_membership", "join_scope": action["join_scope"]}
        actions.append({"id": action["id"], "success": action["observed_success"],
            "candidates": candidates, "coarse_candidates": [r["id"] for r in requests if r["resource"] == action["resource"]],
            "hard_parent": action["projection"] == "hard", "resource": action["resource"],
            "provenance": {"source": f"fixture://{ident}/consumer/{i}", "source_sequence": i, "match": match}})
    case = {"id": ident, "family": family, "origin": "synthetic_fixture", "split": split,
        "query": spec["query"], "requests": requests, "actions": actions,
        "contract": {key: spec[key] for key in ("owners_complete", "actions_complete", "single_action_per_request")},
        "pre": copy.deepcopy(spec["pre"]), "post": copy.deepcopy(spec["post"]),
        "requirement": {"kind": spec["requirement_kind"], "applicable": spec["requirement_applicable"],
                        "allows_target": spec["allows_target"], "source": "fixture-policy-v3: target successful operation permission"},
        "provenance": {"generator": VERSION, "template": f"{split}/{family}/{template}",
            "observation_interface": "resource-and-scopes-v1", "independent_unit": f"template:{split}:{family}:{template}",
            "degradation_sibling_group": f"prefix:{split}:{family}:{template}",
            "representation_of": None, "is_independent_representation": True,
            "replication_boundary": "deterministic synthetic semantic unit; not independent deployment",
            "pre_sources": {k: f"fixture://{ident}/pre/{k}" for k in PRE_KEYS},
            "post_sources": {k: f"fixture://{ident}/post/{k}" for k in POST_KEYS}}}
    case["contract"]["basis"] = "fixture_verified"
    latent["id"] = ident
    latent["family"] = family
    latent["template"] = template
    latent["projection_contract"] = "resource-and-scopes-v1"
    return case, latent


def _replace_strings(value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        return [_replace_strings(x, mapping) for x in value]
    if isinstance(value, dict):
        return {mapping.get(k, k): _replace_strings(v, mapping) for k, v in value.items()}
    return value


def _variant(case: dict[str, Any], ordinal: int) -> dict[str, Any]:
    variant = copy.deepcopy(case)
    kind = ("id_rename", "array_permutation", "unrelated_resource", "nonsemantic_metadata")[ordinal % 4]
    if kind == "id_rename":
        ids = [r["id"] for r in case["requests"]] + [a["id"] for a in case["actions"]]
        # Request and action namespaces may share names.  Both namespaces are
        # renamed consistently; only equality, never lexical content, matters.
        mapping = {name: f"opaque-{i:02d}" for i, name in enumerate(dict.fromkeys(ids + [case["query"]]))}
        mapping.update({r["connection"]: f"opaque-connection-{i:02d}" for i, r in enumerate(case["requests"])})
        variant = _replace_strings(variant, mapping)
    elif kind == "array_permutation":
        variant["requests"].reverse()
        variant["actions"].reverse()
        for action in variant["actions"]:
            action["candidates"].reverse()
            action["coarse_candidates"].reverse()
    elif kind == "unrelated_resource":
        variant["requests"].append({"id": "unrelated-request", "processing": "CONSUMED",
            "content_hash": "sha256:unrelated", "wire_tx": "reused-wire-tx-17", "connection": "unrelated-connection",
            "resource": "svc-independent", "provenance": {"source": "fixture://unrelated/receive", "visible_scopes": []}})
        variant["actions"].append({"id": "unrelated-action", "success": True,
            "candidates": ["unrelated-request"], "coarse_candidates": ["unrelated-request"],
            "hard_parent": True, "resource": "svc-independent",
            "provenance": {"source": "fixture://unrelated/consumer", "match": {"rule": "independent_unique_native_parent", "native_parent": "unrelated-request"}}})
    else:
        variant["provenance"]["display_annotation"] = {"colour": "violet", "note": "nonsemantic representation check", "rank": 999}
    variant["id"] = case["id"] + "-representation"
    variant["provenance"]["representation_of"] = case["id"]
    variant["provenance"]["is_independent_representation"] = False
    variant["provenance"]["representation_transform"] = kind
    return variant


def _check_witness(case: dict[str, Any], witness: dict[str, Any]) -> None:
    requests = {r["id"]: r for r in case["requests"]}
    seen: set[str] = set()
    for action in case["actions"]:
        owner = witness["owners"][action["id"]]
        if owner == EXTERNAL:
            assert not case["contract"]["owners_complete"] and not action["hard_parent"]
        else:
            assert owner in action["candidates"] and requests[owner]["processing"] != "REJECTED"
            if case["contract"]["single_action_per_request"]:
                assert owner not in seen
            seen.add(owner)
        value = witness["success"][action["id"]]
        assert type(value) is bool
        assert action["success"] is None or action["success"] == value
    hidden = witness["hidden_target_success"]
    if hidden:
        assert not case["contract"]["actions_complete"]
        assert case["query"] in requests and requests[case["query"]]["processing"] != "REJECTED"
        assert not case["contract"]["single_action_per_request"] or case["query"] not in seen
    actual = hidden or any(witness["owners"][a["id"]] == case["query"] and witness["success"][a["id"]]
                           for a in case["actions"])
    assert actual == witness["target_success"]


def _check_latent(case: dict[str, Any], latent: dict[str, Any], answer: dict[str, Any]) -> None:
    if latent["intentional_conflict"]:
        assert answer["status"] == "CONFLICT", (case["id"], answer)
        return
    assert answer["status"] == "OK", (case["id"], answer)
    request_ids = {r["id"] for r in case["requests"]}
    latent_owners = {a["id"]: a["actual_owner"] if a["actual_owner"] in request_ids else EXTERNAL for a in latent["actions"]}
    witness = {"owners": latent_owners, "success": {a["id"]: a["actual_success"] for a in latent["actions"]},
               "hidden_target_success": False}
    witness["target_success"] = any(owner == case["query"] and witness["success"][ident] for ident, owner in latent_owners.items())
    _check_witness(case, witness)
    for request in latent["requests"]:
        assert request["observed_processing"] in (request["actual_processing"], "UNKNOWN")
    if answer["must_success"] is True:
        assert witness["target_success"]
    if answer["may_success"] is False:
        assert not witness["target_success"]
    for example in answer.get("opposite_witnesses", []):
        _check_witness(case, example)
    if answer.get("opposite_witnesses"):
        assert {w["target_success"] for w in answer["opposite_witnesses"]} == {False, True}


def _result_signature(result: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(result.get(k) for k in ("status", "processing", "effect", "authorization", "must_success", "may_success"))


def self_check() -> dict[str, Any]:
    """Check contract boundaries without running any candidate method."""
    checked = 0
    positive = 0
    ambiguity = 0
    # Hand-specified development obligations, independent of enumeration output.
    # No hidden sealed label table is supplied to an evaluated method.
    dev_expected = (
        ("REJECTED", "NO_TARGET_ACTION", "CONFORMS"),
        ("REJECTED", "NO_TARGET_ACTION", "CONFORMS"),
        ("CONFLICT", "CONFLICT", "CONFLICT"),
        ("REJECTED", "NO_TARGET_ACTION", "CONFORMS"),
        ("CONSUMED", "ACTION_ONLY", "CONFORMS"),
        ("CONSUMED", "UNKNOWN", "UNKNOWN"),
        ("CONSUMED", "NO_TARGET_ACTION", "CONFORMS"),
        ("CONSUMED", "UNKNOWN", "UNKNOWN"),
        ("CONSUMED", "REOPENED", "DEVIATES"),
        ("CONSUMED", "REOPENED", "CONFORMS"),
        ("CONSUMED", "ACTION_ONLY", "DEVIATES"),
        ("CONSUMED", "ACTION_ONLY", "DEVIATES"),
        ("NO_TARGET_RECORD", "NO_TARGET_ACTION", "CONFORMS"),
        ("UNKNOWN", "UNKNOWN", "UNKNOWN"),
        ("NO_TARGET_RECORD", "NO_TARGET_ACTION", "CONFORMS"),
        ("CONFLICT", "CONFLICT", "CONFLICT"),
        ("CONSUMED", "UNKNOWN", "UNKNOWN"),
        ("CONSUMED", "UNKNOWN", "UNKNOWN"),
        ("UNKNOWN", "UNKNOWN", "UNKNOWN"),
        ("CONSUMED", "UNKNOWN", "UNKNOWN"),
        ("CONSUMED", "UNKNOWN", "UNKNOWN"),
        ("CONSUMED", "ACTION_ONLY", "CONFORMS"),
        ("CONSUMED", "UNKNOWN", "UNKNOWN"),
        ("CONSUMED", "NO_TARGET_ACTION", "CONFORMS"),
    )
    for split in ("dev", "sealed"):
        for ordinal, (family, name, spec) in enumerate(_templates(split), 1):
            case, latent = _project(split, family, name, spec, ordinal)
            answer = reference(case)
            _check_latent(case, latent, answer)
            if split == "dev":
                assert tuple(answer[k] for k in ("processing", "effect", "authorization")) == dev_expected[ordinal - 1]
            variant = _variant(case, ordinal - 1)
            other = reference(variant)
            assert _result_signature(answer) == _result_signature(other), (case["id"], answer, other)
            assert len(variant["requests"]) <= 8 and len(variant["actions"]) <= 8
            stripped = {key: copy.deepcopy(value) for key, value in case.items()
                        if key not in ("id", "family", "split", "origin", "provenance")}
            for record in stripped["requests"] + stripped["actions"]:
                record.pop("provenance", None)
            assert _result_signature(reference(stripped)) == _result_signature(answer)
            if answer.get("opposite_witnesses"):
                ambiguity += 1
            if answer.get("effect") == "REOPENED":
                positive += 1
            checked += 1
    # Strict boolean semantics, bound exhaustion, rejected-owner conflict,
    # optional hidden action, capacity consumption, and unresolved native policy.
    _, _, sample = _templates("dev")[8]
    sample, _ = _project("dev", FAMILIES[2], "boundary", sample, 99)
    invalid = copy.deepcopy(sample)
    invalid["pre"]["rule_empty"] = "true"
    assert reference(invalid)["status"] == "INVALID_INPUT"
    unknown = copy.deepcopy(sample)
    unknown["actions"][0]["success"] = None
    assert reference(unknown, 1)["status"] == "BOUND_EXCEEDED"
    assert reference(unknown, 2)["feasible_assignments"] == 2
    hidden = copy.deepcopy(sample)
    hidden["actions"] = []
    hidden["contract"]["actions_complete"] = False
    assert reference(hidden)["effect"] == "UNKNOWN"
    hidden["actions"] = copy.deepcopy(sample["actions"])
    hidden["actions"][0]["success"] = False
    assert reference(hidden)["effect"] == "NO_TARGET_ACTION"
    hidden["contract"]["single_action_per_request"] = False
    assert reference(hidden)["effect"] == "UNKNOWN"
    no_policy = copy.deepcopy(sample)
    no_policy["requirement"]["kind"] = "unknown"
    assert reference(no_policy)["authorization"] == "UNKNOWN"
    assert checked == 48 and positive >= 4 and ambiguity >= 8
    small_graphs = 0
    # A structurally separate Cartesian-product oracle checks the backtracking
    # implementation over every compatibility graph up to three by three.
    for n in range(1, 4):
        for na in range(4):
            ids = [f"v{i}" for i in range(n)]
            for mask in range(1 << (n * na)):
                domains = [[ids[i] for i in range(n) if mask & (1 << (j * n + i))] for j in range(na)]
                graph = _spec([_request(x) for x in ids],
                    [_action(f"e{j}", domain[0] if domain else ids[0], domain) for j, domain in enumerate(domains)], query=ids[0])
                observed, _ = _project("dev", "self_check_graph", "cartesian", graph, 0)
                for cap in (False, True):
                    observed["contract"]["single_action_per_request"] = cap
                    answer = reference(observed)
                    completed = [owners for owners in itertools.product(*domains)
                                 if not cap or len(set(owners)) == len(owners)]
                    expected = (("CONFLICT", None, None) if not completed else
                                ("OK", all(ids[0] in x for x in completed), any(ids[0] in x for x in completed)))
                    assert (answer["status"], answer.get("must_success"), answer.get("may_success")) == expected
                    assert answer.get("feasible_owner_assignments", 0) == len(completed)
                    small_graphs += 1
    assert small_graphs == 1370
    return {"status": "PASS", "base_fixtures_checked": checked,
            "representations_checked": checked, "boundary_checks": 8,
            "hand_specified_development_obligations": len(dev_expected),
            "cartesian_small_graph_crosschecks": small_graphs,
            "nontrivial_positive_and_opposite_witness_checks": True}


def generate(out_dir: str | Path) -> dict[str, Any]:
    """Write 48 bases + 48 equivalent encodings; keep truth/reference private.

    Existing differing bytes are refused so first generated evidence cannot be
    silently overwritten.  Re-running the unchanged generator is idempotent.
    """
    out = Path(out_dir)
    files: dict[str, str] = {}
    counts = {"dev_base": 0, "dev_representation": 0, "sealed_base": 0, "sealed_representation": 0}
    private_answers: dict[str, dict[str, Any]] = {"dev": {}, "sealed": {}}
    dev_signatures: dict[str, tuple[Any, ...]] = {}

    def write(relative: str, value: Any) -> None:
        data = _canonical(value)
        path = out / relative
        if path.exists() and path.read_bytes() != data:
            raise FileExistsError(f"refusing to replace frozen differing artifact: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        files[relative] = _sha(data)

    for split in ("dev", "sealed"):
        for ordinal, (family, name, spec) in enumerate(_templates(split), 1):
            case, latent = _project(split, family, name, spec, ordinal)
            answer = reference(case)
            _check_latent(case, latent, answer)
            variant = _variant(case, ordinal - 1)
            var_answer = reference(variant)
            assert _result_signature(answer) == _result_signature(var_answer)
            assert len(case["requests"]) <= 8 and len(case["actions"]) <= 8
            assert len(variant["requests"]) <= 8 and len(variant["actions"]) <= 8
            write(f"{split}/{case['id']}.json", case)
            write(f"{split}/{variant['id']}.json", variant)
            write(f"oracle_private/latent/{case['id']}.json", latent)
            # Runtime changes on each execution; retain deterministic counts,
            # and let each evaluation harness record its own elapsed time.
            answer["cost"].pop("seconds", None)
            var_answer["cost"].pop("seconds", None)
            private_answers[split][case["id"]] = answer
            private_answers[split][variant["id"]] = var_answer
            counts[f"{split}_base"] += 1
            counts[f"{split}_representation"] += 1
            if split == "dev":
                dev_signatures[case["id"]] = _result_signature(answer)
    for split in ("dev", "sealed"):
        write(f"oracle_private/{split}_reference.json", private_answers[split])
    source_hash = _sha(Path(__file__).read_bytes())
    manifest = {"generator_version": VERSION, "source_sha256": source_hash,
                "counts": counts, "total_observations": sum(counts.values()),
                "max_requests": 8, "max_actions": 8, "files": files,
                "sealed_policy": "Do not open sealed data/reference before candidate code hash is frozen.",
                "unit_boundary": "48 synthetic base semantic fixtures plus 48 dependent encoding checks; no product runs"}
    write("MANIFEST.json", manifest)
    return {"out_dir": str(out.resolve()), "source_sha256": source_hash, "counts": counts,
            "total_observations": 96, "manifest_sha256": files["MANIFEST.json"],
            "dev_reference_sha256": files["oracle_private/dev_reference.json"],
            "sealed_reference_sha256": files["oracle_private/sealed_reference.json"],
            "dev_signatures": dev_signatures}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    receipt: dict[str, Any] = {}
    if args.self_check:
        receipt["self_check"] = self_check()
    if args.out:
        receipt["generation"] = generate(args.out)
    if not receipt:
        parser.error("choose --out and/or --self-check")
    print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
