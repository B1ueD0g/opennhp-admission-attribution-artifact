"""Paper B3 comparator restricted to its offline graph function."""
import networkx as nx

from baseline import _validate


FIELDS = ("status", "processing", "effect", "authorization", "must_success", "may_success")


STATES = {"pre": ("rule_empty", "tcp_failed", "health_ok", "order_ok"),
          "post": ("new_tcp", "http_ok", "order_ok")}


def terminal(status):
    return dict.fromkeys(FIELDS[:4], status)


def solve(case):
    try:
        _validate(case)
    except (ValueError, TypeError):
        return terminal("INVALID_INPUT")

    target = case["query"]
    requests = {r["id"]: r for r in case["requests"]}
    actions = case["actions"]
    contract = case["contract"]
    located = target in requests
    processing = requests[target]["processing"] if located else (
        "NO_TARGET_RECORD" if contract["owners_complete"] else "UNKNOWN")
    capacity_one = contract["single_action_per_request"]
    target_owner = ("owner", target)
    resource = requests[target]["resource"] if located else None
    sink = ("sink",)
    graph = nx.DiGraph()
    graph.add_node(sink, demand=len(actions))
    terms = {key: [] for key in ("known", "possible", "occupancy", "competitor")}

    for action in actions:
        action_node = ("action", action["id"])
        owners = [("owner", rid) for rid in action["candidates"]
                  if requests[rid]["processing"] != "REJECTED"]
        if not contract["owners_complete"] and not action["hard_parent"]:
            owners.append(("external", action["id"]))
        if not owners:
            return terminal("CONFLICT")
        graph.add_node(action_node, demand=-1)
        for owner in owners:
            edge = (action_node, owner)
            graph.add_edge(*edge, capacity=1)
            graph.add_edge(owner, sink, capacity=1 if capacity_one else len(actions))
            if owner == target_owner:
                terms["occupancy"].append(edge)
                if action["success"] is True:
                    terms["known"].append(edge)
                if action["success"] is not False:
                    terms["possible"].append(edge)
            elif action.get("resource", resource) == resource and action["success"] is not False:
                terms["competitor"].append(edge)

    def optimum(selected, sign):
        weighted = graph.copy()
        for u, v in selected:
            weighted[u][v]["weight"] = sign
        flow = nx.min_cost_flow(weighted)
        return sum(flow[u][v] for u, v in selected)

    try:
        must = optimum(terms["known"], 1) > 0
    except nx.NetworkXUnfeasible:
        return terminal("CONFLICT")
    may = must or optimum(terms["possible"], -1) > 0
    if not may and not contract["actions_complete"] and located and processing != "REJECTED":
        may = not capacity_one or optimum(terms["occupancy"], 1) == 0

    lifecycle = all(case[group][k] is True for group, keys in STATES.items() for k in keys)
    reopen = (must and lifecycle and contract["owners_complete"] and contract["actions_complete"]
              and optimum(terms["competitor"], -1) == 0)
    if processing == "UNKNOWN":
        effect = "UNKNOWN"
    elif processing == "NO_TARGET_RECORD":
        effect = "NO_TARGET_ACTION"
    elif must:
        effect = "REOPENED" if reopen else "ACTION_ONLY"
    else:
        effect = "UNKNOWN" if may else "NO_TARGET_ACTION"

    requirement = case["requirement"]
    qualified = (requirement["kind"] in {"native", "fixture"} and requirement["applicable"]
                 and type(requirement["allows_target"]) is bool and requirement["source"].strip())
    authorization = "UNKNOWN"
    if qualified and effect != "UNKNOWN":
        authorization = ("CONFORMS" if effect == "NO_TARGET_ACTION" or requirement["allows_target"]
                         else "DEVIATES")
    applicable = located and processing != "UNKNOWN"
    return dict(zip(FIELDS, ("OK", processing, effect, authorization,
                             must if applicable else None, may if applicable else None), strict=True))
