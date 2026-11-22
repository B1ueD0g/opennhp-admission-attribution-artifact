"""Verify the stored verdicts for one frozen synthetic graph cohort."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

FIELDS = ("status", "processing", "effect", "authorization", "must_success", "may_success")
DETERMINATE = {"REOPENED", "ACTION_ONLY", "NO_TARGET_ACTION"}
EXPECTED_GAIN = {
    "fixed": {"sealed-05", "sealed-06", "sealed-09", "sealed-10",
              "sealed-17", "sealed-21", "sealed-22"},
    "prospective": {"H05", "H10", "H11", "H15", "H19", "H21"},
}
EXPECTED_COUNTS = {
    "fixed": {"M": 24, "B1": 17, "B2": 24},
    "prospective": {"M": 24, "B1": 18, "B2": 24, "B3": 24},
}


def signature(result):
    return tuple(result.get(field) for field in FIELDS)


def main(cohort):
    folder = Path(__file__).resolve().parent / cohort
    sys.path.insert(0, str(folder))
    from baseline import solve as local
    from fixture_reference import reference
    from method import solve as global_queries

    methods = {"M": global_queries, "B1": local, "B2": reference}
    if cohort == "prospective":
        from b3 import solve as flow
        methods["B3"] = flow
    graphs = json.loads((folder / "cases.json").read_text())
    if len(graphs) != 24:
        raise ValueError(f"Expected 24 frozen base graphs, found {len(graphs)}")
    agreements = Counter()
    verdicts = {name: Counter() for name in methods}
    gains = set()
    for case_id, entry in graphs.items():
        graph = entry["input"]
        projected = json.dumps(graph, sort_keys=True, separators=(",", ":"))
        if cohort == "fixed":
            actual = hashlib.sha256(projected.encode()).hexdigest()
            if actual != entry["canonical_input_sha256"]:
                raise ValueError(f"Solver input fingerprint mismatch: {case_id}")
        if cohort == "prospective":
            actual = hashlib.sha256(json.dumps(graph, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if actual != entry["frozen_input_sha256"]:
                raise ValueError(f"Frozen prospective input fingerprint mismatch: {case_id}")
        expected = entry["expected"]
        results = {name: method(json.loads(projected)) for name, method in methods.items()}
        for name, result in results.items():
            effect = result.get("effect")
            verdicts[name][effect] += 1
            agreements[name] += effect == expected["effect"]
            if name != "B1" and signature(result) != signature(expected):
                raise ValueError(f"Exact signature mismatch: {cohort}/{case_id}/{name}")
        if results["B1"]["effect"] == "UNKNOWN" and results["M"]["effect"] in DETERMINATE:
            gains.add(case_id)

    if dict(agreements) != EXPECTED_COUNTS[cohort] or gains != EXPECTED_GAIN[cohort]:
        raise ValueError(f"Expected published totals for {cohort}; got {agreements}, {gains}")
    print(json.dumps({"cohort": cohort, "base_graphs": len(graphs),
                      "effect_agreements": agreements, "effects": verdicts,
                      "additional_supported_verdicts_vs_B1": sorted(gains)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in EXPECTED_GAIN:
        raise SystemExit("Usage: python offline/verify.py {fixed|prospective}")
    main(sys.argv[1])
